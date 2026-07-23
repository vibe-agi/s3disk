package webdav

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/vibe-agi/s3disk"
	xwebdav "golang.org/x/net/webdav"
)

const maximumPROPFINDBodyBytes int64 = 1 << 20

// Handler is a read-only HTTP/WebDAV view of one Consumer. Refresh must be
// called through Handler so a PROPFIND response observes one complete snapshot.
type Handler struct {
	gate     sync.RWMutex
	statusMu sync.RWMutex
	status   Status
	consumer *s3disk.Consumer
	dav      *xwebdav.Handler
}

// NewHandler validates the Consumer's long-lived read security requirements.
// It performs no network or local-state I/O and does not perform the initial
// Refresh; callers should Refresh successfully before accepting connections.
func NewHandler(consumer *s3disk.Consumer) (*Handler, error) {
	if consumer == nil {
		return nil, fmt.Errorf("s3disk webdav: nil consumer")
	}
	security := consumer.SecurityStatus()
	if !security.DurableWatermarkConfigured {
		return nil, ErrDurableWatermarkRequired
	}
	if security.SymlinkPolicy != s3disk.SymlinkRejectExternal {
		return nil, fmt.Errorf("%w: Consumer must use SymlinkRejectExternal", ErrSymlinkUnsupported)
	}
	handler := &Handler{consumer: consumer}
	filesystem := &readOnlyFileSystem{consumer: consumer, gate: &handler.gate}
	handler.dav = &xwebdav.Handler{
		FileSystem: filesystem,
		LockSystem: xwebdav.NewMemLS(),
	}
	return handler, nil
}

// Refresh atomically advances the view between metadata operations. A
// PROPFIND response observes one complete snapshot, while a GET pins its file
// before streaming so a long transfer does not delay later refreshes.
func (handler *Handler) Refresh(ctx context.Context) (s3disk.RefreshResult, error) {
	if handler == nil || handler.consumer == nil {
		return s3disk.RefreshResult{}, fmt.Errorf("s3disk webdav: handler is not initialized")
	}
	attemptedAt := time.Now().UTC()
	handler.gate.Lock()
	result, err := handler.consumer.Refresh(ctx)
	handler.recordRefresh(attemptedAt, result, err)
	handler.gate.Unlock()
	return result, err
}

// Status returns a concurrency-safe snapshot of refresh health. Callers should
// treat LastRefreshError as diagnostic text rather than a telemetry label.
func (handler *Handler) Status() Status {
	if handler == nil {
		return Status{}
	}
	handler.statusMu.RLock()
	defer handler.statusMu.RUnlock()
	return handler.status
}

func (handler *Handler) recordRefresh(attemptedAt time.Time, result s3disk.RefreshResult, err error) {
	handler.statusMu.Lock()
	defer handler.statusMu.Unlock()
	handler.status.LastRefreshAttempt = attemptedAt
	if err != nil {
		handler.status.ConsecutiveRefreshFailures++
		handler.status.LastRefreshError = err.Error()
		return
	}
	handler.status.Generation = result.Generation
	handler.status.LastRefreshSuccess = time.Now().UTC()
	handler.status.ConsecutiveRefreshFailures = 0
	handler.status.LastRefreshError = ""
}

// AuthorizationExpiry forwards the Consumer's immutable authorization bound.
func (handler *Handler) AuthorizationExpiry() (time.Time, bool) {
	if handler == nil || handler.consumer == nil {
		return time.Time{}, false
	}
	return handler.consumer.AuthorizationExpiry()
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Allow", "OPTIONS, PROPFIND, GET, HEAD")
	if handler == nil || handler.dav == nil || request == nil {
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !validLoopbackRequestHost(request.Host) {
		http.Error(response, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
		return
	}
	if request.URL.RawQuery != "" {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	switch request.Method {
	case http.MethodOptions:
		response.Header().Set("DAV", "1")
		response.Header().Set("MS-Author-Via", "DAV")
		response.WriteHeader(http.StatusOK)
		return
	case "PROPFIND":
		response.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		response.Header().Set("Pragma", "no-cache")
		depth := request.Header.Get("Depth")
		if depth != "0" && depth != "1" {
			http.Error(response, "WebDAV Depth must be 0 or 1", http.StatusForbidden)
			return
		}
		request.Body = http.MaxBytesReader(response, request.Body, maximumPROPFINDBodyBytes)
	case http.MethodGet, http.MethodHead:
		response.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		response.Header().Set("Pragma", "no-cache")
		// GET/HEAD use a generation-specific whole-second Last-Modified value.
		// PROPFIND continues to expose the source file's real modification time.
		request = request.WithContext(context.WithValue(request.Context(), snapshotHTTPValidatorKey{}, true))
		contentType := mime.TypeByExtension(path.Ext(request.URL.Path))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		response.Header().Set("Content-Type", contentType)
	default:
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = response.Write([]byte("read-only WebDAV endpoint\n"))
		return
	}
	if expiresAt, known := handler.AuthorizationExpiry(); known && !time.Now().Before(expiresAt) {
		http.Error(response, ErrAuthorizationExpired.Error(), http.StatusGone)
		return
	}
	if request.Method == "PROPFIND" {
		// x/net/webdav walks every Depth-1 child with separate FileSystem calls.
		// Keep those calls on one generation, and mark the context so the
		// FileSystem does not recursively acquire the same RWMutex.
		handler.gate.RLock()
		defer handler.gate.RUnlock()
		request = request.WithContext(context.WithValue(request.Context(), snapshotGateHeldKey{}, true))
	}
	handler.dav.ServeHTTP(response, request)
}

// validLoopbackRequestHost rejects DNS-rebinding authorities before any
// decrypted metadata or file bytes reach the response. The CLI separately
// constrains the listening socket; both checks are required because browsers
// preserve an attacker's hostname while resolving it to a loopback address.
func validLoopbackRequestHost(authority string) bool {
	if authority == "" {
		return false
	}
	parsed, err := url.Parse("http://" + authority)
	if err != nil || parsed.Host != authority || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

// IsReadOnlyMethod reports the exact HTTP method surface exposed by Handler.
func IsReadOnlyMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodOptions, "PROPFIND", http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

var _ http.Handler = (*Handler)(nil)

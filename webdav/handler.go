package webdav

import (
	"context"
	"fmt"
	"mime"
	"net/http"
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
	filesystem := &readOnlyFileSystem{consumer: consumer}
	return &Handler{
		consumer: consumer,
		dav: &xwebdav.Handler{
			FileSystem: filesystem,
			LockSystem: xwebdav.NewMemLS(),
		},
	}, nil
}

// Refresh atomically advances the view between HTTP requests. It serializes
// against complete requests so directory metadata cannot mix generations.
func (handler *Handler) Refresh(ctx context.Context) (s3disk.RefreshResult, error) {
	if handler == nil || handler.consumer == nil {
		return s3disk.RefreshResult{}, fmt.Errorf("s3disk webdav: handler is not initialized")
	}
	handler.gate.Lock()
	defer handler.gate.Unlock()
	return handler.consumer.Refresh(ctx)
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
		depth := request.Header.Get("Depth")
		if depth != "0" && depth != "1" {
			http.Error(response, "WebDAV Depth must be 0 or 1", http.StatusForbidden)
			return
		}
		request.Body = http.MaxBytesReader(response, request.Body, maximumPROPFINDBodyBytes)
	case http.MethodGet, http.MethodHead:
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
	handler.gate.RLock()
	defer handler.gate.RUnlock()
	handler.dav.ServeHTTP(response, request)
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

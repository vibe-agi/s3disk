package webdav

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

type handlerFixture struct {
	handler   *Handler
	consumer  *s3disk.Consumer
	publisher *s3disk.Publisher
	store     *memstore.Store
	source    string
}

func newHandlerFixture(t *testing.T) handlerFixture {
	t.Helper()
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "webdav-test")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "dir", "nested.txt"), []byte("nested"), 0o640); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink("hello.txt", filepath.Join(source, "hello-link")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := publisher.Publish(context.Background(), source, "main"); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(state, "watermark.json"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Watermarks: watermarks, RequirePersistentWatermark: true,
		Symlinks: s3disk.SymlinkRejectExternal,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(consumer)
	if err != nil {
		t.Fatal(err)
	}
	result, err := handler.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != s3disk.RefreshUpdated {
		t.Fatalf("initial refresh status = %v, want updated", result.Status)
	}
	return handlerFixture{handler: handler, consumer: consumer, publisher: publisher, store: store, source: source}
}

func TestHandlerServesFinderReadSurface(t *testing.T) {
	t.Parallel()
	fixture := newHandlerFixture(t)

	options := httptest.NewRecorder()
	fixture.handler.ServeHTTP(options, httptest.NewRequest(http.MethodOptions, "http://127.0.0.1/", nil))
	if options.Code != http.StatusOK || options.Header().Get("DAV") != "1" ||
		options.Header().Get("Allow") != "OPTIONS, PROPFIND, GET, HEAD" {
		t.Fatalf("OPTIONS = status %d headers %#v", options.Code, options.Header())
	}

	propfindRequest := httptest.NewRequest("PROPFIND", "http://127.0.0.1/", strings.NewReader(""))
	propfindRequest.Header.Set("Depth", "1")
	propfind := httptest.NewRecorder()
	fixture.store.ResetStats()
	fixture.handler.ServeHTTP(propfind, propfindRequest)
	if propfind.Code != 207 {
		t.Fatalf("PROPFIND status = %d, body = %q", propfind.Code, propfind.Body.String())
	}
	for _, href := range []string{"<D:href>/</D:href>", "<D:href>/dir/</D:href>", "<D:href>/hello.txt</D:href>"} {
		if !strings.Contains(propfind.Body.String(), href) {
			t.Fatalf("PROPFIND body lacks %q: %s", href, propfind.Body.String())
		}
	}
	if strings.Contains(propfind.Body.String(), "hello-link") {
		t.Fatalf("PROPFIND exposed unsupported symlink: %s", propfind.Body.String())
	}
	if got := fixture.store.Stats().ChunkGets; got != 0 {
		t.Fatalf("PROPFIND fetched %d file chunks, want metadata-only", got)
	}
	head := httptest.NewRecorder()
	fixture.handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "http://127.0.0.1/hello.txt", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != "11" {
		t.Fatalf("HEAD = status %d body %q headers %#v", head.Code, head.Body.String(), head.Header())
	}
	if got := fixture.store.Stats().ChunkGets; got != 0 {
		t.Fatalf("HEAD fetched %d file chunks, want metadata-only", got)
	}

	get := httptest.NewRecorder()
	fixture.handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil))
	if get.Code != http.StatusOK || get.Body.String() != "hello world" || get.Header().Get("ETag") == "" {
		t.Fatalf("GET = status %d body %q headers %#v", get.Code, get.Body.String(), get.Header())
	}

	rangeRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil)
	rangeRequest.Header.Set("Range", "bytes=1-4")
	ranged := httptest.NewRecorder()
	fixture.handler.ServeHTTP(ranged, rangeRequest)
	if ranged.Code != http.StatusPartialContent || ranged.Body.String() != "ello" {
		t.Fatalf("range GET = status %d body %q", ranged.Code, ranged.Body.String())
	}
}

func TestHandlerRejectsEveryMutation(t *testing.T) {
	t.Parallel()
	fixture := newHandlerFixture(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "PROPPATCH", "PATCH"} {
		t.Run(method, func(t *testing.T) {
			request := httptest.NewRequest(method, "http://127.0.0.1/hello.txt", bytes.NewReader([]byte("replacement")))
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s status = %d, want 405", method, response.Code)
			}
		})
	}

	get := httptest.NewRecorder()
	fixture.handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil))
	if get.Body.String() != "hello world" {
		t.Fatalf("contents after mutations = %q", get.Body.String())
	}
}

func TestOpenFilePinsBytesAcrossRefresh(t *testing.T) {
	t.Parallel()
	fixture := newHandlerFixture(t)
	filesystem := fixture.handler.dav.FileSystem
	opened, err := filesystem.OpenFile(context.Background(), "/hello.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	if err := os.WriteFile(filepath.Join(fixture.source, "hello.txt"), []byte("new generation"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publisher.Publish(context.Background(), fixture.source, "main"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handler.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	oldBytes, err := io.ReadAll(opened)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldBytes) != "hello world" {
		t.Fatalf("pinned file bytes = %q", oldBytes)
	}
	current := httptest.NewRecorder()
	fixture.handler.ServeHTTP(current, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil))
	if current.Body.String() != "new generation" {
		t.Fatalf("current bytes = %q", current.Body.String())
	}
}

func TestHandlerRequiresDurableWatermark(t *testing.T) {
	t.Parallel()
	repository, err := s3disk.NewRepository(memstore.New(), "webdav-no-watermark")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHandler(consumer); !errors.Is(err, ErrDurableWatermarkRequired) {
		t.Fatalf("NewHandler error = %v", err)
	}
}

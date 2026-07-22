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
	"sync"
	"testing"
	"time"

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

func TestDateValidatorsCannotHideSameSecondRefresh(t *testing.T) {
	t.Parallel()
	fixture := newHandlerFixture(t)
	initial := httptest.NewRecorder()
	fixture.handler.ServeHTTP(initial,
		httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil))
	lastModified := initial.Header().Get("Last-Modified")
	oldETag := initial.Header().Get("ETag")
	if lastModified == "" || oldETag == "" {
		t.Fatalf("initial validators: Last-Modified=%q ETag=%q", lastModified, oldETag)
	}
	original, err := os.Stat(filepath.Join(fixture.source, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.source, "hello.txt"), []byte("new generation"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(fixture.source, "hello.txt"), original.ModTime(), original.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publisher.Publish(context.Background(), fixture.source, "main"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.handler.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	modifiedSince := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil)
	modifiedSince.Header.Set("If-Modified-Since", lastModified)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, modifiedSince)
	if response.Code != http.StatusOK || response.Body.String() != "new generation" {
		t.Fatalf("same-second If-Modified-Since = status %d body %q", response.Code, response.Body.String())
	}
	newETag := response.Header().Get("ETag")
	if newETag == "" || newETag == oldETag {
		t.Fatalf("refreshed ETag = %q, old = %q", newETag, oldETag)
	}
	newLastModified := response.Header().Get("Last-Modified")
	if newLastModified == "" || newLastModified == lastModified {
		t.Fatalf("refreshed Last-Modified = %q, old = %q", newLastModified, lastModified)
	}

	noneMatch := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil)
	noneMatch.Header.Set("If-None-Match", newETag)
	notModified := httptest.NewRecorder()
	fixture.handler.ServeHTTP(notModified, noneMatch)
	if notModified.Code != http.StatusNotModified {
		t.Fatalf("current If-None-Match status = %d, want 304", notModified.Code)
	}
	modifiedSinceCurrent := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil)
	modifiedSinceCurrent.Header.Set("If-Modified-Since", newLastModified)
	dateNotModified := httptest.NewRecorder()
	fixture.handler.ServeHTTP(dateNotModified, modifiedSinceCurrent)
	if dateNotModified.Code != http.StatusNotModified {
		t.Fatalf("current If-Modified-Since status = %d, want 304", dateNotModified.Code)
	}

	dateRange := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil)
	dateRange.Header.Set("Range", "bytes=6-")
	dateRange.Header.Set("If-Range", lastModified)
	complete := httptest.NewRecorder()
	fixture.handler.ServeHTTP(complete, dateRange)
	if complete.Code != http.StatusOK || complete.Body.String() != "new generation" {
		t.Fatalf("same-second date If-Range = status %d body %q", complete.Code, complete.Body.String())
	}
}

func TestSnapshotHTTPValidatorTimeIsStableAndBounded(t *testing.T) {
	t.Parallel()
	first := snapshotHTTPValidatorTime(1)
	second := snapshotHTTPValidatorTime(2)
	if first.IsZero() || !second.After(first) || second.Sub(first) != time.Second {
		t.Fatalf("validator times: generation 1=%s generation 2=%s", first, second)
	}
	if repeat := snapshotHTTPValidatorTime(2); !repeat.Equal(second) {
		t.Fatalf("repeated validator time = %s, want %s", repeat, second)
	}
	if value := snapshotHTTPValidatorTime(^uint64(0)); !value.IsZero() {
		t.Fatalf("unrepresentable generation validator = %s, want zero", value)
	}
}

func TestLongGETPinsBytesWithoutBlockingRefresh(t *testing.T) {
	t.Parallel()
	fixture := newHandlerFixture(t)
	response := newBlockingResponseWriter()
	t.Cleanup(response.unblock)
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		fixture.handler.ServeHTTP(response,
			httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil))
	}()
	waitForSignal(t, response.writeStarted, "GET did not begin streaming")

	if err := os.WriteFile(filepath.Join(fixture.source, "hello.txt"), []byte("new generation"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publisher.Publish(context.Background(), fixture.source, "main"); err != nil {
		t.Fatal(err)
	}
	refreshDone := make(chan error, 1)
	go func() {
		result, err := fixture.handler.Refresh(context.Background())
		if err == nil && result.Status != s3disk.RefreshUpdated {
			err = errors.New("refresh did not adopt the published generation")
		}
		refreshDone <- err
	}()
	select {
	case err := <-refreshDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("refresh was blocked by an in-progress GET body")
	}
	response.unblock()
	waitForSignal(t, requestDone, "GET did not finish after releasing its client")
	if response.statusCode != http.StatusOK || response.body.String() != "hello world" {
		t.Fatalf("pinned GET = status %d body %q", response.statusCode, response.body.String())
	}

	current := httptest.NewRecorder()
	fixture.handler.ServeHTTP(current,
		httptest.NewRequest(http.MethodGet, "http://127.0.0.1/hello.txt", nil))
	if current.Code != http.StatusOK || current.Body.String() != "new generation" {
		t.Fatalf("current GET = status %d body %q", current.Code, current.Body.String())
	}
}

func TestPROPFINDRemainsSingleSnapshotDuringRefresh(t *testing.T) {
	t.Parallel()
	fixture := newHandlerFixture(t)
	response := newBlockingResponseWriter()
	t.Cleanup(response.unblock)
	request := httptest.NewRequest("PROPFIND", "http://127.0.0.1/", nil)
	request.Header.Set("Depth", "1")
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		fixture.handler.ServeHTTP(response, request)
	}()
	waitForSignal(t, response.writeStarted, "PROPFIND did not begin its response")

	if err := os.WriteFile(filepath.Join(fixture.source, "new.txt"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publisher.Publish(context.Background(), fixture.source, "main"); err != nil {
		t.Fatal(err)
	}
	refreshDone := make(chan error, 1)
	go func() {
		_, err := fixture.handler.Refresh(context.Background())
		refreshDone <- err
	}()
	select {
	case err := <-refreshDone:
		t.Fatalf("refresh completed before PROPFIND snapshot finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	response.unblock()
	waitForSignal(t, requestDone, "PROPFIND did not finish after releasing its client")
	if strings.Contains(response.body.String(), "new.txt") {
		t.Fatalf("PROPFIND mixed a later generation into its response: %s", response.body.String())
	}
	select {
	case err := <-refreshDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not resume after PROPFIND completed")
	}

	currentRequest := httptest.NewRequest("PROPFIND", "http://127.0.0.1/", nil)
	currentRequest.Header.Set("Depth", "1")
	current := httptest.NewRecorder()
	fixture.handler.ServeHTTP(current, currentRequest)
	if current.Code != 207 || !strings.Contains(current.Body.String(), "new.txt") {
		t.Fatalf("current PROPFIND = status %d body %q", current.Code, current.Body.String())
	}
}

func TestHandlerStatusTracksRefreshHealth(t *testing.T) {
	t.Parallel()
	fixture := newHandlerFixture(t)
	initial := fixture.handler.Status()
	if initial.Generation != 1 || initial.LastRefreshSuccess.IsZero() ||
		initial.ConsecutiveRefreshFailures != 0 || initial.LastRefreshError != "" {
		t.Fatalf("initial status = %#v", initial)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.handler.Refresh(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled refresh error = %v", err)
	}
	failed := fixture.handler.Status()
	if failed.Generation != initial.Generation || failed.ConsecutiveRefreshFailures != 1 ||
		failed.LastRefreshError == "" || failed.LastRefreshAttempt.Before(initial.LastRefreshSuccess) {
		t.Fatalf("failed status = %#v", failed)
	}

	if _, err := fixture.handler.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered := fixture.handler.Status()
	if recovered.Generation != initial.Generation || recovered.ConsecutiveRefreshFailures != 0 ||
		recovered.LastRefreshError != "" || recovered.LastRefreshSuccess.Before(initial.LastRefreshSuccess) {
		t.Fatalf("recovered status = %#v", recovered)
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

type blockingResponseWriter struct {
	header       http.Header
	statusCode   int
	body         bytes.Buffer
	writeStarted chan struct{}
	release      chan struct{}
	startOnce    sync.Once
	releaseOnce  sync.Once
}

func newBlockingResponseWriter() *blockingResponseWriter {
	return &blockingResponseWriter{
		header: make(http.Header), writeStarted: make(chan struct{}), release: make(chan struct{}),
	}
}

func (writer *blockingResponseWriter) Header() http.Header { return writer.header }

func (writer *blockingResponseWriter) WriteHeader(statusCode int) {
	if writer.statusCode == 0 {
		writer.statusCode = statusCode
	}
}

func (writer *blockingResponseWriter) Write(contents []byte) (int, error) {
	if writer.statusCode == 0 {
		writer.statusCode = http.StatusOK
	}
	writer.startOnce.Do(func() { close(writer.writeStarted) })
	<-writer.release
	return writer.body.Write(contents)
}

func (writer *blockingResponseWriter) unblock() {
	writer.releaseOnce.Do(func() { close(writer.release) })
}

func waitForSignal(t *testing.T, signal <-chan struct{}, timeoutMessage string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal(timeoutMessage)
	}
}

package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
	s3webdav "github.com/vibe-agi/s3disk/webdav"
)

func TestServeWebDAVLifecycleAndRead(t *testing.T) {
	t.Parallel()
	handler := newCLIWebDAVHandler(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var status, warnings synchronizedBuffer
	result := make(chan error, 1)
	go func() {
		result <- serveWebDAV(ctx, listener, handler, WebDAVOptions{
			PollInterval: 100 * time.Millisecond, PollTimeout: time.Second,
			StatusWriter: &status, ErrorWriter: &warnings,
		}, time.Now().Add(time.Minute))
	}()
	url := "http://" + listener.Addr().String() + "/hello.txt"
	var response *http.Response
	for deadline := time.Now().Add(3 * time.Second); ; {
		response, err = http.Get(url) // #nosec G107 -- loopback listener created by this test.
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("WebDAV server did not become ready: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	contents, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read response: %v; close: %v", err, closeErr)
	}
	if response.StatusCode != http.StatusOK || string(contents) != "hello" {
		t.Fatalf("GET = status %d body %q", response.StatusCode, contents)
	}
	if !strings.Contains(status.String(), "loopback_only=true authentication=none") || warnings.String() != "" {
		t.Fatalf("status = %q warnings = %q", status.String(), warnings.String())
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WebDAV server did not stop after context cancellation")
	}
}

func TestServeWebDAVStopsAtAuthorizationExpiry(t *testing.T) {
	t.Parallel()
	handler := newCLIWebDAVHandler(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- serveWebDAV(context.Background(), listener, handler, WebDAVOptions{
			PollInterval: time.Second, PollTimeout: time.Second,
		}, time.Now().Add(50*time.Millisecond))
	}()
	select {
	case err := <-result:
		if !errors.Is(err, s3webdav.ErrAuthorizationExpired) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WebDAV server did not stop at authorization expiry")
	}
}

func newCLIWebDAVHandler(t *testing.T) *s3webdav.Handler {
	t.Helper()
	repository, err := s3disk.NewRepository(memstore.New(), "cli-webdav-test")
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
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
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
	handler, err := s3webdav.NewHandler(consumer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return handler
}

//go:build integration && darwin

package webdav

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
)

func TestMacOSNativeWebDAVMount(t *testing.T) {
	fixture := newHandlerFixture(t)
	server := httptest.NewServer(fixture.handler)
	defer server.Close()

	mountpoint := t.TempDir()
	mount := exec.Command("/sbin/mount_webdav", "-S", "-o", "rdonly", server.URL+"/", mountpoint)
	output, err := mount.CombinedOutput()
	if err != nil {
		t.Fatalf("mount_webdav: %v\n%s", err, output)
	}
	defer func() {
		unmount := exec.Command("/sbin/umount", mountpoint)
		if output, err := unmount.CombinedOutput(); err != nil {
			t.Errorf("unmount WebDAV: %v\n%s", err, output)
		}
	}()

	var contents []byte
	for deadline := time.Now().Add(5 * time.Second); ; {
		contents, err = os.ReadFile(filepath.Join(mountpoint, "hello.txt"))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("read through native WebDAV mount: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if string(contents) != "hello world" {
		t.Fatalf("mounted contents = %q", contents)
	}
	if nested := readMountedFile(t, filepath.Join(mountpoint, "dir", "nested.txt"), "nested", 5*time.Second); nested != "nested" {
		t.Fatalf("nested mounted contents = %q", nested)
	}
	if err := os.WriteFile(filepath.Join(mountpoint, "created.txt"), []byte("forbidden"), 0o644); err == nil {
		t.Fatal("native WebDAV mount accepted a write")
	}

	if err := os.WriteFile(filepath.Join(fixture.source, "hello.txt"), []byte("refreshed through Finder"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.source, "新增.txt"), []byte("unicode path"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.publisher.Publish(context.Background(), fixture.source, "main"); err != nil {
		t.Fatal(err)
	}
	if result, err := fixture.handler.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	} else if result.Status != s3disk.RefreshUpdated {
		t.Fatalf("WebDAV refresh did not adopt the new publication: %#v", result)
	}
	assertDirectWebDAVFile(t, server.URL+"/hello.txt", "refreshed through Finder")

	// Apple's WebDAVFS validates a downloaded file at most once per 60 seconds.
	// The server cannot invalidate that client-side cache, so allow one complete
	// native validation window while proving that the mounted view advances
	// without a remount.
	readMountedFile(t, filepath.Join(mountpoint, "hello.txt"), "refreshed through Finder", 75*time.Second)
	readMountedFile(t, filepath.Join(mountpoint, "新增.txt"), "unicode path", 15*time.Second)
}

func assertDirectWebDAVFile(t *testing.T, url, want string) {
	t.Helper()
	response, err := http.Get(url) // #nosec G107 -- the URL is an in-process test server.
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(contents) != want {
		t.Fatalf("direct WebDAV GET: status=%d contents=%q", response.StatusCode, contents)
	}
}

func readMountedFile(t *testing.T, path, want string, timeout time.Duration) string {
	t.Helper()
	var (
		contents []byte
		err      error
	)
	for deadline := time.Now().Add(timeout); ; {
		contents, err = os.ReadFile(path)
		if err == nil && string(contents) == want {
			return string(contents)
		}
		if time.Now().After(deadline) {
			t.Fatalf("read mounted file %q: contents=%q error=%v", path, contents, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

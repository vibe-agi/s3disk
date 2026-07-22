//go:build integration && darwin

package webdav

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
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
	if err := os.WriteFile(filepath.Join(mountpoint, "created.txt"), []byte("forbidden"), 0o644); err == nil {
		t.Fatal("native WebDAV mount accepted a write")
	}
}

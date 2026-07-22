package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestCommandTreeHasProductEntryPoints(t *testing.T) {
	root := NewRootCommand(Dependencies{
		Publish: func(context.Context, PublishOptions) error { return nil },
		Mount:   func(context.Context, MountOptions) error { return nil },
		MountSet: func(context.Context, MountSetOptions) error {
			return nil
		},
		ServeWebDAV: func(context.Context, WebDAVOptions) error { return nil },
		Doctor:      func(context.Context, DoctorOptions, io.Writer) error { return nil },
	})
	for _, path := range [][]string{{"share", "publish"}, {"share", "resume"}, {"mount"}, {"mount-set"}, {"serve", "webdav"}, {"s3", "doctor"}} {
		command, _, err := root.Find(path)
		if err != nil || command == nil || command.CommandPath() != "s3disk "+strings.Join(path, " ") {
			t.Fatalf("missing command %q: command=%v err=%v", strings.Join(path, " "), command, err)
		}
	}
}

func TestWebDAVCommandPassesOnlyHandoffAndLocalOptions(t *testing.T) {
	wantErr := errors.New("stop")
	var observed WebDAVOptions
	root := NewRootCommand(Dependencies{ServeWebDAV: func(_ context.Context, options WebDAVOptions) error {
		observed = options
		return wantErr
	}})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"serve", "webdav", "--handoff", "/private/share.json", "--listen", "[::1]:9876",
		"--state-dir", "/state", "--cache-dir", "/cache", "--poll-interval", "750ms", "--poll-timeout", "45s",
	})
	err := root.ExecuteContext(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v", err)
	}
	if observed.HandoffPath != "/private/share.json" || observed.Listen != "[::1]:9876" ||
		observed.StateDir != "/state" || observed.CacheDir != "/cache" ||
		observed.PollInterval != 750*time.Millisecond || observed.PollTimeout != 45*time.Second ||
		observed.StatusWriter != &stdout || observed.ErrorWriter != &stderr {
		t.Fatalf("unexpected WebDAV options: %#v", observed)
	}
}

func TestWebDAVCommandRejectsNonLoopbackListener(t *testing.T) {
	called := false
	root := NewRootCommand(Dependencies{ServeWebDAV: func(context.Context, WebDAVOptions) error {
		called = true
		return nil
	}})
	root.SetArgs([]string{
		"serve", "webdav", "--handoff", "/private/share.json", "--listen", "0.0.0.0:9867", "--state-dir", "/state",
	})
	err := root.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("WebDAV runner called with a non-loopback listener")
	}
}

func TestWebDAVCommandDefaultsToFreeLoopbackPort(t *testing.T) {
	wantErr := errors.New("stop")
	var observed WebDAVOptions
	root := NewRootCommand(Dependencies{ServeWebDAV: func(_ context.Context, options WebDAVOptions) error {
		observed = options
		return wantErr
	}})
	root.SetArgs([]string{
		"serve", "webdav", "--handoff", "/private/share.json", "--state-dir", "/state",
	})
	if err := root.ExecuteContext(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v", err)
	}
	if observed.Listen != "127.0.0.1:0" {
		t.Fatalf("default listen address = %q", observed.Listen)
	}
}

func TestMountSetCommandPassesOnlyPrivateConfigAndOutput(t *testing.T) {
	wantErr := errors.New("stop")
	var observed MountSetOptions
	root := NewRootCommand(Dependencies{MountSet: func(_ context.Context, options MountSetOptions) error {
		observed = options
		return wantErr
	}})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"mount-set", "--config", "/private/mounts.json"})
	if err := root.ExecuteContext(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v", err)
	}
	if observed.ConfigPath != "/private/mounts.json" ||
		observed.StatusWriter != &stdout || observed.ErrorWriter != &stderr {
		t.Fatalf("unexpected mount-set options: %#v", observed)
	}
}

func TestRootCommandReportsBuildVersion(t *testing.T) {
	root := NewRootCommand(Dependencies{Version: "v0.1.0-test"})
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetArgs([]string{"--version"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "s3disk version v0.1.0-test\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestPublishCommandValidatesSelectionAndFailClosedMode(t *testing.T) {
	base := []string{
		"share", "publish", "--source", t.TempDir(), "--bucket", "bucket", "--prefix", "private/share",
		"--state-dir", t.TempDir(), "--handoff-out", t.TempDir() + "/share.json",
		"--recovery-key", "/recovery-key.json", "--tls-ca", "/ca.pem",
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "selection required", args: append(append([]string(nil), base...), "--once"), want: "choose exactly one"},
		{name: "selection exclusive", args: append(append([]string(nil), base...), "--once", "--all", "--path", "file"), want: "choose exactly one"},
		{name: "path traversal", args: append(append([]string(nil), base...), "--once", "--path", "../secret"), want: "must not traverse"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := NewRootCommand(Dependencies{Publish: func(context.Context, PublishOptions) error {
				t.Fatal("runner called after invalid flags")
				return nil
			}})
			root.SetArgs(test.args)
			err := root.ExecuteContext(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestPublishCommandDefaultsToContinuousMode(t *testing.T) {
	called := false
	root := NewRootCommand(Dependencies{Publish: func(_ context.Context, options PublishOptions) error {
		called = true
		if options.Once {
			t.Fatal("continuous mode unexpectedly became --once")
		}
		return nil
	}})
	root.SetArgs([]string{
		"share", "publish", "--source", "/source", "--all", "--bucket", "bucket", "--prefix", "private/share",
		"--state-dir", "/state", "--handoff-out", "/handoff", "--recovery-key", "/recovery-key.json", "--tls-ca", "/ca.pem",
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("continuous publish runner was not called")
	}
}

func TestPublishCommandPassesValidatedOptions(t *testing.T) {
	var observed PublishOptions
	var stdout, stderr bytes.Buffer
	root := NewRootCommand(Dependencies{Publish: func(_ context.Context, options PublishOptions) error {
		observed = clonePublishOptions(options)
		options.Paths[0] = "mutated"
		return nil
	}})
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"share", "publish", "--source", "/source", "--path", "dir/file,with-comma", "--bucket", "bucket",
		"--prefix", "shares/random", "--state-dir", "/state", "--handoff-out", "/handoff.json",
		"--recovery-key", "/recovery-key.json", "--region", "ap-southeast-1", "--expires-in", "90m", "--tls-ca", "/ca.pem", "--once",
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if observed.Region != "ap-southeast-1" || observed.ExpiresIn != 90*time.Minute || !observed.Once ||
		!reflect.DeepEqual(observed.Paths, []string{"dir/file,with-comma"}) ||
		observed.StatusWriter != &stdout || observed.ErrorWriter != &stderr {
		t.Fatalf("unexpected options: %#v", observed)
	}
}

func TestMountCommandHasNoS3AuthorityFlags(t *testing.T) {
	root := NewRootCommand(Dependencies{})
	command, _, err := root.Find([]string{"mount"})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"access-key", "secret-key", "session-token", "bucket", "endpoint", "region", "profile"} {
		if command.Flags().Lookup(forbidden) != nil || command.InheritedFlags().Lookup(forbidden) != nil {
			t.Fatalf("mount unexpectedly exposes --%s", forbidden)
		}
	}
}

func TestMountCommandPassesOnlyHandoffAndLocalOptions(t *testing.T) {
	wantErr := errors.New("stop")
	var observed MountOptions
	root := NewRootCommand(Dependencies{Mount: func(_ context.Context, options MountOptions) error {
		observed = options
		return wantErr
	}})
	var stderr bytes.Buffer
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"mount", "--handoff", "/private/share.json", "--mountpoint", "/mnt/share", "--state-dir", "/state",
		"--cache-dir", "/cache", "--poll-interval", "750ms", "--poll-timeout", "45s",
	})
	err := root.ExecuteContext(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v", err)
	}
	if observed.HandoffPath != "/private/share.json" || observed.Mountpoint != "/mnt/share" ||
		observed.StateDir != "/state" || observed.CacheDir != "/cache" || observed.PollInterval != 750*time.Millisecond ||
		observed.PollTimeout != 45*time.Second ||
		observed.ErrorWriter != &stderr {
		t.Fatalf("unexpected mount options: %#v", observed)
	}
}

func TestPublishDoesNotExposeSystemTrustOptOut(t *testing.T) {
	root := NewRootCommand(Dependencies{})
	publish, _, err := root.Find([]string{"share", "publish"})
	if err != nil {
		t.Fatal(err)
	}
	if publish.Flags().Lookup("dangerously-allow-system-trust") != nil {
		t.Fatal("share publish exposes the system-trust S3-only opt-out")
	}
	doctor, _, err := root.Find([]string{"s3", "doctor"})
	if err != nil {
		t.Fatal(err)
	}
	if doctor.Flags().Lookup("dangerously-allow-system-trust") == nil {
		t.Fatal("s3 doctor unexpectedly lost its A-side diagnostic opt-out")
	}
}

func TestPublishRequiresExplicitCAForStrictS3OnlyHTTPS(t *testing.T) {
	root := NewRootCommand(Dependencies{Publish: func(context.Context, PublishOptions) error {
		t.Fatal("publish runner called without an explicit CA")
		return nil
	}})
	root.SetArgs([]string{
		"share", "publish", "--source", "/source", "--all", "--bucket", "bucket", "--prefix", "private/share",
		"--state-dir", "/state", "--handoff-out", "/handoff", "--recovery-key", "/recovery-key.json",
	})
	err := root.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--tls-ca is required for the strict S3-only share profile") {
		t.Fatalf("error = %v", err)
	}
}

func TestDoctorCommandPassesSafeConfigurationAndOutput(t *testing.T) {
	var observed DoctorOptions
	root := NewRootCommand(Dependencies{Doctor: func(_ context.Context, options DoctorOptions, output io.Writer) error {
		observed = options
		_, err := io.WriteString(output, "{\"compatible\":true}\n")
		return err
	}})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"s3", "doctor", "--bucket", "bucket", "--endpoint", "http://127.0.0.1:9000", "--path-style",
		"--dangerously-allow-http", "--timeout", "20s", "--total-timeout", "45s",
		"--capability-lifetime", "30s", "--cleanup-timeout", "3s",
		"--deployment-fingerprint", strings.Repeat("a", 64), "--evidence-id", "release-42",
		"--implementation-version", "v0.0.0-dev+42",
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "{\"compatible\":true}\n" || observed.Bucket != "bucket" || !observed.UsePathStyle ||
		!observed.AllowInsecureEndpoint || observed.PresignedTimeout != 20*time.Second || observed.TotalTimeout != 45*time.Second ||
		observed.CapabilityLifetime != 30*time.Second || observed.DeploymentFingerprint != strings.Repeat("a", 64) ||
		observed.EvidenceID != "release-42" || observed.ImplementationVersion != "v0.0.0-dev+42" ||
		observed.ErrorWriter != &stderr {
		t.Fatalf("stdout=%q options=%#v", stdout.String(), observed)
	}
}

func TestDoctorCommandRejectsPartialEvidenceBindingsBeforeOutput(t *testing.T) {
	called := false
	root := NewRootCommand(Dependencies{Doctor: func(context.Context, DoctorOptions, io.Writer) error {
		called = true
		return nil
	}})
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{
		"s3", "doctor", "--bucket", "bucket", "--endpoint", "http://127.0.0.1:9000",
		"--dangerously-allow-http", "--deployment-fingerprint", strings.Repeat("a", 64),
	})
	err := root.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "must be supplied together") {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("doctor runner called after preflight failure")
	}
	if stdout.Len() != 0 {
		t.Fatalf("preflight wrote stdout: %q", stdout.String())
	}
}

func TestNoCredentialFlagsAnywhere(t *testing.T) {
	root := NewRootCommand(Dependencies{})
	for _, command := range append([]*cobra.Command{root}, flattenCommands(root.Commands())...) {
		command.LocalFlags().VisitAll(func(flag *pflag.Flag) {
			lower := strings.ToLower(flag.Name)
			if strings.Contains(lower, "access-key") || strings.Contains(lower, "secret-key") || strings.Contains(lower, "session-token") {
				t.Errorf("%s exposes credential flag --%s", command.CommandPath(), flag.Name)
			}
		})
	}
}

func flattenCommands(commands []*cobra.Command) []*cobra.Command {
	var flattened []*cobra.Command
	for _, command := range commands {
		flattened = append(flattened, command)
		flattened = append(flattened, flattenCommands(command.Commands())...)
	}
	return flattened
}

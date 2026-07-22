package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadMountSetConfigAppliesDefaultsAndRejectsUnknownOrDuplicateMembers(t *testing.T) {
	root := privateMountSetTestDirectory(t)
	mountpoint := filepath.Join(root, "mount")
	state := filepath.Join(root, "state")
	handoff := filepath.Join(root, "handoff.json")
	valid := fmt.Sprintf(
		`{"version":1,"mounts":[{"name":"workspace-a","handoff":%q,"mountpoint":%q,"state_dir":%q}]}`,
		handoff, mountpoint, state,
	)
	path := writeMountSetTestConfig(t, root, "valid.json", valid)
	config, resolved, err := readMountSetConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	wantResolved, err := resolvePrivatePath(path)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != string(wantResolved) || len(config.Mounts) != 1 {
		t.Fatalf("resolved=%q config=%#v", resolved, config)
	}
	options, err := config.Mounts[0].mountOptions()
	if err != nil {
		t.Fatal(err)
	}
	if options.PollInterval != defaultPollInterval || options.PollTimeout != defaultPollTimeout {
		t.Fatalf("default polling = %s/%s", options.PollInterval, options.PollTimeout)
	}

	for _, test := range []struct {
		name string
		body string
		want string
	}{
		{name: "unknown", body: strings.Replace(valid, `"version":1`, `"version":1,"unexpected":true`, 1), want: "unknown field"},
		{name: "duplicate", body: strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1), want: "duplicate JSON member"},
		{name: "trailing", body: valid + `{}`, want: "trailing JSON value"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := writeMountSetTestConfig(t, root, test.name+".json", test.body)
			_, _, err := readMountSetConfig(candidate)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestReadMountSetConfigRequiresPrivateFile(t *testing.T) {
	root := privateMountSetTestDirectory(t)
	path := writeMountSetTestConfig(t, root, "mounts.json", `{"version":1,"mounts":[]}`)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := readMountSetConfig(path)
	if err == nil || !strings.Contains(err.Error(), "private file validation failed") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateMountSetConfigBoundsNamesPathsAndDurations(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "value")
	valid := mountSetConfig{Version: mountSetFormat, Mounts: []mountSetEntry{{
		Name: "workspace-1", Handoff: absolute + "-handoff",
		Mountpoint: absolute + "-mount", StateDir: absolute + "-state",
		PollInterval: "750ms", PollTimeout: "45s",
	}}}
	if err := validateMountSetConfig(valid); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*mountSetConfig)
		want   string
	}{
		{name: "version", mutate: func(config *mountSetConfig) { config.Version = 2 }, want: "version must be 1"},
		{name: "duplicate name", mutate: func(config *mountSetConfig) { config.Mounts = append(config.Mounts, config.Mounts[0]) }, want: "duplicated"},
		{name: "unsafe name", mutate: func(config *mountSetConfig) { config.Mounts[0].Name = "../workspace" }, want: "name is invalid"},
		{name: "relative path", mutate: func(config *mountSetConfig) { config.Mounts[0].Handoff = "handoff.json" }, want: "must be absolute"},
		{name: "short polling", mutate: func(config *mountSetConfig) { config.Mounts[0].PollInterval = "1ms" }, want: "poll-interval"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Mounts = append([]mountSetEntry(nil), valid.Mounts...)
			test.mutate(&candidate)
			if err := validateMountSetConfig(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidatePreparedMountSetRejectsCrossWorkspacePathOverlap(t *testing.T) {
	root := t.TempDir()
	entries := []preparedMountSetEntry{
		{name: "a", handoffPath: filepath.Join(root, "a.handoff"), local: mountLocalPaths{
			mountpoint: filepath.Join(root, "mount-a"), stateDir: filepath.Join(root, "state-a"),
		}},
		{name: "b", handoffPath: filepath.Join(root, "b.handoff"), local: mountLocalPaths{
			mountpoint: filepath.Join(root, "mount-a", "nested"), stateDir: filepath.Join(root, "state-b"),
		}},
	}
	if err := validatePreparedMountSet(filepath.Join(root, "config.json"), entries); err == nil || !strings.Contains(err.Error(), "mountpoints") {
		t.Fatalf("error = %v", err)
	}
	entries[1].local.mountpoint = filepath.Join(root, "mount-b")
	entries[1].local.stateDir = filepath.Join(root, "mount-a", "state")
	if err := validatePreparedMountSet(filepath.Join(root, "config.json"), entries); err == nil || !strings.Contains(err.Error(), "state or cache") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunMountSetRejectsDuplicateShareBeforeStartingMounts(t *testing.T) {
	root := privateMountSetTestDirectory(t)
	handoff := filepath.Join(root, "share.handoff")
	if err := writeHandoff(context.Background(), handoff, newTestHandoff(t)); err != nil {
		t.Fatal(err)
	}
	mountA := filepath.Join(root, "mount-a")
	mountB := filepath.Join(root, "mount-b")
	for _, path := range []string{mountA, mountB} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := fmt.Sprintf(
		`{"version":1,"mounts":[`+
			`{"name":"a","handoff":%q,"mountpoint":%q,"state_dir":%q},`+
			`{"name":"b","handoff":%q,"mountpoint":%q,"state_dir":%q}`+
			`]}`,
		handoff, mountA, filepath.Join(root, "state"),
		handoff, mountB, filepath.Join(root, "state"),
	)
	configPath := writeMountSetTestConfig(t, root, "mounts.json", config)
	err := runMountSet(context.Background(), MountSetOptions{ConfigPath: configPath})
	if err == nil || !strings.Contains(err.Error(), "refer to the same share") {
		t.Fatalf("error = %v", err)
	}
}

func TestSuperviseMountSetRunsAllUntilGracefulCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan string, 2)
	tasks := make([]mountSetTask, 0, 2)
	for _, name := range []string{"a", "b"} {
		name := name
		tasks = append(tasks, mountSetTask{name: name, run: func(ctx context.Context) error {
			started <- name
			<-ctx.Done()
			return ctx.Err()
		}})
	}
	result := make(chan error, 1)
	go func() { result <- superviseMountSet(ctx, tasks) }()
	seen := map[string]bool{}
	for range tasks {
		select {
		case name := <-started:
			seen[name] = true
		case <-time.After(time.Second):
			t.Fatal("mount set did not start every workspace")
		}
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("started = %#v", seen)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("graceful cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("mount set did not stop after cancellation")
	}
}

func TestSuperviseMountSetCancelsPeersOnTerminalFailure(t *testing.T) {
	wantErr := errors.New("mount failed")
	bothStarted := make(chan struct{})
	peerCanceled := make(chan struct{})
	var mu sync.Mutex
	count := 0
	started := func() {
		mu.Lock()
		defer mu.Unlock()
		count++
		if count == 2 {
			close(bothStarted)
		}
	}
	tasks := []mountSetTask{
		{name: "healthy", run: func(ctx context.Context) error {
			started()
			<-ctx.Done()
			close(peerCanceled)
			return ctx.Err()
		}},
		{name: "broken", run: func(context.Context) error {
			started()
			<-bothStarted
			return wantErr
		}},
	}
	err := superviseMountSet(context.Background(), tasks)
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), `workspace "broken" failed`) {
		t.Fatalf("error = %v", err)
	}
	select {
	case <-peerCanceled:
	default:
		t.Fatal("peer was not canceled before supervisor returned")
	}
}

func TestMountSetWorkspaceWriterPrefixesCompleteAndFragmentedLines(t *testing.T) {
	var destination bytes.Buffer
	output := &mountSetOutput{}
	writer := output.writer("alpha", &destination)
	for _, fragment := range []string{"first", " line\nsecond\n", "third", " line\n"} {
		if _, err := writer.Write([]byte(fragment)); err != nil {
			t.Fatal(err)
		}
	}
	want := "workspace=\"alpha\" first line\nworkspace=\"alpha\" second\nworkspace=\"alpha\" third line\n"
	if destination.String() != want {
		t.Fatalf("output = %q, want %q", destination.String(), want)
	}
}

func privateMountSetTestDirectory(t *testing.T) string {
	t.Helper()
	requirePrivateSecretFiles(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeMountSetTestConfig(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

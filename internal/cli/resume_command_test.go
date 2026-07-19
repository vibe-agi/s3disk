package cli

import (
	"bytes"
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

const testResumeShareID = "AQEBAQEBAQEBAQEBAQEBAQ"

func TestPublishCommandRequiresAndPassesRecoveryKey(t *testing.T) {
	base := []string{
		"share", "publish",
		"--source", "/source",
		"--all",
		"--bucket", "bucket",
		"--prefix", "private/share",
		"--state-dir", "/state",
		"--handoff-out", "/handoff.json",
		"--endpoint", "http://127.0.0.1:9000",
		"--dangerously-allow-http",
		"--once",
	}

	t.Run("required", func(t *testing.T) {
		called := false
		root := NewRootCommand(Dependencies{Publish: func(context.Context, PublishOptions) error {
			called = true
			return nil
		}})
		root.SetArgs(base)
		err := root.ExecuteContext(context.Background())
		if err == nil || !strings.Contains(err.Error(), "--recovery-key is required") {
			t.Fatalf("error = %v, want missing --recovery-key", err)
		}
		if called {
			t.Fatal("publish runner called without --recovery-key")
		}
	})

	t.Run("dependency receives path", func(t *testing.T) {
		const recoveryKey = "/private/recovery-key.json"
		called := false
		root := NewRootCommand(Dependencies{Publish: func(_ context.Context, options PublishOptions) error {
			called = true
			if options.RecoveryKey != recoveryKey {
				t.Fatalf("RecoveryKey = %q, want %q", options.RecoveryKey, recoveryKey)
			}
			return nil
		}})
		root.SetArgs(append(append([]string(nil), base...), "--recovery-key", recoveryKey))
		if err := root.ExecuteContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatal("publish runner was not called")
		}
	})
}

func TestResumeCommandPassesRecoveryCoordinates(t *testing.T) {
	const (
		stateDir    = "/private/s3disk-state"
		recoveryKey = "/private/recovery-key.json"
	)
	var stdout, stderr bytes.Buffer
	called := false
	root := NewRootCommand(Dependencies{Resume: func(_ context.Context, options ResumeOptions) error {
		called = true
		if options.StateDir != stateDir || options.ShareID != testResumeShareID || options.RecoveryKey != recoveryKey {
			t.Fatalf("options = %#v", options)
		}
		if options.StatusWriter != &stdout {
			t.Fatalf("StatusWriter = %T, want command stdout", options.StatusWriter)
		}
		if options.ErrorWriter != &stderr {
			t.Fatalf("ErrorWriter = %T, want command stderr", options.ErrorWriter)
		}
		return nil
	}})
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"share", "resume",
		"--state-dir", stateDir,
		"--share-id", testResumeShareID,
		"--recovery-key", recoveryKey,
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("resume runner was not called")
	}
}

func TestResumeCommandRejectsMissingInvalidAndExtraArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "state directory required",
			args: []string{"share", "resume", "--share-id", testResumeShareID, "--recovery-key", "/key"},
			want: "--state-dir is required",
		},
		{
			name: "share ID required",
			args: []string{"share", "resume", "--state-dir", "/state", "--recovery-key", "/key"},
			want: "--share-id is required",
		},
		{
			name: "recovery key required",
			args: []string{"share", "resume", "--state-dir", "/state", "--share-id", testResumeShareID},
			want: "--recovery-key is required",
		},
		{
			name: "share ID must be canonical",
			args: []string{"share", "resume", "--state-dir", "/state", "--share-id", "not-a-share-id", "--recovery-key", "/key"},
			want: "--share-id",
		},
		{
			name: "positional arguments rejected",
			args: []string{"share", "resume", "--state-dir", "/state", "--share-id", testResumeShareID, "--recovery-key", "/key", "unexpected"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			root := NewRootCommand(Dependencies{Resume: func(context.Context, ResumeOptions) error {
				called = true
				return nil
			}})
			root.SetArgs(test.args)
			err := root.ExecuteContext(context.Background())
			if err == nil {
				t.Fatal("expected command failure")
			}
			if test.want != "" && !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
			if called {
				t.Fatal("resume runner called after invalid arguments")
			}
		})
	}
}

func TestResumeCommandExposesOnlyRecoveryCoordinateFlags(t *testing.T) {
	root := NewRootCommand(Dependencies{})
	command, _, err := root.Find([]string{"share", "resume"})
	if err != nil {
		t.Fatal(err)
	}
	if command == nil || command.CommandPath() != "s3disk share resume" {
		t.Fatalf("unexpected resume command: %v", command)
	}

	var businessFlags []string
	command.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		businessFlags = append(businessFlags, flag.Name)
	})
	sort.Strings(businessFlags)
	want := []string{"recovery-key", "share-id", "state-dir"}
	if !reflect.DeepEqual(businessFlags, want) {
		t.Fatalf("resume flags = %v, want %v", businessFlags, want)
	}

	for _, forbidden := range []string{
		"bucket", "prefix", "region", "endpoint", "expected-bucket-owner", "path-style",
		"dangerously-allow-http", "expires-in", "source", "all", "path", "channel",
		"handoff", "handoff-out", "tls-ca", "once",
	} {
		if command.Flags().Lookup(forbidden) != nil || command.InheritedFlags().Lookup(forbidden) != nil {
			t.Errorf("share resume unexpectedly exposes --%s", forbidden)
		}
	}
}

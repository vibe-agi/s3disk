package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/vibe-agi/s3disk"
)

const (
	mountSetFormat                 = 1
	maximumMountSetBytes     int64 = 1 << 20
	maximumMountSetEntries         = 128
	maximumMountSetPathBytes       = 32 << 10
	maximumMountSetNameBytes       = 64
)

type mountSetConfig struct {
	Version int             `json:"version"`
	Mounts  []mountSetEntry `json:"mounts"`
}

type mountSetEntry struct {
	Name         string `json:"name"`
	Handoff      string `json:"handoff"`
	Mountpoint   string `json:"mountpoint"`
	StateDir     string `json:"state_dir"`
	CacheDir     string `json:"cache_dir,omitempty"`
	PollInterval string `json:"poll_interval,omitempty"`
	PollTimeout  string `json:"poll_timeout,omitempty"`
}

type preparedMountSetEntry struct {
	name        string
	options     MountOptions
	local       mountLocalPaths
	handoffPath string
	share       decodedHandoff
}

type mountSetTask struct {
	name string
	run  func(context.Context) error
}

func runMountSet(ctx context.Context, options MountSetOptions) error {
	if ctx == nil {
		return fmt.Errorf("s3disk mount-set: context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	config, configPath, err := readMountSetConfig(options.ConfigPath)
	if err != nil {
		return err
	}
	output := &mountSetOutput{}
	prepared := make([]preparedMountSetEntry, 0, len(config.Mounts))
	identities := make(map[string]string, len(config.Mounts))
	for _, entry := range config.Mounts {
		if err := ctx.Err(); err != nil {
			return err
		}
		mountOptions, entryErr := entry.mountOptions()
		if entryErr != nil {
			return fmt.Errorf("s3disk mount-set: workspace %q: %w", entry.Name, entryErr)
		}
		mountOptions.StatusWriter = output.writer(entry.Name, options.StatusWriter)
		mountOptions.ErrorWriter = output.writer(entry.Name, options.ErrorWriter)
		item, prepareErr := prepareMountSetEntry(mountOptions, entry.Name)
		if prepareErr != nil {
			return fmt.Errorf("s3disk mount-set: workspace %q preflight: %w", entry.Name, prepareErr)
		}
		identity := item.share.repository.String() + "\x00" + item.share.shareID.String()
		if previous, exists := identities[identity]; exists {
			return fmt.Errorf(
				"s3disk mount-set: workspaces %q and %q refer to the same share",
				previous, entry.Name,
			)
		}
		identities[identity] = entry.Name
		prepared = append(prepared, item)
	}
	if err := validatePreparedMountSet(configPath, prepared); err != nil {
		return err
	}
	tasks := make([]mountSetTask, 0, len(prepared))
	for index := range prepared {
		item := prepared[index]
		tasks = append(tasks, mountSetTask{name: item.name, run: func(taskContext context.Context) error {
			err := runPreparedMount(taskContext, item.options, item.local, item.share)
			if err == nil && taskContext.Err() == nil && item.options.StatusWriter != nil {
				_, _ = fmt.Fprintln(item.options.StatusWriter, "stopped: mount lifecycle ended")
			}
			return err
		}})
	}
	if options.StatusWriter != nil {
		_, _ = fmt.Fprintf(options.StatusWriter, "mount-set: starting workspaces=%d\n", len(tasks))
	}
	return superviseMountSet(ctx, tasks)
}

func readMountSetConfig(path string) (mountSetConfig, string, error) {
	fail := func(err error) (mountSetConfig, string, error) {
		return mountSetConfig{}, "", fmt.Errorf("s3disk mount-set: invalid config: %w", err)
	}
	if strings.TrimSpace(path) == "" {
		return fail(errors.New("path is required"))
	}
	resolved, err := resolvePrivatePath(path)
	if err != nil {
		return fail(err)
	}
	absolute := string(resolved)
	before, err := os.Lstat(absolute)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return fail(errors.New("path is not a regular non-symlink file"))
	}
	file, err := os.Open(absolute)
	if err != nil {
		return fail(err)
	}
	defer file.Close()
	if err := s3disk.ValidatePrivateSecretFile(absolute, file); err != nil {
		return fail(fmt.Errorf("private file validation failed: %w", err))
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maximumMountSetBytes+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > maximumMountSetBytes {
		clear(encoded)
		return fail(errors.New("file is empty, unreadable, or exceeds the size limit"))
	}
	defer clear(encoded)
	if !utf8.Valid(encoded) {
		return fail(errors.New("file is not valid UTF-8"))
	}
	if err := rejectDuplicateJSONNames(encoded); err != nil {
		return fail(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var config mountSetConfig
	if err := decoder.Decode(&config); err != nil {
		return fail(err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fail(errors.New("trailing JSON value"))
	}
	if err := validateMountSetConfig(config); err != nil {
		return fail(err)
	}
	return config, absolute, nil
}

func validateMountSetConfig(config mountSetConfig) error {
	if config.Version != mountSetFormat {
		return fmt.Errorf("version must be %d", mountSetFormat)
	}
	if len(config.Mounts) == 0 || len(config.Mounts) > maximumMountSetEntries {
		return fmt.Errorf("mounts must contain between 1 and %d entries", maximumMountSetEntries)
	}
	names := make(map[string]struct{}, len(config.Mounts))
	for index, entry := range config.Mounts {
		if !validMountSetName(entry.Name) {
			return fmt.Errorf("mounts[%d].name is invalid", index)
		}
		if _, exists := names[entry.Name]; exists {
			return fmt.Errorf("mounts[%d].name %q is duplicated", index, entry.Name)
		}
		names[entry.Name] = struct{}{}
		for _, field := range []struct {
			name     string
			value    string
			required bool
		}{
			{name: "handoff", value: entry.Handoff, required: true},
			{name: "mountpoint", value: entry.Mountpoint, required: true},
			{name: "state_dir", value: entry.StateDir, required: true},
			{name: "cache_dir", value: entry.CacheDir},
		} {
			value := field.value
			if (field.required && value == "") || len(value) > maximumMountSetPathBytes ||
				!utf8.ValidString(value) || strings.ContainsRune(value, '\x00') ||
				strings.TrimSpace(value) != value {
				return fmt.Errorf("mounts[%d].%s is invalid", index, field.name)
			}
			if value != "" && !filepath.IsAbs(value) {
				return fmt.Errorf("mounts[%d].%s must be absolute", index, field.name)
			}
		}
		if _, err := entry.mountOptions(); err != nil {
			return fmt.Errorf("mounts[%d]: %w", index, err)
		}
	}
	return nil
}

func (entry mountSetEntry) mountOptions() (MountOptions, error) {
	pollInterval, err := parseMountSetDuration(entry.PollInterval, defaultPollInterval)
	if err != nil {
		return MountOptions{}, fmt.Errorf("poll_interval: %w", err)
	}
	pollTimeout, err := parseMountSetDuration(entry.PollTimeout, defaultPollTimeout)
	if err != nil {
		return MountOptions{}, fmt.Errorf("poll_timeout: %w", err)
	}
	options := MountOptions{
		HandoffPath: entry.Handoff, Mountpoint: entry.Mountpoint,
		StateDir: entry.StateDir, CacheDir: entry.CacheDir,
		PollInterval: pollInterval, PollTimeout: pollTimeout,
	}
	if err := validateMountOptions(&options); err != nil {
		return MountOptions{}, err
	}
	return options, nil
}

func parseMountSetDuration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	if len(value) > 64 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return 0, errors.New("invalid duration")
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, errors.New("invalid duration")
	}
	return duration, nil
}

func validMountSetName(value string) bool {
	if len(value) == 0 || len(value) > maximumMountSetNameBytes {
		return false
	}
	for index, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func prepareMountSetEntry(options MountOptions, name string) (preparedMountSetEntry, error) {
	local, err := preflightMountLocalPaths(options)
	if err != nil {
		return preparedMountSetEntry{}, fmt.Errorf("local paths: %w", err)
	}
	handoffPath, err := resolveHandoffPath(options.HandoffPath)
	if err != nil {
		return preparedMountSetEntry{}, fmt.Errorf("handoff path: %w", err)
	}
	share, err := readHandoff(handoffPath)
	if err != nil {
		return preparedMountSetEntry{}, err
	}
	return preparedMountSetEntry{
		name: name, options: options, local: local, handoffPath: handoffPath, share: share,
	}, nil
}

func validatePreparedMountSet(configPath string, entries []preparedMountSetEntry) error {
	for index := range entries {
		current := entries[index]
		if pathWithin(configPath, current.local.mountpoint) || pathWithin(current.handoffPath, current.local.mountpoint) {
			return fmt.Errorf("s3disk mount-set: workspace %q mountpoint contains its config or handoff", current.name)
		}
		for otherIndex := range entries {
			if index == otherIndex {
				continue
			}
			other := entries[otherIndex]
			if pathsOverlap(current.local.mountpoint, other.local.mountpoint) {
				return fmt.Errorf("s3disk mount-set: workspace mountpoints %q and %q overlap", current.name, other.name)
			}
			if pathsOverlap(current.local.mountpoint, other.local.stateDir) ||
				(other.local.cacheBase != "" && pathsOverlap(current.local.mountpoint, other.local.cacheBase)) {
				return fmt.Errorf("s3disk mount-set: workspace %q mountpoint overlaps workspace %q state or cache", current.name, other.name)
			}
			if pathWithin(other.handoffPath, current.local.mountpoint) {
				return fmt.Errorf("s3disk mount-set: workspace %q mountpoint contains workspace %q handoff", current.name, other.name)
			}
		}
	}
	return nil
}

func superviseMountSet(ctx context.Context, tasks []mountSetTask) error {
	if ctx == nil {
		return fmt.Errorf("s3disk mount-set: context is required")
	}
	if len(tasks) == 0 {
		return fmt.Errorf("s3disk mount-set: no workspaces to supervise")
	}
	taskContext, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(tasks))
	for _, task := range tasks {
		task := task
		go func() {
			if task.run == nil {
				results <- result{name: task.name, err: errors.New("mount runner is unavailable")}
				return
			}
			results <- result{name: task.name, err: task.run(taskContext)}
		}()
	}
	var firstFailure error
	for range tasks {
		finished := <-results
		if finished.err != nil && firstFailure == nil && ctx.Err() == nil {
			firstFailure = fmt.Errorf("s3disk mount-set: workspace %q failed: %w", finished.name, finished.err)
			cancel()
		}
	}
	return firstFailure
}

func rejectDuplicateJSONNames(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return errors.New("object member name is not a string")
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("duplicate JSON member %q", name)
				}
				seen[name] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("unterminated JSON object")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("unterminated JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

type mountSetOutput struct {
	mu sync.Mutex
}

type mountSetWorkspaceWriter struct {
	output      *mountSetOutput
	workspace   string
	destination io.Writer
	atLineStart bool
}

func (output *mountSetOutput) writer(workspace string, destination io.Writer) io.Writer {
	if destination == nil {
		return nil
	}
	return &mountSetWorkspaceWriter{
		output: output, workspace: workspace, destination: destination, atLineStart: true,
	}
}

func (writer *mountSetWorkspaceWriter) Write(value []byte) (int, error) {
	writer.output.mu.Lock()
	defer writer.output.mu.Unlock()
	written := 0
	for len(value) > 0 {
		if writer.atLineStart {
			if err := writeAll(writer.destination, []byte(fmt.Sprintf("workspace=%q ", writer.workspace))); err != nil {
				return written, err
			}
			writer.atLineStart = false
		}
		newline := bytes.IndexByte(value, '\n')
		length := len(value)
		if newline >= 0 {
			length = newline + 1
		}
		if err := writeAll(writer.destination, value[:length]); err != nil {
			return written, err
		}
		written += length
		value = value[length:]
		if newline >= 0 {
			writer.atLineStart = true
		}
	}
	return written, nil
}

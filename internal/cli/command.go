// Package cli contains the deliberately thin command-line adapter for s3disk.
// Business rules and protocol state remain in the public library packages.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vibe-agi/s3disk/presignedshare"
	"github.com/vibe-agi/s3disk/s3store"
)

const (
	defaultChannel      = "main"
	defaultRegion       = "us-east-1"
	defaultShareExpiry  = 2 * time.Hour
	defaultPollInterval = time.Second
)

// Dependencies makes every command path testable without network or FUSE I/O.
// A nil function selects the production implementation.
type Dependencies struct {
	Publish             func(context.Context, PublishOptions) error
	GenerateRecoveryKey func(context.Context, RecoveryKeyGenerateOptions) error
	Mount               func(context.Context, MountOptions) error
	Doctor              func(context.Context, DoctorOptions, io.Writer) error
}

type PublishOptions struct {
	Source                string
	Paths                 []string
	All                   bool
	Bucket                string
	Prefix                string
	Region                string
	Endpoint              string
	ExpectedBucketOwner   string
	UsePathStyle          bool
	AllowInsecureEndpoint bool
	Channel               string
	ExpiresIn             time.Duration
	HandoffOut            string
	StateDir              string
	TLSCAFile             string
	Once                  bool
	StatusWriter          io.Writer
}

type MountOptions struct {
	HandoffPath  string
	Mountpoint   string
	StateDir     string
	CacheDir     string
	PollInterval time.Duration
	StatusWriter io.Writer
	ErrorWriter  io.Writer
}

type DoctorOptions struct {
	Bucket                      string
	Prefix                      string
	Region                      string
	Endpoint                    string
	ExpectedBucketOwner         string
	UsePathStyle                bool
	AllowInsecureEndpoint       bool
	TotalTimeout                time.Duration
	CapabilityLifetime          time.Duration
	CleanupTimeout              time.Duration
	TLSCAFile                   string
	DangerouslyAllowSystemTrust bool
}

func NewRootCommand(dependencies Dependencies) *cobra.Command {
	if dependencies.Publish == nil {
		dependencies.Publish = runPublish
	}
	if dependencies.GenerateRecoveryKey == nil {
		dependencies.GenerateRecoveryKey = runGenerateRecoveryKey
	}
	if dependencies.Mount == nil {
		dependencies.Mount = runMount
	}
	if dependencies.Doctor == nil {
		dependencies.Doctor = runDoctor
	}

	command := &cobra.Command{
		Use:           "s3disk",
		Short:         "Share a directory through S3 as a lazy read-only mount",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
	}
	command.CompletionOptions.DisableDefaultCmd = true
	command.SetFlagErrorFunc(func(command *cobra.Command, err error) error {
		return fmt.Errorf("%s: %w", command.CommandPath(), err)
	})
	command.AddCommand(newShareCommand(dependencies), newMountCommand(dependencies), newS3Command(dependencies))
	return command
}

func newShareCommand(dependencies Dependencies) *cobra.Command {
	command := &cobra.Command{Use: "share", Short: "Create a time-limited encrypted share", Args: cobra.NoArgs}
	command.AddCommand(newPublishCommand(dependencies), newRecoveryKeyCommand(dependencies))
	return command
}

func newRecoveryKeyCommand(dependencies Dependencies) *cobra.Command {
	command := &cobra.Command{
		Use:   "recovery-key",
		Short: "Manage A-side publisher recovery keys",
		Args:  cobra.NoArgs,
	}
	command.AddCommand(newRecoveryKeyGenerateCommand(dependencies))
	return command
}

func newRecoveryKeyGenerateCommand(dependencies Dependencies) *cobra.Command {
	options := RecoveryKeyGenerateOptions{}
	command := &cobra.Command{
		Use:   "generate",
		Short: "Generate a private publisher recovery-key file",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateRecoveryKeyGenerateOptions(options); err != nil {
				return err
			}
			options.StatusWriter = command.OutOrStdout()
			return dependencies.GenerateRecoveryKey(command.Context(), options)
		},
	}
	command.Flags().StringVar(&options.Out, "out", "", "new private 0600 publisher recovery-key file")
	return command
}

func newPublishCommand(dependencies Dependencies) *cobra.Command {
	options := PublishOptions{}
	command := &cobra.Command{
		Use:   "publish",
		Short: "Publish A's directory and write a secret handoff file for B",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validatePublishOptions(&options); err != nil {
				return err
			}
			options.StatusWriter = command.OutOrStdout()
			return dependencies.Publish(command.Context(), clonePublishOptions(options))
		},
	}
	flags := command.Flags()
	flags.SortFlags = false
	flags.StringVar(&options.Source, "source", "", "directory on A to share")
	flags.StringArrayVar(&options.Paths, "path", nil, "relative path to include (repeatable)")
	flags.BoolVar(&options.All, "all", false, "share the complete source tree")
	flags.StringVar(&options.Bucket, "bucket", "", "S3 bucket")
	flags.StringVar(&options.Prefix, "prefix", "", "private S3 prefix reserved for this share")
	flags.StringVar(&options.Region, "region", defaultRegion, "S3 region")
	flags.StringVar(&options.Endpoint, "endpoint", "", "S3-compatible endpoint (AWS is used when empty)")
	flags.StringVar(&options.ExpectedBucketOwner, "expected-bucket-owner", "", "expected AWS account ID for the bucket")
	flags.BoolVar(&options.UsePathStyle, "path-style", false, "use path-style S3 addressing")
	flags.BoolVar(&options.AllowInsecureEndpoint, "dangerously-allow-http", false, "allow an HTTP loopback endpoint for local testing")
	flags.StringVar(&options.Channel, "channel", defaultChannel, "share channel")
	flags.DurationVar(&options.ExpiresIn, "expires-in", defaultShareExpiry, "fixed authorization lifetime")
	flags.StringVar(&options.HandoffOut, "handoff-out", "", "new 0600 handoff file to give B privately")
	flags.StringVar(&options.StateDir, "state-dir", "", "private durable state directory on A")
	flags.StringVar(&options.TLSCAFile, "tls-ca", "", "PEM trust roots embedded in the handoff")
	flags.BoolVar(&options.Once, "once", false, "publish one snapshot and exit")
	return command
}

func newMountCommand(dependencies Dependencies) *cobra.Command {
	options := MountOptions{}
	command := &cobra.Command{
		Use:   "mount",
		Short: "Mount B's handoff as a lazy read-only filesystem",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateMountOptions(&options); err != nil {
				return err
			}
			options.StatusWriter = command.OutOrStdout()
			options.ErrorWriter = command.ErrOrStderr()
			return dependencies.Mount(command.Context(), options)
		},
	}
	flags := command.Flags()
	flags.SortFlags = false
	flags.StringVar(&options.HandoffPath, "handoff", "", "secret handoff file received privately from A")
	flags.StringVar(&options.Mountpoint, "mountpoint", "", "existing empty directory to mount")
	flags.StringVar(&options.StateDir, "state-dir", "", "private durable anti-rollback state directory on B")
	flags.StringVar(&options.CacheDir, "cache-dir", "", "private lazy block cache base (defaults below state-dir)")
	flags.DurationVar(&options.PollInterval, "poll-interval", defaultPollInterval, "S3 root refresh interval")
	return command
}

func newS3Command(dependencies Dependencies) *cobra.Command {
	command := &cobra.Command{Use: "s3", Short: "Commission an S3-compatible provider", Args: cobra.NoArgs}
	command.AddCommand(newDoctorCommand(dependencies))
	return command
}

func newDoctorCommand(dependencies Dependencies) *cobra.Command {
	options := DoctorOptions{}
	command := &cobra.Command{
		Use:   "doctor",
		Short: "Probe exact presigned-GET semantics and anonymous-policy confinement",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := validateDoctorOptions(&options); err != nil {
				return err
			}
			return dependencies.Doctor(command.Context(), options, command.OutOrStdout())
		},
	}
	flags := command.Flags()
	flags.SortFlags = false
	flags.StringVar(&options.Bucket, "bucket", "", "S3 bucket used for two temporary canary objects")
	flags.StringVar(&options.Prefix, "prefix", "", "private temporary-object prefix (uses a safe default when empty)")
	flags.StringVar(&options.Region, "region", defaultRegion, "S3 region")
	flags.StringVar(&options.Endpoint, "endpoint", "", "S3-compatible endpoint (AWS is used when empty)")
	flags.StringVar(&options.ExpectedBucketOwner, "expected-bucket-owner", "", "expected AWS account ID for the bucket")
	flags.BoolVar(&options.UsePathStyle, "path-style", false, "use path-style S3 addressing")
	flags.BoolVar(&options.AllowInsecureEndpoint, "dangerously-allow-http", false, "allow an HTTP loopback endpoint for local testing")
	flags.DurationVar(&options.TotalTimeout, "timeout", s3store.PresignedGetCompatibilityDefaultTimeout, "total semantic probe timeout")
	flags.DurationVar(&options.CapabilityLifetime, "capability-lifetime", s3store.PresignedGetCompatibilityDefaultCapabilityLifetime, "temporary bearer lifetime")
	flags.DurationVar(&options.CleanupTimeout, "cleanup-timeout", s3store.PresignedGetCompatibilityDefaultCleanupTimeout, "best-effort cleanup timeout")
	flags.StringVar(&options.TLSCAFile, "tls-ca", "", "PEM trust roots for HTTPS probes")
	flags.BoolVar(&options.DangerouslyAllowSystemTrust, "dangerously-allow-system-trust", false, "allow system TLS trust without an explicit CA bundle")
	return command
}

func validatePublishOptions(options *PublishOptions) error {
	if options == nil {
		return errors.New("s3disk share publish: options are required")
	}
	for _, field := range []struct{ name, value string }{
		{"--source", options.Source}, {"--bucket", options.Bucket}, {"--prefix", options.Prefix},
		{"--handoff-out", options.HandoffOut}, {"--state-dir", options.StateDir}, {"--region", options.Region},
		{"--channel", options.Channel},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("s3disk share publish: %s is required", field.name)
		}
	}
	if options.All == (len(options.Paths) > 0) {
		return errors.New("s3disk share publish: choose exactly one of --all or one or more --path flags")
	}
	if strings.Trim(options.Prefix, "/") == "" {
		return errors.New("s3disk share publish: --prefix must contain a non-slash path component")
	}
	for _, selected := range options.Paths {
		if err := validateSelectedPath(selected); err != nil {
			return fmt.Errorf("s3disk share publish: invalid --path: %w", err)
		}
	}
	if options.ExpiresIn <= 0 || options.ExpiresIn > presignedshare.MaximumCapabilityLifetime {
		return fmt.Errorf("s3disk share publish: --expires-in must be positive and at most %s", presignedshare.MaximumCapabilityLifetime)
	}
	if err := validateStrictShareEndpointTrust(options.Endpoint, options.AllowInsecureEndpoint, options.TLSCAFile != ""); err != nil {
		return fmt.Errorf("s3disk share publish: %w", err)
	}
	if pathsOverlap(options.Source, options.StateDir) {
		return errors.New("s3disk share publish: --source and --state-dir must not contain one another")
	}
	if pathWithin(options.HandoffOut, options.Source) || pathWithin(options.HandoffOut, options.StateDir) {
		return errors.New("s3disk share publish: --handoff-out must be outside --source and --state-dir")
	}
	return nil
}

func validateStrictShareEndpointTrust(endpoint string, allowHTTP, hasTLSCA bool) error {
	err := validateEndpointTrust(endpoint, allowHTTP, hasTLSCA, false)
	if err == nil || hasTLSCA || allowHTTP {
		return err
	}
	if endpoint == "" {
		return errors.New("--tls-ca is required for the strict S3-only share profile")
	}
	parsed, parseErr := url.Parse(endpoint)
	if parseErr == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" {
		return errors.New("--tls-ca is required for the strict S3-only share profile")
	}
	return err
}

func validateSelectedPath(value string) error {
	if value == "" || value == "." || filepath.IsAbs(value) || strings.ContainsRune(value, '\x00') {
		return errors.New("path must be a non-empty relative path below source")
	}
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == ".." || strings.HasPrefix(clean, "../") || clean != filepath.ToSlash(value) {
		return errors.New("path must be clean and must not traverse above source")
	}
	return nil
}

func validateMountOptions(options *MountOptions) error {
	if options == nil {
		return errors.New("s3disk mount: options are required")
	}
	for _, field := range []struct{ name, value string }{
		{"--handoff", options.HandoffPath}, {"--mountpoint", options.Mountpoint}, {"--state-dir", options.StateDir},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("s3disk mount: %s is required", field.name)
		}
	}
	if options.PollInterval < 100*time.Millisecond || options.PollInterval > 5*time.Minute {
		return errors.New("s3disk mount: --poll-interval must be between 100ms and 5m")
	}
	if pathsOverlap(options.StateDir, options.Mountpoint) {
		return errors.New("s3disk mount: --state-dir and --mountpoint must not contain one another")
	}
	if options.CacheDir != "" && pathsOverlap(options.CacheDir, options.Mountpoint) {
		return errors.New("s3disk mount: --cache-dir and --mountpoint must not contain one another")
	}
	if options.CacheDir != "" && pathsOverlap(options.CacheDir, options.StateDir) {
		return errors.New("s3disk mount: --cache-dir and --state-dir must not contain one another")
	}
	return nil
}

func validateDoctorOptions(options *DoctorOptions) error {
	if options == nil {
		return errors.New("s3disk s3 doctor: options are required")
	}
	if strings.TrimSpace(options.Bucket) == "" {
		return errors.New("s3disk s3 doctor: --bucket is required")
	}
	if strings.TrimSpace(options.Region) == "" {
		return errors.New("s3disk s3 doctor: --region is required")
	}
	if options.TotalTimeout <= 0 || options.TotalTimeout > s3store.PresignedGetCompatibilityMaximumTimeout {
		return fmt.Errorf("s3disk s3 doctor: --timeout must be positive and at most %s", s3store.PresignedGetCompatibilityMaximumTimeout)
	}
	if options.CapabilityLifetime < 2*time.Second || options.CapabilityLifetime > presignedshare.MaximumCapabilityLifetime {
		return fmt.Errorf("s3disk s3 doctor: --capability-lifetime must be between 2s and %s", presignedshare.MaximumCapabilityLifetime)
	}
	if options.CapabilityLifetime < options.TotalTimeout+2*time.Second {
		return errors.New("s3disk s3 doctor: --capability-lifetime must cover --timeout plus the signing margin")
	}
	if options.CleanupTimeout <= 0 || options.CleanupTimeout > s3store.PresignedGetCompatibilityMaximumTimeout {
		return fmt.Errorf("s3disk s3 doctor: --cleanup-timeout must be positive and at most %s", s3store.PresignedGetCompatibilityMaximumTimeout)
	}
	if options.TLSCAFile != "" && options.DangerouslyAllowSystemTrust {
		return errors.New("s3disk s3 doctor: --tls-ca and --dangerously-allow-system-trust are mutually exclusive")
	}
	if err := validateEndpointTrust(options.Endpoint, options.AllowInsecureEndpoint, options.TLSCAFile != "", options.DangerouslyAllowSystemTrust); err != nil {
		return fmt.Errorf("s3disk s3 doctor: %w", err)
	}
	return nil
}

func validateEndpointTrust(endpoint string, allowHTTP, hasTLSCA, allowSystemTrust bool) error {
	if endpoint == "" {
		if hasTLSCA == allowSystemTrust {
			return errors.New("choose exactly one of --tls-ca or --dangerously-allow-system-trust for HTTPS")
		}
		if allowHTTP {
			return errors.New("--dangerously-allow-http requires an explicit HTTP loopback endpoint")
		}
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("--endpoint must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	if parsed.Scheme == "http" {
		address := net.ParseIP(parsed.Hostname())
		if address == nil || !address.IsLoopback() {
			return errors.New("HTTP is restricted to a literal loopback endpoint")
		}
		if !allowHTTP {
			return errors.New("HTTP loopback requires --dangerously-allow-http")
		}
		if hasTLSCA || allowSystemTrust {
			return errors.New("HTTP loopback does not use --tls-ca or --dangerously-allow-system-trust")
		}
		return nil
	}
	if allowHTTP {
		return errors.New("--dangerously-allow-http is valid only with an HTTP loopback endpoint")
	}
	if hasTLSCA == allowSystemTrust {
		return errors.New("choose exactly one of --tls-ca or --dangerously-allow-system-trust for HTTPS")
	}
	return nil
}

func clonePublishOptions(options PublishOptions) PublishOptions {
	options.Paths = append([]string(nil), options.Paths...)
	return options
}

func pathsOverlap(first, second string) bool {
	return pathWithin(first, second) || pathWithin(second, first)
}

func pathWithin(candidate, directory string) bool {
	candidateAbs, candidateErr := filepath.Abs(candidate)
	directoryAbs, directoryErr := filepath.Abs(directory)
	if candidateErr != nil || directoryErr != nil {
		return false
	}
	relative, err := filepath.Rel(filepath.Clean(directoryAbs), filepath.Clean(candidateAbs))
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func ExecuteContext(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	command := NewRootCommand(Dependencies{})
	command.SetArgs(arguments)
	command.SetOut(stdout)
	command.SetErr(stderr)
	return command.ExecuteContext(ctx)
}

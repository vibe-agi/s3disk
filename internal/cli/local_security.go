package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/presignedshare"
)

func preparePrivateDirectory(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if os.IsNotExist(err) {
		parent, resolveErr := filepath.EvalSymlinks(filepath.Dir(absolute))
		if resolveErr != nil {
			return "", resolveErr
		}
		absolute = filepath.Join(parent, filepath.Base(absolute))
		if err := os.Mkdir(absolute, 0o700); err != nil {
			return "", err
		}
		if err := syncPrivateDirectory(parent); err != nil {
			return "", fmt.Errorf("make private directory durable: %w", err)
		}
		info, err = os.Lstat(absolute)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("path is not a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("directory permissions must not grant group or other access")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

type publishLocalPaths struct {
	source      string
	stateDir    string
	handoff     string
	recoveryKey string
}

func protectedPublisherSourceFiles(
	recoveryKey string,
	handoff string,
	shareDirectory string,
) []s3disk.ProtectedSourceFile {
	return []s3disk.ProtectedSourceFile{
		{Path: recoveryKey},
		{Path: filepath.Join(shareDirectory, publisherSessionFileName)},
		{Path: filepath.Join(shareDirectory, publicationJournalFileName)},
		{Path: filepath.Join(shareDirectory, rootRecoveryFileName)},
		{Path: handoff, AllowMissingInitially: true},
	}
}

func preflightPublishLocalPaths(ctx context.Context, options PublishOptions) (publishLocalPaths, error) {
	if ctx == nil {
		return publishLocalPaths{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return publishLocalPaths{}, err
	}
	source, err := filepath.EvalSymlinks(options.Source)
	if err != nil {
		return publishLocalPaths{}, fmt.Errorf("resolve source: %w", err)
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return publishLocalPaths{}, fmt.Errorf("make source absolute: %w", err)
	}
	source = filepath.Clean(source)
	info, err := os.Stat(source)
	if err != nil || !info.IsDir() {
		return publishLocalPaths{}, fmt.Errorf("source is not an existing directory")
	}
	if err := ctx.Err(); err != nil {
		return publishLocalPaths{}, err
	}
	state, err := resolveProspectiveLocalPath(options.StateDir)
	if err != nil {
		return publishLocalPaths{}, fmt.Errorf("resolve state directory: %w", err)
	}
	handoff, err := resolveHandoffPath(options.HandoffOut)
	if err != nil {
		return publishLocalPaths{}, fmt.Errorf("resolve handoff output: %w", err)
	}
	recoveryKey, err := resolvePrivatePath(options.RecoveryKey)
	if err != nil {
		return publishLocalPaths{}, fmt.Errorf("resolve recovery key: %w", err)
	}
	if pathsOverlap(source, state) {
		return publishLocalPaths{}, fmt.Errorf("source and state directory must not contain one another")
	}
	if pathWithin(handoff, source) || pathWithin(handoff, state) {
		return publishLocalPaths{}, fmt.Errorf("handoff output must be outside source and state directory")
	}
	if pathWithin(string(recoveryKey), source) || pathWithin(string(recoveryKey), state) || handoff == string(recoveryKey) {
		return publishLocalPaths{}, fmt.Errorf("recovery key must be outside source and state directory and differ from handoff output")
	}
	if err := preflightHandoffOutput(handoff); err != nil {
		return publishLocalPaths{}, err
	}
	return publishLocalPaths{
		source: source, stateDir: state, handoff: handoff, recoveryKey: string(recoveryKey),
	}, nil
}

type resumeLocalPaths struct {
	stateDir       string
	shareDirectory string
	recoveryKey    string
}

// preflightResumeLocalPaths is deliberately existing-only. A misspelled
// share identity must not create a new state namespace which could obscure a
// recovery mistake.
func preflightResumeLocalPaths(ctx context.Context, options ResumeOptions, shareID string) (resumeLocalPaths, error) {
	if ctx == nil {
		return resumeLocalPaths{}, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return resumeLocalPaths{}, err
	}
	absoluteState, err := filepath.Abs(options.StateDir)
	if err != nil {
		return resumeLocalPaths{}, fmt.Errorf("resolve state directory: %w", err)
	}
	state, err := filepath.EvalSymlinks(absoluteState)
	if err != nil {
		return resumeLocalPaths{}, fmt.Errorf("resolve existing state directory: %w", err)
	}
	state = filepath.Clean(state)
	info, err := os.Lstat(state)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return resumeLocalPaths{}, fmt.Errorf("state directory is not a real existing directory")
	}
	if err := s3disk.ValidatePrivateSecretDirectory(state); err != nil {
		return resumeLocalPaths{}, fmt.Errorf("unsafe state directory: %w", err)
	}
	shareDirectory := filepath.Join(state, shareID)
	if err := ctx.Err(); err != nil {
		return resumeLocalPaths{}, err
	}
	shareInfo, err := os.Lstat(shareDirectory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return resumeLocalPaths{}, ErrPublisherSessionNotFound
		}
		return resumeLocalPaths{}, fmt.Errorf("inspect publisher session directory: %w", err)
	}
	if !shareInfo.IsDir() || shareInfo.Mode()&os.ModeSymlink != 0 {
		return resumeLocalPaths{}, fmt.Errorf("publisher session directory is not a real directory")
	}
	if err := s3disk.ValidatePrivateSecretDirectory(shareDirectory); err != nil {
		return resumeLocalPaths{}, fmt.Errorf("unsafe publisher session directory: %w", err)
	}
	recoveryKey, err := resolvePrivatePath(options.RecoveryKey)
	if err != nil {
		return resumeLocalPaths{}, fmt.Errorf("resolve recovery key: %w", err)
	}
	if pathWithin(string(recoveryKey), state) {
		return resumeLocalPaths{}, fmt.Errorf("recovery key must be outside the state directory")
	}
	return resumeLocalPaths{stateDir: state, shareDirectory: shareDirectory, recoveryKey: string(recoveryKey)}, nil
}

// preflightRecoveredSessionPaths resolves only authenticated paths from the
// sealed session. Resume calls it before any new snapshot or handoff operation;
// exact root-WAL recovery may precede it so a removable source or handoff
// volume cannot prevent an already authorized S3 operation from being settled.
func preflightRecoveredSessionPaths(
	ctx context.Context,
	state publisherSession,
	local resumeLocalPaths,
	requireSource bool,
) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	source := string(state.SourcePath)
	if requireSource {
		resolvedSource, err := filepath.EvalSymlinks(source)
		if err != nil {
			return fmt.Errorf("resolve authenticated source: %w", err)
		}
		resolvedSource, err = filepath.Abs(resolvedSource)
		if err != nil || filepath.Clean(resolvedSource) != source {
			return fmt.Errorf("authenticated source path changed")
		}
		info, err := os.Stat(resolvedSource)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("authenticated source is not an existing directory")
		}
		source = resolvedSource
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	handoff, err := resolveHandoffPath(string(state.HandoffPath))
	if err != nil || handoff != string(state.HandoffPath) {
		return fmt.Errorf("resolve authenticated handoff path")
	}
	if err := s3disk.ValidatePrivateSecretDirectory(filepath.Dir(handoff)); err != nil {
		return fmt.Errorf("unsafe authenticated handoff directory: %w", err)
	}
	if pathsOverlap(source, local.stateDir) || pathWithin(handoff, source) || pathWithin(handoff, local.stateDir) {
		return fmt.Errorf("authenticated local paths overlap")
	}
	if pathWithin(local.recoveryKey, source) || handoff == local.recoveryKey {
		return fmt.Errorf("recovery key collides with authenticated share paths")
	}
	return nil
}

func resolveProspectiveLocalPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(absolute)
	missing := make([]string, 0, 4)
	for {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if len(missing) > 0 && !info.IsDir() {
				return "", fmt.Errorf("nearest existing path is not a directory")
			}
			resolved, resolveErr := filepath.EvalSymlinks(current)
			if resolveErr != nil {
				return "", resolveErr
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(statErr) {
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("no existing ancestor for %q", path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

type mountLocalPaths struct {
	mountpoint string
	stateDir   string
	cacheBase  string
}

func preflightMountLocalPaths(options MountOptions) (mountLocalPaths, error) {
	mountpoint, err := filepath.Abs(options.Mountpoint)
	if err != nil {
		return mountLocalPaths{}, fmt.Errorf("resolve mountpoint: %w", err)
	}
	mountpoint, err = filepath.EvalSymlinks(mountpoint)
	if err != nil {
		return mountLocalPaths{}, fmt.Errorf("resolve mountpoint: %w", err)
	}
	info, err := os.Stat(mountpoint)
	if err != nil || !info.IsDir() {
		return mountLocalPaths{}, fmt.Errorf("mountpoint is not an existing directory")
	}
	stateDir, err := resolveProspectiveLocalPath(options.StateDir)
	if err != nil {
		return mountLocalPaths{}, fmt.Errorf("resolve state directory: %w", err)
	}
	if pathsOverlap(stateDir, mountpoint) {
		return mountLocalPaths{}, fmt.Errorf("state directory and mountpoint must not contain one another")
	}
	resolved := mountLocalPaths{mountpoint: filepath.Clean(mountpoint), stateDir: stateDir}
	if options.CacheDir == "" {
		return resolved, nil
	}
	cacheBase, err := resolveProspectiveLocalPath(options.CacheDir)
	if err != nil {
		return mountLocalPaths{}, fmt.Errorf("resolve cache base: %w", err)
	}
	if pathsOverlap(cacheBase, mountpoint) {
		return mountLocalPaths{}, fmt.Errorf("cache base and mountpoint must not contain one another")
	}
	if pathsOverlap(cacheBase, stateDir) {
		return mountLocalPaths{}, fmt.Errorf("cache base and state directory must not contain one another")
	}
	resolved.cacheBase = cacheBase
	return resolved, nil
}

func s3HTTPClient(tlsCAPEM []byte) (*http.Client, error) {
	if len(tlsCAPEM) == 0 {
		return nil, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(tlsCAPEM) {
		return nil, fmt.Errorf("PEM contains no certificates")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots,
	}}}, nil
}

// canonicalTLSRootCAPEM accepts only a sequence of headerless CERTIFICATE PEM
// blocks separated by ASCII whitespace. AppendCertsFromPEM deliberately skips
// unknown blocks and trailing text, which would let a CA file smuggle private
// keys or unrelated secrets into the sealed session and B's handoff.
func canonicalTLSRootCAPEM(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	remaining := input
	canonical := make([]byte, 0, len(input))
	certificates := 0
	for {
		remaining = bytes.TrimLeft(remaining, " \t\r\n")
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			clear(canonical)
			return nil, fmt.Errorf("PEM must contain only headerless CERTIFICATE blocks")
		}
		const endMarker = "-----END CERTIFICATE-----"
		endOffset := bytes.Index(remaining, []byte(endMarker))
		if endOffset < 0 || bytes.Contains(
			remaining[len("-----BEGIN CERTIFICATE-----"):endOffset],
			[]byte("-----BEGIN "),
		) {
			clear(canonical)
			return nil, fmt.Errorf("PEM must contain only complete CERTIFICATE blocks")
		}
		candidateEnd := endOffset + len(endMarker)
		if candidateEnd < len(remaining) && remaining[candidateEnd] == '\r' {
			candidateEnd++
		}
		if candidateEnd < len(remaining) && remaining[candidateEnd] == '\n' {
			candidateEnd++
		}
		block, rest := pem.Decode(remaining[:candidateEnd])
		if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			clear(canonical)
			return nil, fmt.Errorf("PEM must contain only headerless CERTIFICATE blocks")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			clear(canonical)
			return nil, fmt.Errorf("PEM contains an invalid certificate")
		}
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
		certificates++
		if certificates > presignedshare.MaximumTLSRootCertificates {
			clear(canonical)
			return nil, fmt.Errorf("PEM contains too many certificates")
		}
		remaining = remaining[candidateEnd:]
	}
	if certificates == 0 {
		clear(canonical)
		return nil, fmt.Errorf("PEM contains no certificates")
	}
	return canonical, nil
}

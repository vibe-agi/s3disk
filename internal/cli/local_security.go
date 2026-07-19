package cli

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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

func preflightPublishLocalPaths(options PublishOptions) error {
	source, err := filepath.EvalSymlinks(options.Source)
	if err != nil {
		return fmt.Errorf("resolve source: %w", err)
	}
	info, err := os.Stat(source)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("source is not an existing directory")
	}
	state, err := resolveProspectiveLocalPath(options.StateDir)
	if err != nil {
		return fmt.Errorf("resolve state directory: %w", err)
	}
	handoff, err := resolveHandoffPath(options.HandoffOut)
	if err != nil {
		return fmt.Errorf("resolve handoff output: %w", err)
	}
	if pathsOverlap(source, state) {
		return fmt.Errorf("source and state directory must not contain one another")
	}
	if pathWithin(handoff, source) || pathWithin(handoff, state) {
		return fmt.Errorf("handoff output must be outside source and state directory")
	}
	return preflightHandoffOutput(handoff)
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

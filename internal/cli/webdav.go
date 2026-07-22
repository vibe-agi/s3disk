package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/vibe-agi/s3disk"
	s3webdav "github.com/vibe-agi/s3disk/webdav"
)

const (
	webDAVReadHeaderTimeout = 10 * time.Second
	webDAVIdleTimeout       = 2 * time.Minute
	webDAVShutdownTimeout   = 10 * time.Second
	webDAVMaximumHeaderSize = 64 << 10
)

func runWebDAV(ctx context.Context, options WebDAVOptions) error {
	if ctx == nil {
		return fmt.Errorf("s3disk serve webdav: context is required")
	}
	if err := validateWebDAVOptions(&options); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	localPaths, err := preflightConsumerLocalPaths(options.StateDir, options.CacheDir)
	if err != nil {
		return fmt.Errorf("s3disk serve webdav: local preflight: %w", err)
	}
	share, err := readHandoff(options.HandoffPath)
	if err != nil {
		return err
	}
	runtime, err := prepareConsumerRuntime(ctx, share, localPaths.stateDir, localPaths.cacheBase)
	if err != nil {
		return fmt.Errorf("s3disk serve webdav: %w", err)
	}
	defer runtime.Close()
	handler, err := s3webdav.NewHandler(runtime.consumer)
	if err != nil {
		return err
	}
	initialContext, cancelInitial := context.WithTimeout(ctx, options.PollTimeout)
	result, err := handler.Refresh(initialContext)
	cancelInitial()
	if err != nil {
		return fmt.Errorf("s3disk serve webdav: initial refresh: %w", err)
	}
	if result.Status == s3disk.RefreshNoSnapshot {
		return s3disk.ErrNoSnapshot
	}
	if expiresAt, known := handler.AuthorizationExpiry(); known && !time.Now().Before(expiresAt) {
		return s3webdav.ErrAuthorizationExpired
	}
	listener, err := net.Listen("tcp", options.Listen)
	if err != nil {
		return fmt.Errorf("s3disk serve webdav: listen: %w", err)
	}
	defer listener.Close()
	if err := validateLoopbackListener(listener); err != nil {
		return err
	}
	return serveWebDAV(ctx, listener, handler, options, share.wire.AuthorizationExpiresAt)
}

func validateLoopbackListener(listener net.Listener) error {
	if listener == nil {
		return fmt.Errorf("s3disk serve webdav: listener is required")
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.IP == nil || !address.IP.IsLoopback() {
		return fmt.Errorf("s3disk serve webdav: refusing non-loopback listener %q", listener.Addr())
	}
	return nil
}

func serveWebDAV(
	ctx context.Context,
	listener net.Listener,
	handler *s3webdav.Handler,
	options WebDAVOptions,
	expiresAt time.Time,
) error {
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: webDAVReadHeaderTimeout,
		IdleTimeout:       webDAVIdleTimeout,
		MaxHeaderBytes:    webDAVMaximumHeaderSize,
	}
	if options.ErrorWriter != nil {
		server.ErrorLog = log.New(options.ErrorWriter, "s3disk webdav: ", 0)
	} else {
		server.ErrorLog = log.New(io.Discard, "", 0)
	}
	lifetimeContext, cancelLifetime := context.WithCancel(ctx)
	defer cancelLifetime()
	pollResult := make(chan error, 1)
	go func() {
		pollResult <- pollWebDAV(lifetimeContext, handler, options)
	}()
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	if options.StatusWriter != nil {
		health := handler.Status()
		_, _ = fmt.Fprintf(options.StatusWriter,
			"webdav: url=%q expires_at=%s generation=%d last_refresh_success=%s max_stale=%s read_only=true loopback_only=true authentication=none\n",
			"http://"+listener.Addr().String()+"/", expiresAt.Format(time.RFC3339), health.Generation,
			health.LastRefreshSuccess.Format(time.RFC3339), options.MaxStale)
	}

	var expiryTimer *time.Timer
	var expiry <-chan time.Time
	if !expiresAt.IsZero() {
		expiryTimer = time.NewTimer(time.Until(expiresAt))
		expiry = expiryTimer.C
		defer expiryTimer.Stop()
	}
	var resultErr error
	serverExited := false
	pollExited := false
	select {
	case err := <-serveResult:
		serverExited = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			resultErr = fmt.Errorf("s3disk serve webdav: HTTP server: %w", err)
		}
	case <-ctx.Done():
	case <-expiry:
		resultErr = s3webdav.ErrAuthorizationExpired
	case err := <-pollResult:
		pollExited = true
		if err != nil {
			resultErr = err
		}
	}
	cancelLifetime()
	if !serverExited {
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), webDAVShutdownTimeout)
		shutdownErr := server.Shutdown(shutdownContext)
		cancelShutdown()
		if shutdownErr != nil {
			_ = server.Close()
			if resultErr == nil {
				resultErr = fmt.Errorf("s3disk serve webdav: shutdown: %w", shutdownErr)
			}
		}
		serveErr := <-serveResult
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && resultErr == nil {
			resultErr = fmt.Errorf("s3disk serve webdav: HTTP server: %w", serveErr)
		}
	}
	if serverExited {
		_ = server.Close()
	}
	if !pollExited {
		pollErr := <-pollResult
		if pollErr != nil && resultErr == nil {
			resultErr = pollErr
		}
	}
	return resultErr
}

func pollWebDAV(ctx context.Context, handler *s3webdav.Handler, options WebDAVOptions) error {
	ticker := time.NewTicker(options.PollInterval)
	defer ticker.Stop()
	for {
		var (
			staleDeadline time.Time
			staleTimer    *time.Timer
			stale         <-chan time.Time
		)
		if options.MaxStale > 0 {
			health := handler.Status()
			if health.LastRefreshSuccess.IsZero() {
				return webDAVStaleError(health)
			}
			staleDeadline = health.LastRefreshSuccess.Add(options.MaxStale)
			untilStale := time.Until(staleDeadline)
			if untilStale <= 0 {
				return webDAVStaleError(health)
			}
			staleTimer = time.NewTimer(untilStale)
			stale = staleTimer.C
		}
		select {
		case <-ctx.Done():
			stopWebDAVTimer(staleTimer)
			return nil
		case <-ticker.C:
			stopWebDAVTimer(staleTimer)
		case <-stale:
			return webDAVStaleError(handler.Status())
		}
		attemptDeadline := time.Now().Add(options.PollTimeout)
		if !staleDeadline.IsZero() && staleDeadline.Before(attemptDeadline) {
			attemptDeadline = staleDeadline
		}
		attemptContext, cancelAttempt := context.WithDeadline(ctx, attemptDeadline)
		result, err := handler.Refresh(attemptContext)
		cancelAttempt()
		if err != nil && ctx.Err() == nil {
			health := handler.Status()
			if options.ErrorWriter != nil {
				_, _ = fmt.Fprintf(options.ErrorWriter,
					"s3disk webdav: refresh warning: consecutive_failures=%d last_success=%s error=%v\n",
					health.ConsecutiveRefreshFailures, health.LastRefreshSuccess.Format(time.RFC3339), err)
			}
			if options.MaxStale > 0 && !time.Now().Before(health.LastRefreshSuccess.Add(options.MaxStale)) {
				return webDAVStaleError(health)
			}
			continue
		}
		if err == nil && result.Status == s3disk.RefreshUpdated && options.StatusWriter != nil {
			health := handler.Status()
			_, _ = fmt.Fprintf(options.StatusWriter, "webdav: refreshed generation=%d at=%s\n",
				health.Generation, health.LastRefreshSuccess.Format(time.RFC3339))
		}
	}
}

func webDAVStaleError(health s3webdav.Status) error {
	if health.LastRefreshSuccess.IsZero() {
		return fmt.Errorf("%w: no successful refresh was recorded", s3webdav.ErrRefreshStale)
	}
	return fmt.Errorf("%w: last successful refresh was %s",
		s3webdav.ErrRefreshStale, health.LastRefreshSuccess.Format(time.RFC3339))
}

func stopWebDAVTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

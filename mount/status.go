package mount

import (
	"time"

	"github.com/vibe-agi/s3disk"
)

// DefaultAutoUnmountTimeout bounds the automatic unmount retry loop started
// when the context passed to ReadOnly is canceled or the fixed authorization
// deadline expires. A finite default prevents a permanent local configuration
// error from leaving an unobservable retry goroutine running forever.
const DefaultAutoUnmountTimeout = 30 * time.Second

// Lifecycle describes the local mount process lifecycle. It is independent of
// refresh and reverse-notification health.
type Lifecycle string

const (
	LifecycleRunning    Lifecycle = "running"
	LifecycleStopping   Lifecycle = "stopping"
	LifecycleStopFailed Lifecycle = "stop_failed"
	LifecycleStopped    Lifecycle = "stopped"
)

// InvalidationMode describes how the mount is refreshing kernel cache state.
// A reverse-notification sweep remains advisory: Active does not promise an
// inotify event or prove that every application has reopened a path.
type InvalidationMode string

const (
	InvalidationActive      InvalidationMode = "active"
	InvalidationBackoff     InvalidationMode = "backoff"
	InvalidationTTLFallback InvalidationMode = "ttl_fallback"
)

// AutomaticUnmountReason records which lifetime boundary started automatic
// unmount. Explicit Unmount calls and an externally stopped FUSE server leave
// this value empty.
type AutomaticUnmountReason string

const (
	AutomaticUnmountReasonNone                 AutomaticUnmountReason = ""
	AutomaticUnmountReasonContextDone          AutomaticUnmountReason = "context_done"
	AutomaticUnmountReasonAuthorizationExpired AutomaticUnmountReason = "authorization_expired"
)

// SnapshotIdentity is the immutable part of a snapshot used by mount health.
type SnapshotIdentity struct {
	Generation uint64
	Commit     s3disk.Digest
}

// ComponentStatus records one independently failing mount component. Error is
// a diagnostic string rather than an error interface so Status remains an
// immutable, race-safe value snapshot.
type ComponentStatus struct {
	LastAttempt         time.Time
	LastSuccess         time.Time
	NextRetry           time.Time
	ConsecutiveFailures uint64
	LastError           string
}

// MountStatus is a point-in-time, no-I/O health snapshot. ObservedSnapshot is
// the latest snapshot adopted by the Consumer. NotifiedSnapshot is only the
// latest stable generation for which a complete reverse-notification sweep
// returned successfully; it is not a lookup linearization or IDE watcher
// barrier.
type MountStatus struct {
	Lifecycle Lifecycle
	// AuthorizationExpiresAt is the immutable, earliest authorization expiry
	// observed immediately after the initial refresh. A zero value means the
	// Consumer's ObjectReader did not expose a finite deadline. It is never
	// extended during this mount's lifetime.
	AuthorizationExpiresAt time.Time
	// AutomaticUnmountReason is populated when the ReadOnly context or the
	// authorization deadline starts automatic unmount.
	AutomaticUnmountReason  AutomaticUnmountReason
	ObservedSnapshot        SnapshotIdentity
	NotifiedSnapshot        SnapshotIdentity
	InvalidationMode        InvalidationMode
	Invalidation            ComponentStatus
	Refresh                 ComponentStatus
	Unmount                 ComponentStatus
	Polling                 bool
	InodeIdentitiesUsed     int
	InodeIdentitiesLimit    int
	InodeIdentityBytesUsed  int64
	InodeIdentityBytesLimit int64
}

// Healthy reports whether polling is active, the latest observed snapshot has
// completed a reverse-notification sweep, and no component is degraded. It
// deliberately makes no claim about inotify/VS Code event delivery.
func (status MountStatus) Healthy() bool {
	return status.Lifecycle == LifecycleRunning && status.Polling &&
		status.InvalidationMode == InvalidationActive &&
		status.ObservedSnapshot == status.NotifiedSnapshot &&
		status.Refresh.ConsecutiveFailures == 0 &&
		status.Invalidation.ConsecutiveFailures == 0 &&
		status.Unmount.ConsecutiveFailures == 0
}

// HealthyAt applies a caller-selected refresh-freshness bound to Healthy and
// rejects a status at or after its known authorization expiry.
// maximumRefreshAge must be positive and Refresh.LastSuccess must be present.
// A LastSuccess later than now is considered fresh so a backward local clock
// adjustment does not produce an immediate false alarm. The refresh-age
// boundary is inclusive: a success exactly maximumRefreshAge old remains
// healthy.
//
// HealthyAt is a passive health decision. It does not cancel or distinguish an
// in-flight refresh from a poller waiting for its next attempt.
func (status MountStatus) HealthyAt(now time.Time, maximumRefreshAge time.Duration) bool {
	if !status.Healthy() || maximumRefreshAge <= 0 || status.Refresh.LastSuccess.IsZero() {
		return false
	}
	if !status.AuthorizationExpiresAt.IsZero() && !now.Before(status.AuthorizationExpiresAt) {
		return false
	}
	if status.Refresh.LastSuccess.After(now) {
		return true
	}
	return now.Sub(status.Refresh.LastSuccess) <= maximumRefreshAge
}

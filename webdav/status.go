package webdav

import "time"

// Status describes the latest refresh outcome for health reporting. Times are
// UTC. LastRefreshError is diagnostic text and is cleared by the next
// successful refresh.
type Status struct {
	Generation                 uint64
	LastRefreshAttempt         time.Time
	LastRefreshSuccess         time.Time
	ConsecutiveRefreshFailures uint64
	LastRefreshError           string
}

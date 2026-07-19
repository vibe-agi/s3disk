package s3disk

import (
	"math"
	"testing"
	"time"
)

func TestPollDurationScalingSaturatesInsteadOfWrapping(t *testing.T) {
	t.Parallel()
	if got := scaleDurationSaturated(time.Duration(math.MaxInt64), 2); got != time.Duration(math.MaxInt64) {
		t.Fatalf("overflowing duration scale = %v, want MaxInt64", got)
	}
	if got := scaleDurationSaturated(time.Hour, 0); got != 0 {
		t.Fatalf("zero duration scale = %v", got)
	}
	for range 1000 {
		if got := jitterDuration(time.Duration(math.MaxInt64), 1); got < 0 {
			t.Fatalf("jitter wrapped to negative duration %v", got)
		}
	}
}

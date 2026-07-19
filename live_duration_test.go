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

func TestNextBackoffDuration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		current time.Duration
		maximum time.Duration
		factor  float64
		want    time.Duration
	}{
		{name: "fixed factor", current: 10 * time.Millisecond, maximum: time.Second, factor: 1, want: 10 * time.Millisecond},
		{name: "rounding still advances", current: time.Nanosecond, maximum: time.Second, factor: 1.1, want: 2 * time.Nanosecond},
		{name: "ordinary growth", current: 10 * time.Millisecond, maximum: time.Second, factor: 2, want: 20 * time.Millisecond},
		{name: "caps at maximum", current: 750 * time.Millisecond, maximum: time.Second, factor: 2, want: time.Second},
		{name: "already capped", current: time.Second, maximum: time.Second, factor: 2, want: time.Second},
		{name: "saturated scale caps", current: time.Duration(math.MaxInt64 / 2), maximum: time.Duration(math.MaxInt64), factor: 10, want: time.Duration(math.MaxInt64)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := nextBackoffDuration(test.current, test.maximum, test.factor); got != test.want {
				t.Fatalf("nextBackoffDuration(%v, %v, %v) = %v, want %v", test.current, test.maximum, test.factor, got, test.want)
			}
		})
	}
}

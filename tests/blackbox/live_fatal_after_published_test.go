package s3disk_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

// A permanent, non-self-healing root-publication fault reported by AfterPublished
// (the share root disappeared under a committed anchor, the root forked, or the
// generation space is exhausted) must terminate Watch with that error rather than
// retry it forever. Retrying such a fault can never succeed, silently freezes the
// publication pipeline at the current generation, and hides a trust event; the
// operator needs a loud, terminal signal. Transient faults keep retrying (covered
// by TestPublisherWatchRetriesAfterPublishedForSameGeneration).
func TestPublisherWatchTerminatesOnPermanentAfterPublishedFault(t *testing.T) {
	for _, fatal := range []error{
		s3disk.ErrRollbackDetected,
		s3disk.ErrSplitBrain,
		s3disk.ErrGenerationExhausted,
	} {
		t.Run(fatal.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			repository, err := s3disk.NewRepository(memstore.New(), "watch-fatal-after-published")
			if err != nil {
				t.Fatal(err)
			}
			publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
				DangerouslyAllowUncommissionedRepository: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			source := privateTestDirectory(t)
			writeFile(t, filepath.Join(source, "data"), []byte("payload"))

			reported := make(chan error, 8)
			watchDone := make(chan error, 1)
			go func() {
				watchDone <- publisher.Watch(ctx, source, "main", s3disk.WatchOptions{
					// Small deterministic retry window so a buggy retry loop would
					// visibly spin instead of terminating.
					AfterPublishedRetryInterval:       20 * time.Millisecond,
					AfterPublishedRetryMaxInterval:    20 * time.Millisecond,
					AfterPublishedRetryJitterFraction: -1,
					AfterPublished: func(_ context.Context, _ s3disk.Snapshot) error {
						return fatal
					},
					OnError: func(err error) { reported <- err },
				})
			}()

			select {
			case err := <-watchDone:
				if !errors.Is(err, fatal) {
					t.Fatalf("Watch returned %v, want termination with %v", err, fatal)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("Watch did not terminate on a permanent AfterPublished fault (still retrying %v)", fatal)
			}

			// The fault must still be surfaced through OnError before Watch returns.
			select {
			case err := <-reported:
				if !errors.Is(err, fatal) {
					t.Fatalf("OnError = %v, want %v", err, fatal)
				}
			case <-time.After(time.Second):
				t.Fatalf("permanent AfterPublished fault %v was not reported through OnError", fatal)
			}
		})
	}
}

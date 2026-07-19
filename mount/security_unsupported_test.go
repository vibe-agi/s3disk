//go:build !linux && !darwin && !freebsd

package mount

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
)

func TestUnsupportedReadOnlySharesSecurityDefaults(t *testing.T) {
	t.Parallel()
	consumer := &s3disk.Consumer{}
	if _, err := ReadOnly(context.Background(), consumer, "unused", Options{}); !errors.Is(err, ErrDurableWatermarkRequired) {
		t.Fatalf("ReadOnly error = %v, want ErrDurableWatermarkRequired before platform dispatch", err)
	}
	if _, err := ReadOnly(context.Background(), consumer, "unused", Options{
		DangerouslyAllowMountWithoutDurableWatermark: true,
	}); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("ReadOnly opted-out error = %v, want ErrUnsupportedPlatform", err)
	}
}

func TestUnsupportedReadOnlyValidatesOptionsBeforeSecurityAndPlatformDispatch(t *testing.T) {
	t.Parallel()
	consumer := &s3disk.Consumer{}
	if _, err := ReadOnly(context.Background(), consumer, "unused", Options{AttrTTL: -time.Nanosecond}); err == nil || errors.Is(err, ErrDurableWatermarkRequired) || errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("ReadOnly invalid-options error = %v, want option validation failure", err)
	}
	if _, err := ReadOnly(context.Background(), consumer, "unused", Options{KernelCache: true}); !errors.Is(err, ErrKernelCacheUnsupported) {
		t.Fatalf("ReadOnly KernelCache error = %v, want ErrKernelCacheUnsupported", err)
	}
}

func TestUnsupportedReadOnlyRejectsExpiredAuthorizationWithoutObjectIO(t *testing.T) {
	t.Parallel()
	reader := &unsupportedExpiringReader{expiresAt: time.Now().Add(-time.Minute)}
	repository, err := s3disk.NewReadOnlyRepository(reader, "unsupported-expired")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ReadOnly(context.Background(), consumer, "unused", Options{
		DangerouslyAllowMountWithoutDurableWatermark: true,
	})
	if !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("ReadOnly error = %v, want ErrAuthorizationExpired before platform dispatch", err)
	}
	if reader.gets != 0 {
		t.Fatalf("unsupported expiry validation issued %d object GETs", reader.gets)
	}
	if reader.inspections != 1 {
		t.Fatalf("authorization inspections = %d, want one", reader.inspections)
	}
}

type unsupportedExpiringReader struct {
	expiresAt   time.Time
	gets        int
	inspections int
}

func (reader *unsupportedExpiringReader) Get(
	context.Context,
	string,
	s3disk.GetOptions,
) (s3disk.Object, error) {
	reader.gets++
	return s3disk.Object{}, errors.New("unexpected object GET")
}

func (reader *unsupportedExpiringReader) AuthorizationExpiry() (time.Time, bool) {
	reader.inspections++
	return reader.expiresAt, true
}

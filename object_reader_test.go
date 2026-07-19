package s3disk_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestReadOnlyRepositorySupportsConsumerWithoutWritableCapability(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memstore.New()
	writable, err := s3disk.NewRepository(store, "reader-only-consumer")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(writable, s3disk.PublisherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	payload := []byte("served through Get-only authority")
	if err := os.WriteFile(filepath.Join(source, "file.txt"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}

	reader := &countingObjectReader{reader: store}
	readOnly, err := s3disk.NewReadOnlyRepository(reader, "reader-only-consumer")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(readOnly, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	file, err := consumer.Open(ctx, "file.txt")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if n, err := file.ReadAtContext(ctx, got, 0); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAtContext: n=%d error=%v", n, err)
	} else if n != len(payload) {
		t.Fatalf("ReadAtContext read %d bytes, want %d", n, len(payload))
	}
	if string(got) != string(payload) {
		t.Fatalf("read payload = %q, want %q", got, payload)
	}
	if reader.gets == 0 {
		t.Fatal("Consumer did not use ObjectReader.Get")
	}
}

func TestReadOnlyRepositoryDropsConcreteStoreWriteCapability(t *testing.T) {
	t.Parallel()
	repository, err := s3disk.NewReadOnlyRepository(memstore.New(), "drop-writes")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{}); !errors.Is(err, s3disk.ErrRepositoryReadOnly) {
		t.Fatalf("NewPublisher error = %v, want ErrRepositoryReadOnly", err)
	}
}

func TestReadOnlyRepositoryFullProbeFailsBeforeObjectIO(t *testing.T) {
	t.Parallel()
	reader := &countingObjectReader{reader: memstore.New()}
	repository, err := s3disk.NewReadOnlyRepository(reader, "probe-read-only")
	if err != nil {
		t.Fatal(err)
	}
	report, err := repository.ProbeStoreCompatibility(context.Background())
	if !errors.Is(err, s3disk.ErrRepositoryReadOnly) {
		t.Fatalf("ProbeStoreCompatibility error = %v, want ErrRepositoryReadOnly", err)
	}
	if reader.gets != 0 {
		t.Fatalf("read-only probe issued %d GETs", reader.gets)
	}
	if report.Status != s3disk.StoreCompatibilityConfigurationError || len(report.Checks) != 1 || report.Checks[0].ID != s3disk.StoreCompatibilityCheckConfiguration {
		t.Fatalf("unexpected fail-fast report: %+v", report)
	}
}

func TestNewReadOnlyRepositoryRejectsNilReaders(t *testing.T) {
	t.Parallel()
	if _, err := s3disk.NewReadOnlyRepository(nil, "nil-reader"); err == nil || err.Error() != "s3disk: nil object reader" {
		t.Fatalf("nil reader error = %v", err)
	}
	var reader *countingObjectReader
	if _, err := s3disk.NewReadOnlyRepository(reader, "typed-nil-reader"); err == nil || err.Error() != "s3disk: object reader must not be a typed nil" {
		t.Fatalf("typed-nil reader error = %v", err)
	}
}

func TestAuthorizationExpiryIsForwardedWithoutObjectIO(t *testing.T) {
	t.Parallel()
	expiresAt := time.Now().Add(time.Hour).Round(0)
	reader := &expiringObjectReader{
		countingObjectReader: countingObjectReader{reader: memstore.New()},
		expiresAt:            expiresAt,
		known:                true,
	}
	repository, err := s3disk.NewReadOnlyRepository(reader, "expiring-reader")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, inspect := range map[string]func() (time.Time, bool){
		"repository": repository.AuthorizationExpiry,
		"consumer":   consumer.AuthorizationExpiry,
	} {
		t.Run(name, func(t *testing.T) {
			got, known := inspect()
			if !known || !got.Equal(expiresAt) {
				t.Fatalf("AuthorizationExpiry = (%v, %t), want (%v, true)", got, known, expiresAt)
			}
		})
	}
	if reader.gets != 0 {
		t.Fatalf("AuthorizationExpiry issued %d GETs", reader.gets)
	}
	if reader.inspections != 2 {
		t.Fatalf("AuthorizationExpiry inspections = %d, want 2", reader.inspections)
	}
}

func TestAuthorizationExpiryUnknownForOrdinaryReader(t *testing.T) {
	t.Parallel()
	repository, err := s3disk.NewReadOnlyRepository(&countingObjectReader{reader: memstore.New()}, "non-expiring-reader")
	if err != nil {
		t.Fatal(err)
	}
	if expiresAt, known := repository.AuthorizationExpiry(); known || !expiresAt.IsZero() {
		t.Fatalf("AuthorizationExpiry = (%v, %t), want zero, false", expiresAt, known)
	}
	var nilRepository *s3disk.Repository
	if expiresAt, known := nilRepository.AuthorizationExpiry(); known || !expiresAt.IsZero() {
		t.Fatalf("nil Repository AuthorizationExpiry = (%v, %t), want zero, false", expiresAt, known)
	}
	var nilConsumer *s3disk.Consumer
	if expiresAt, known := nilConsumer.AuthorizationExpiry(); known || !expiresAt.IsZero() {
		t.Fatalf("nil Consumer AuthorizationExpiry = (%v, %t), want zero, false", expiresAt, known)
	}
}

type countingObjectReader struct {
	reader s3disk.ObjectReader
	gets   int
}

func (reader *countingObjectReader) Get(ctx context.Context, key string, options s3disk.GetOptions) (s3disk.Object, error) {
	reader.gets++
	return reader.reader.Get(ctx, key, options)
}

type expiringObjectReader struct {
	countingObjectReader
	expiresAt   time.Time
	known       bool
	inspections int
}

func (reader *expiringObjectReader) AuthorizationExpiry() (time.Time, bool) {
	reader.inspections++
	return reader.expiresAt, reader.known
}

package s3disk_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestConsumerSecurityStatusReportsImmutableConfiguration(t *testing.T) {
	t.Parallel()
	repository, err := s3disk.NewRepository(memstore.New(), "consumer-security-status")
	if err != nil {
		t.Fatal(err)
	}

	plain, err := s3disk.NewConsumer(repository, "plain", s3disk.ConsumerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if status := plain.SecurityStatus(); status.DurableWatermarkConfigured ||
		status.SymlinkPolicy != s3disk.SymlinkRejectExternal || status.ReferenceAuthenticationConfigured {
		t.Fatalf("plain security status = %+v", status)
	}

	repositoryID := s3disk.RepositoryID{1}
	secured, err := s3disk.NewConsumer(repository, "secured", s3disk.ConsumerOptions{
		Watermarks:                              consumerSecurityWatermarks{},
		ReferenceVerifier:                       consumerSecurityVerifier{repositoryID: repositoryID},
		DangerouslyAllowCustomReferenceVerifier: true,
		Symlinks:                                s3disk.SymlinkPreserve,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status := secured.SecurityStatus(); !status.DurableWatermarkConfigured ||
		status.SymlinkPolicy != s3disk.SymlinkPreserve || !status.ReferenceAuthenticationConfigured {
		t.Fatalf("secured security status = %+v", status)
	}
}

func TestNewConsumerRejectsCustomVerifierBeforeCallingIt(t *testing.T) {
	t.Parallel()
	repository, err := s3disk.NewRepository(memstore.New(), "consumer-security-offline-verifier")
	if err != nil {
		t.Fatal(err)
	}
	verifier := &consumerSecurityCountingVerifier{repositoryID: s3disk.RepositoryID{1}}
	options := s3disk.ConsumerOptions{
		Watermarks:        consumerSecurityWatermarks{},
		ReferenceVerifier: verifier,
	}
	if _, err := s3disk.NewConsumer(repository, "main", options); err == nil {
		t.Fatal("NewConsumer accepted a custom verifier without the dangerous opt-out")
	}
	if verifier.calls != 0 {
		t.Fatalf("custom verifier calls = %d, want 0", verifier.calls)
	}

	options.DangerouslyAllowCustomReferenceVerifier = true
	if _, err := s3disk.NewConsumer(repository, "main", options); err != nil {
		t.Fatalf("NewConsumer with dangerous custom-verifier opt-out: %v", err)
	}
	if verifier.calls != 1 {
		t.Fatalf("custom verifier calls = %d, want 1 after opt-out", verifier.calls)
	}
}

func TestNewConsumerRejectsWrapperEmbeddingOfflineVerifier(t *testing.T) {
	t.Parallel()
	repository, err := s3disk.NewRepository(memstore.New(), "consumer-security-embedded-verifier")
	if err != nil {
		t.Fatal(err)
	}
	repositoryID := s3disk.RepositoryID{1}
	builtIn, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{
		"test": make(ed25519.PublicKey, ed25519.PublicKeySize),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := &consumerSecurityEmbeddedVerifier{Ed25519ReferenceVerifier: builtIn}
	if _, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Watermarks:        consumerSecurityWatermarks{},
		ReferenceVerifier: verifier,
	}); err == nil {
		t.Fatal("NewConsumer accepted a wrapper which overrides an embedded offline verifier")
	}
	if verifier.calls != 0 {
		t.Fatalf("embedded verifier calls = %d, want 0", verifier.calls)
	}
}

func TestNilConsumerSecurityStatusIsZero(t *testing.T) {
	t.Parallel()
	var consumer *s3disk.Consumer
	if status := consumer.SecurityStatus(); status != (s3disk.ConsumerSecurityStatus{}) {
		t.Fatalf("nil Consumer status = %+v, want zero value", status)
	}
}

func TestNewConsumerRejectsTypedNilDependencies(t *testing.T) {
	t.Parallel()
	repository, err := s3disk.NewRepository(memstore.New(), "consumer-security-typed-nil")
	if err != nil {
		t.Fatal(err)
	}
	var cache *consumerSecurityPointerCache
	var watermarks *consumerSecurityPointerWatermarks
	var verifier *consumerSecurityPointerVerifier
	for _, test := range []struct {
		name    string
		options s3disk.ConsumerOptions
		want    string
	}{
		{name: "cache", options: s3disk.ConsumerOptions{Cache: cache}, want: "chunk cache must not be a typed nil"},
		{name: "watermark", options: s3disk.ConsumerOptions{Watermarks: watermarks}, want: "watermark store must not be a typed nil"},
		{name: "required watermark", options: s3disk.ConsumerOptions{Watermarks: watermarks, RequirePersistentWatermark: true}, want: "watermark store must not be a typed nil"},
		{name: "verifier", options: s3disk.ConsumerOptions{ReferenceVerifier: verifier, Watermarks: consumerSecurityWatermarks{}}, want: "reference verifier must not be a typed nil"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := s3disk.NewConsumer(repository, "main", test.options); err == nil {
				t.Fatal("NewConsumer accepted a typed-nil dependency")
			} else if err.Error() != "s3disk: "+test.want {
				t.Fatalf("NewConsumer error = %q, want %q", err, "s3disk: "+test.want)
			}
		})
	}
}

type consumerSecurityPointerCache struct{}

func (*consumerSecurityPointerCache) Get(context.Context, s3disk.Digest) ([]byte, bool, error) {
	return nil, false, nil
}

func (*consumerSecurityPointerCache) Put(context.Context, s3disk.Digest, []byte) error { return nil }

type consumerSecurityWatermarks struct{}

func (consumerSecurityWatermarks) Load(context.Context, string) (s3disk.Watermark, bool, error) {
	return s3disk.Watermark{}, false, nil
}

func (consumerSecurityWatermarks) CompareAndSwap(context.Context, string, *s3disk.Watermark, s3disk.Watermark) error {
	return nil
}

type consumerSecurityPointerWatermarks struct{}

func (*consumerSecurityPointerWatermarks) Load(context.Context, string) (s3disk.Watermark, bool, error) {
	return s3disk.Watermark{}, false, nil
}

func (*consumerSecurityPointerWatermarks) CompareAndSwap(context.Context, string, *s3disk.Watermark, s3disk.Watermark) error {
	return nil
}

type consumerSecurityPointerVerifier struct {
	repositoryID s3disk.RepositoryID
}

func (verifier *consumerSecurityPointerVerifier) RepositoryID() s3disk.RepositoryID {
	return verifier.repositoryID
}

func (*consumerSecurityPointerVerifier) Verify(context.Context, string, []byte, []byte) error {
	return nil
}

type consumerSecurityVerifier struct {
	repositoryID s3disk.RepositoryID
}

func (verifier consumerSecurityVerifier) RepositoryID() s3disk.RepositoryID {
	return verifier.repositoryID
}

func (consumerSecurityVerifier) Verify(context.Context, string, []byte, []byte) error {
	return nil
}

type consumerSecurityCountingVerifier struct {
	repositoryID s3disk.RepositoryID
	calls        int
}

type consumerSecurityEmbeddedVerifier struct {
	*s3disk.Ed25519ReferenceVerifier
	calls int
}

func (verifier *consumerSecurityEmbeddedVerifier) RepositoryID() s3disk.RepositoryID {
	verifier.calls++
	return verifier.Ed25519ReferenceVerifier.RepositoryID()
}

func (verifier *consumerSecurityEmbeddedVerifier) Verify(context.Context, string, []byte, []byte) error {
	verifier.calls++
	return nil
}

func (verifier *consumerSecurityCountingVerifier) RepositoryID() s3disk.RepositoryID {
	verifier.calls++
	return verifier.repositoryID
}

func (*consumerSecurityCountingVerifier) Verify(context.Context, string, []byte, []byte) error {
	return nil
}

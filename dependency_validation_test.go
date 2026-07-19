package s3disk_test

import (
	"context"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestNewRepositoryRejectsTypedNilStore(t *testing.T) {
	t.Parallel()
	var store *typedNilStore
	if _, err := s3disk.NewRepository(store, "typed-nil"); err == nil {
		t.Fatal("NewRepository accepted a typed-nil Store")
	} else if err.Error() != "s3disk: store must not be a typed nil" {
		t.Fatalf("NewRepository error = %q", err)
	}
}

func TestNewPublisherRejectsTypedNilDependencies(t *testing.T) {
	t.Parallel()
	repository, err := s3disk.NewRepository(memstore.New(), "publisher-typed-nil")
	if err != nil {
		t.Fatal(err)
	}
	var signer *typedNilSigner
	var verifier *typedNilVerifier
	var journal *typedNilJournal
	for _, test := range []struct {
		name    string
		options s3disk.PublisherOptions
		want    string
	}{
		{name: "signer", options: s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true, ReferenceSigner: signer}, want: "s3disk: reference signer must not be a typed nil"},
		{name: "verifier", options: s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true, ReferenceVerifier: verifier}, want: "s3disk: reference verifier must not be a typed nil"},
		{name: "journal", options: s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true, PublicationJournal: journal}, want: "s3disk: publication journal must not be a typed nil"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := s3disk.NewPublisher(repository, test.options); err == nil {
				t.Fatal("NewPublisher accepted a typed-nil dependency")
			} else if err.Error() != test.want {
				t.Fatalf("NewPublisher error = %q, want %q", err, test.want)
			}
		})
	}
}

type typedNilStore struct{}

func (*typedNilStore) Get(context.Context, string, s3disk.GetOptions) (s3disk.Object, error) {
	return s3disk.Object{}, nil
}

func (*typedNilStore) Head(context.Context, string) (s3disk.Version, error) {
	return s3disk.Version{}, nil
}

func (*typedNilStore) PutIfAbsent(context.Context, string, []byte) (s3disk.Version, error) {
	return s3disk.Version{}, nil
}

func (*typedNilStore) CompareAndSwap(context.Context, string, *s3disk.Version, []byte) (s3disk.Version, error) {
	return s3disk.Version{}, nil
}

type typedNilSigner struct {
	repositoryID s3disk.RepositoryID
}

func (signer *typedNilSigner) RepositoryID() s3disk.RepositoryID     { return signer.repositoryID }
func (*typedNilSigner) KeyID() string                                { return "key" }
func (*typedNilSigner) Sign(context.Context, []byte) ([]byte, error) { return nil, nil }

type typedNilVerifier struct {
	repositoryID s3disk.RepositoryID
}

func (verifier *typedNilVerifier) RepositoryID() s3disk.RepositoryID {
	return verifier.repositoryID
}

func (*typedNilVerifier) Verify(context.Context, string, []byte, []byte) error { return nil }

type typedNilJournal struct{}

func (*typedNilJournal) Load(context.Context, string) (s3disk.PublicationJournalState, s3disk.PublicationJournalRevision, bool, error) {
	return s3disk.PublicationJournalState{}, s3disk.PublicationJournalRevision{}, false, nil
}

func (*typedNilJournal) CompareAndSwap(context.Context, string, *s3disk.PublicationJournalRevision, s3disk.PublicationJournalState) (s3disk.PublicationJournalRevision, error) {
	return s3disk.PublicationJournalRevision{}, nil
}

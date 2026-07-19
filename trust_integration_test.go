package s3disk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
)

func TestSignedReferencePublishConsumeAndRotateKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repositoryID, oldSigner, newSigner, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "signed")
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	file := filepath.Join(source, "data.txt")
	writeFile(t, file, []byte("one"))
	publicationJournal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	oldPublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          oldSigner, ReferenceVerifier: verifier,
		PublicationJournal: publicationJournal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := oldPublisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, repository.ReferenceKey("main"), s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("signed publisher wrote legacy reference: %v", err)
	}

	newPublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          newSigner, ReferenceVerifier: verifier,
		PublicationJournal: publicationJournal,
	})
	if err != nil {
		t.Fatal(err)
	}
	resigned, err := newPublisher.ResignReference(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if resigned.Generation != first.Generation || resigned.Commit != first.Commit {
		t.Fatalf("resign changed snapshot from %+v to %+v", first, resigned)
	}
	resignedObject, err := store.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(resignedObject.Data, []byte(`"key_id":"online-2026-b"`)) {
		t.Fatalf("resigned reference did not use the new key: %s", resignedObject.Data)
	}

	writeFile(t, file, []byte("two"))
	second, err := newPublisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation != 2 {
		t.Fatalf("rotated generation = %d, want 2", second.Generation)
	}

	checkpoint := s3disk.Watermark{
		RepositoryID: repositoryID, Generation: first.Generation, Commit: first.Commit,
	}
	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(privateTestDirectory(t), "signed.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		ReferenceVerifier: verifier, Watermarks: watermarks, TrustedCheckpoint: &checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 2 {
		t.Fatalf("signed refresh = %+v, %v", result, err)
	}
	if got := string(readFile(t, consumer, "data.txt")); got != "two" {
		t.Fatalf("signed read = %q, want two", got)
	}
}

func TestSignedReferenceRejectsTamperAndContextReplay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repositoryID, signer, _, verifier, publicKeys := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "trusted-a")
	if err != nil {
		t.Fatal(err)
	}
	publicationJournal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: publicationJournal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("authentic"))
	snapshot, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	object, err := store.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := s3disk.Watermark{RepositoryID: repositoryID, Generation: snapshot.Generation, Commit: snapshot.Commit}

	t.Run("signature", func(t *testing.T) {
		var envelope struct {
			Format    int             `json:"format"`
			Reference json.RawMessage `json:"reference"`
			Signature []byte          `json:"signature"`
		}
		if err := json.Unmarshal(object.Data, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.Signature[0] ^= 0x80
		tampered, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		store.ForcePut(repository.SignedReferenceKey("main"), tampered)
		consumer := newSignedConsumer(t, repository, "main", verifier, checkpoint)
		if _, err := consumer.Refresh(ctx); !errors.Is(err, s3disk.ErrUntrustedReference) {
			t.Fatalf("tampered signature error = %v, want ErrUntrustedReference", err)
		}
		if _, ok := consumer.CurrentSnapshot(); ok {
			t.Fatal("consumer exposed a snapshot with a bad signature")
		}
		store.ForcePut(repository.SignedReferenceKey("main"), object.Data)
	})

	t.Run("channel", func(t *testing.T) {
		store.ForcePut(repository.SignedReferenceKey("other"), object.Data)
		consumer := newSignedConsumer(t, repository, "other", verifier, checkpoint)
		if _, err := consumer.Refresh(ctx); !errors.Is(err, s3disk.ErrUntrustedReference) {
			t.Fatalf("cross-channel replay error = %v, want ErrUntrustedReference", err)
		}
	})

	t.Run("repository", func(t *testing.T) {
		otherID, err := s3disk.GenerateRepositoryID()
		if err != nil {
			t.Fatal(err)
		}
		// Keep the same signing public keys but bind the verifier to another
		// repository identity. A copied envelope must still fail.
		otherVerifier, err := s3disk.NewEd25519ReferenceVerifier(otherID, publicKeys)
		if err != nil {
			t.Fatal(err)
		}
		otherRepository, err := s3disk.NewRepository(store, "trusted-b")
		if err != nil {
			t.Fatal(err)
		}
		store.ForcePut(otherRepository.SignedReferenceKey("main"), object.Data)
		otherCheckpoint := checkpoint
		otherCheckpoint.RepositoryID = otherID
		consumer := newSignedConsumer(t, otherRepository, "main", otherVerifier, otherCheckpoint)
		if _, err := consumer.Refresh(ctx); !errors.Is(err, s3disk.ErrUntrustedReference) {
			t.Fatalf("cross-repository replay error = %v, want ErrUntrustedReference", err)
		}
	})
}

func TestSignedConsumerNeverFallsBackAndRequiresBootstrapState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repositoryID, _, _, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "no-downgrade")
	if err != nil {
		t.Fatal(err)
	}
	legacyPublisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{DangerouslyAllowUncommissionedRepository: true})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("legacy"))
	legacy, err := legacyPublisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := s3disk.Watermark{RepositoryID: repositoryID, Generation: legacy.Generation, Commit: legacy.Commit}
	consumer := newSignedConsumer(t, repository, "main", verifier, checkpoint)
	if _, err := consumer.Refresh(ctx); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("signed consumer legacy fallback error = %v, want rollback detection", err)
	}

	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(privateTestDirectory(t), "empty.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	unbootstrapped, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		ReferenceVerifier: verifier, Watermarks: watermarks,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unbootstrapped.Refresh(ctx); !errors.Is(err, s3disk.ErrTrustStateRequired) {
		t.Fatalf("unbootstrapped refresh error = %v, want ErrTrustStateRequired", err)
	}
}

func TestSignedPublisherRequiresDurableStateAndRejectsReferenceReplay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "publisher-replay")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
	}); !errors.Is(err, s3disk.ErrTrustStateRequired) {
		t.Fatalf("signed publisher without durable state error = %v, want ErrTrustStateRequired", err)
	}

	journalPath := filepath.Join(privateTestDirectory(t), "publisher.journal")
	journal, err := s3disk.NewFilePublicationJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	file := filepath.Join(source, "data")
	writeFile(t, file, []byte("one"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	oldReference, err := store.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, []byte("two"))
	second, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	currentReference, err := store.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	store.ForcePut(repository.SignedReferenceKey("main"), oldReference.Data)
	restartedJournal, err := s3disk.NewFilePublicationJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: restartedJournal,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, []byte("attacker branch"))
	if _, err := restarted.Publish(ctx, source, "main"); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("publish from replayed signed reference error = %v, want ErrRollbackDetected", err)
	}

	store.ForcePut(repository.SignedReferenceKey("main"), currentReference.Data)
	writeFile(t, file, []byte("three"))
	third, err := restarted.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	if third.Generation != second.Generation+1 {
		t.Fatalf("recovered generation = %d, want %d", third.Generation, second.Generation+1)
	}
}

func TestSignedConsumerDurableStateRejectsReplayAfterRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repositoryID, signer, _, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "signed-consumer-restart")
	if err != nil {
		t.Fatal(err)
	}
	publicationJournal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: publicationJournal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	file := filepath.Join(source, "data")
	writeFile(t, file, []byte("one"))
	first, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	firstReference, err := store.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, []byte("two"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	currentReference, err := store.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	consumerWatermarkPath := filepath.Join(privateTestDirectory(t), "consumer.watermark")
	consumerWatermarks, err := s3disk.NewFileWatermarkStore(consumerWatermarkPath)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := s3disk.Watermark{RepositoryID: repositoryID, Generation: first.Generation, Commit: first.Commit}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		ReferenceVerifier: verifier, Watermarks: consumerWatermarks, TrustedCheckpoint: &checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := consumer.Refresh(ctx); err != nil || result.Generation != 2 {
		t.Fatalf("initial signed refresh = %+v, %v", result, err)
	}

	store.ForcePut(repository.SignedReferenceKey("main"), firstReference.Data)
	restartedWatermarks, err := s3disk.NewFileWatermarkStore(consumerWatermarkPath)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		ReferenceVerifier: verifier, Watermarks: restartedWatermarks,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Refresh(ctx); !errors.Is(err, s3disk.ErrRollbackDetected) {
		t.Fatalf("restarted signed consumer replay error = %v, want ErrRollbackDetected", err)
	}
	if _, exposed := restarted.CurrentSnapshot(); exposed {
		t.Fatal("restarted signed consumer exposed a replayed snapshot")
	}

	store.ForcePut(repository.SignedReferenceKey("main"), currentReference.Data)
	if result, err := restarted.Refresh(ctx); err != nil || result.Generation != 2 {
		t.Fatalf("signed consumer recovery = %+v, %v", result, err)
	}
}

func TestTrustedCheckpointRejectsHigherDivergentDurableWatermark(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repositoryID, signer, _, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "checkpoint-divergence")
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	file := filepath.Join(source, "data")
	branchAJournal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "branch-a.journal"))
	if err != nil {
		t.Fatal(err)
	}
	branchA, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: branchAJournal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, []byte("common"))
	common, err := branchA.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	commonReference, err := store.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, []byte("branch-a-two"))
	checkpointSnapshot, err := branchA.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := s3disk.Watermark{
		RepositoryID: repositoryID, Generation: checkpointSnapshot.Generation, Commit: checkpointSnapshot.Commit,
	}

	// Restore generation one and create a separately signed, internally valid
	// branch through generations two and three.
	store.ForcePut(repository.SignedReferenceKey("main"), commonReference.Data)
	commonCheckpoint := s3disk.Watermark{
		RepositoryID: repositoryID, Generation: common.Generation, Commit: common.Commit,
	}
	branchBJournal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "branch-b.journal"))
	if err != nil {
		t.Fatal(err)
	}
	branchB, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: branchBJournal, TrustedCheckpoint: &commonCheckpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, []byte("branch-b-two"))
	if _, err := branchB.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, []byte("branch-b-three"))
	divergent, err := branchB.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	divergentWatermark := s3disk.Watermark{
		RepositoryID: repositoryID, Generation: divergent.Generation, Commit: divergent.Commit,
	}

	newDivergentState := func(name string) *s3disk.FileWatermarkStore {
		state, err := s3disk.NewFileWatermarkStore(filepath.Join(privateTestDirectory(t), name))
		if err != nil {
			t.Fatal(err)
		}
		if err := state.CompareAndSwap(ctx, "main", nil, divergentWatermark); err != nil {
			t.Fatal(err)
		}
		return state
	}
	newDivergentJournal := func(name string) *s3disk.FilePublicationJournal {
		journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), name))
		if err != nil {
			t.Fatal(err)
		}
		committed := divergentWatermark
		_, err = journal.CompareAndSwap(ctx, "main", nil, s3disk.PublicationJournalState{
			RepositoryID: repositoryID,
			Channel:      "main",
			Committed:    &committed,
		})
		if err != nil {
			t.Fatal(err)
		}
		return journal
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		ReferenceVerifier: verifier, Watermarks: newDivergentState("consumer.watermark"),
		TrustedCheckpoint: &checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.Refresh(ctx); !errors.Is(err, s3disk.ErrSplitBrain) {
		t.Fatalf("consumer higher divergent watermark error = %v, want ErrSplitBrain", err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: newDivergentJournal("publisher.journal"),
		TrustedCheckpoint:  &checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Stage(ctx, source, "main"); !errors.Is(err, s3disk.ErrSplitBrain) {
		t.Fatalf("publisher higher divergent journal anchor error = %v, want ErrSplitBrain", err)
	}
}

func TestSignedCommitRecoversLostCASResponseAndFinalizesPublisherJournal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repositoryID, signer, _, verifier, _ := signedTestKeys(t)
	base := memstore.New()
	store := &hookedStore{base: base}
	loseResponse := true
	var signedReferenceKey string
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		version, err := base.CompareAndSwap(ctx, key, expected, data)
		if err == nil && loseResponse && key == signedReferenceKey {
			loseResponse = false
			return s3disk.Version{}, errInjectedNetwork
		}
		return version, err
	}
	repository, err := s3disk.NewRepository(store, "signed-lost-cas")
	if err != nil {
		t.Fatal(err)
	}
	signedReferenceKey = repository.SignedReferenceKey("main")
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("signed"))
	snapshot, err := publisher.Publish(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	state, _, found, err := journal.Load(ctx, "main")
	if err != nil || !found {
		t.Fatalf("publisher journal load = %+v, %v, %v", state, found, err)
	}
	want := s3disk.Watermark{RepositoryID: repositoryID, Generation: snapshot.Generation, Commit: snapshot.Commit}
	if state.Committed == nil || *state.Committed != want || state.Pending != nil {
		t.Fatalf("publisher journal = %+v, want committed %+v with no pending intent", state, want)
	}
}

func TestSignedCommitPersistsPendingIntentBeforeRemoteCASAndRecoversAfterRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	base := memstore.New()
	store := &hookedStore{base: base}
	repository, err := s3disk.NewRepository(store, "signed-pre-cas-watermark")
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(privateTestDirectory(t), "publisher.journal")
	journal, err := s3disk.NewFilePublicationJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	file := filepath.Join(source, "data")
	writeFile(t, file, []byte("one"))
	if _, err := publisher.Publish(ctx, source, "main"); err != nil {
		t.Fatal(err)
	}

	writeFile(t, file, []byte("two"))
	staged, err := publisher.Stage(ctx, source, "main")
	if err != nil {
		t.Fatal(err)
	}
	blockReferenceCAS := true
	store.compareAndSwap = func(ctx context.Context, key string, expected *s3disk.Version, data []byte) (s3disk.Version, error) {
		if blockReferenceCAS && key == repository.SignedReferenceKey("main") {
			return s3disk.Version{}, errInjectedNetwork
		}
		return base.CompareAndSwap(ctx, key, expected, data)
	}
	if _, err := publisher.Commit(ctx, staged); !errors.Is(err, s3disk.ErrPublishIndeterminate) {
		t.Fatalf("dropped signed CAS error = %v, want ErrPublishIndeterminate", err)
	}
	state, _, found, err := journal.Load(ctx, "main")
	if err != nil || !found {
		t.Fatalf("pending journal = %+v, found=%v, err=%v", state, found, err)
	}
	if state.Pending == nil || state.Pending.Kind != s3disk.PublicationIntentPublish ||
		state.Pending.Next.Generation != staged.Snapshot.Generation || state.Pending.Next.Commit != staged.Snapshot.Commit {
		t.Fatalf("pending journal = %+v, want exact staged publication %+v", state, staged.Snapshot)
	}
	if state.Committed == nil || state.Committed.Generation+1 != state.Pending.Next.Generation {
		t.Fatalf("pending journal has invalid committed base: %+v", state)
	}
	if state.Pending.IntentID.IsZero() || len(state.Pending.Reference) == 0 {
		t.Fatalf("pending journal did not preserve operation identity and exact signed bytes: %+v", state.Pending)
	}
	pendingIntentID := state.Pending.IntentID
	pendingReference := append([]byte(nil), state.Pending.Reference...)

	// Simulate a process crash after the durable begin but before the S3 CAS.
	// Recovery must replay the exact signed bytes rather than sign a different
	// generation-two branch.
	restartedJournal, err := s3disk.NewFilePublicationJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	unavailableSigner := &unavailableReferenceSigner{delegate: signer}
	restarted, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          unavailableSigner, ReferenceVerifier: verifier,
		PublicationJournal: restartedJournal,
	})
	if err != nil {
		t.Fatal(err)
	}
	blockReferenceCAS = false
	recovery, err := restarted.RecoverPublication(ctx, "main")
	if err != nil {
		t.Fatalf("recover pending publication after restart: %v", err)
	}
	if recovery.Outcome != s3disk.PublicationRecoveryApplied || recovery.IntentID != pendingIntentID ||
		recovery.Current.Generation != staged.Snapshot.Generation || recovery.Current.Commit != staged.Snapshot.Commit {
		t.Fatalf("publication recovery = %+v, want applied intent %s and snapshot %+v", recovery, pendingIntentID, staged.Snapshot)
	}
	if unavailableSigner.calls != 0 {
		t.Fatalf("restart recovery invoked signer %d times, want zero", unavailableSigner.calls)
	}
	visible, err := base.Get(ctx, repository.SignedReferenceKey("main"), s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(visible.Data, pendingReference) {
		t.Fatal("restart recovery did not publish the exact durable reference bytes")
	}
	recovered, _, found, err := restartedJournal.Load(ctx, "main")
	if err != nil || !found || recovered.Pending != nil || recovered.Committed == nil {
		t.Fatalf("recovered journal = %+v, found=%v, err=%v", recovered, found, err)
	}
	if recovered.Committed.Generation != staged.Snapshot.Generation || recovered.Committed.Commit != staged.Snapshot.Commit {
		t.Fatalf("recovered committed watermark = %+v, want staged %+v", recovered.Committed, staged.Snapshot)
	}

	writeFile(t, file, []byte("generation three"))
	continuation, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: restartedJournal,
	})
	if err != nil {
		t.Fatal(err)
	}
	third, err := continuation.Publish(ctx, source, "main")
	if err != nil {
		t.Fatalf("publish after recovery: %v", err)
	}
	if third.Generation != staged.Snapshot.Generation+1 {
		t.Fatalf("generation after recovery = %d, want %d", third.Generation, staged.Snapshot.Generation+1)
	}
}

type unavailableReferenceSigner struct {
	delegate s3disk.ReferenceSigner
	calls    int
}

func (signer *unavailableReferenceSigner) RepositoryID() s3disk.RepositoryID {
	return signer.delegate.RepositoryID()
}

func (signer *unavailableReferenceSigner) KeyID() string { return signer.delegate.KeyID() }

func (signer *unavailableReferenceSigner) Sign(context.Context, []byte) ([]byte, error) {
	signer.calls++
	return nil, errors.New("test: signer unavailable")
}

func TestConcurrentSignedFirstPublishersHaveOneWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "signed-concurrent")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	newPublisher := func() *s3disk.Publisher {
		publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
			DangerouslyAllowUncommissionedRepository: true,
			ReferenceSigner:                          signer, ReferenceVerifier: verifier,
			PublicationJournal: journal, AllowTrustOnFirstUse: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return publisher
	}
	publisherA, publisherB := newPublisher(), newPublisher()
	sourceA, sourceB := privateTestDirectory(t), privateTestDirectory(t)
	writeFile(t, filepath.Join(sourceA, "winner"), []byte("A"))
	writeFile(t, filepath.Join(sourceB, "winner"), []byte("B"))
	stagedA, err := publisherA.Stage(ctx, sourceA, "main")
	if err != nil {
		t.Fatal(err)
	}
	stagedB, err := publisherB.Stage(ctx, sourceB, "main")
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, attempt := range []struct {
		publisher *s3disk.Publisher
		staged    *s3disk.StagedSnapshot
	}{{publisherA, stagedA}, {publisherB, stagedB}} {
		attempt := attempt
		go func() {
			<-start
			_, err := attempt.publisher.Commit(ctx, attempt.staged)
			results <- err
		}()
	}
	close(start)
	firstErr, secondErr := <-results, <-results
	if (firstErr == nil) == (secondErr == nil) {
		t.Fatalf("signed concurrent commit errors = (%v, %v), want exactly one winner", firstErr, secondErr)
	}
	loser := firstErr
	if loser == nil {
		loser = secondErr
	}
	if !errors.Is(loser, s3disk.ErrPublishConflict) {
		t.Fatalf("signed losing commit error = %v, want ErrPublishConflict", loser)
	}
	if state, _, found, err := journal.Load(ctx, "main"); err != nil || !found || state.Committed == nil || state.Pending != nil {
		t.Fatalf("signed winner journal state=%+v found=%v err=%v", state, found, err)
	}
}

func TestSignedPublisherRejectsChannelBeyondObjectKeyLimitBeforeCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, signer, _, verifier, _ := signedTestKeys(t)
	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "signed-reference-limit")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
		ReferenceSigner:                          signer, ReferenceVerifier: verifier,
		PublicationJournal: journal, AllowTrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("value"))
	channel := strings.Repeat("\x01", 1024)
	if _, err := publisher.Publish(ctx, source, channel); !errors.Is(err, s3disk.ErrInvalidPath) {
		t.Fatalf("oversized signed-reference key error = %v, want ErrInvalidPath", err)
	}
	if _, err := store.Get(ctx, repository.SignedReferenceKey(channel), s3disk.GetOptions{}); !errors.Is(err, s3disk.ErrObjectNotFound) {
		t.Fatalf("oversized signed reference became visible: %v", err)
	}
}

func TestResignReferenceRejectsEnvelopeBeyondProtocolLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	shortPublic, shortPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	longPublic, longPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortKeyID := "a"
	longKeyID := strings.Repeat("b", 128)
	shortSigner, err := s3disk.NewEd25519ReferenceSigner(repositoryID, shortKeyID, shortPrivate)
	if err != nil {
		t.Fatal(err)
	}
	longSigner, err := s3disk.NewEd25519ReferenceSigner(repositoryID, longKeyID, longPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, map[string]ed25519.PublicKey{
		shortKeyID: shortPublic,
		longKeyID:  longPublic,
	})
	if err != nil {
		t.Fatal(err)
	}

	store := memstore.New()
	repository, err := s3disk.NewRepository(store, "resign-reference-limit")
	if err != nil {
		t.Fatal(err)
	}
	journal, err := s3disk.NewFilePublicationJournal(filepath.Join(privateTestDirectory(t), "publisher.journal"))
	if err != nil {
		t.Fatal(err)
	}
	newPublisher := func(signer s3disk.ReferenceSigner, tofu bool) *s3disk.Publisher {
		publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
			DangerouslyAllowUncommissionedRepository: true,
			ReferenceSigner:                          signer, ReferenceVerifier: verifier,
			PublicationJournal: journal, AllowTrustOnFirstUse: tofu,
		})
		if err != nil {
			t.Fatal(err)
		}
		return publisher
	}

	// The short-key envelope fits, while changing only the key ID makes the
	// replacement exceed the reader's fixed 4 KiB reference limit.
	channel := strings.Repeat("\x01", 605)
	source := privateTestDirectory(t)
	writeFile(t, filepath.Join(source, "data"), []byte("value"))
	if _, err := newPublisher(shortSigner, true).Publish(ctx, source, channel); err != nil {
		t.Fatalf("publish short reference: %v", err)
	}
	key := repository.SignedReferenceKey(channel)
	before, err := store.Get(ctx, key, s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newPublisher(longSigner, false).ResignReference(ctx, channel); !errors.Is(err, s3disk.ErrResourceLimit) {
		t.Fatalf("oversized resign error = %v, want ErrResourceLimit", err)
	}
	after, err := store.Get(ctx, key, s3disk.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.Data, before.Data) || after.Version != before.Version {
		t.Fatal("oversized resign changed the visible reference")
	}
}

func signedTestKeys(t *testing.T) (s3disk.RepositoryID, *s3disk.Ed25519ReferenceSigner, *s3disk.Ed25519ReferenceSigner, *s3disk.Ed25519ReferenceVerifier, map[string]ed25519.PublicKey) {
	t.Helper()
	repositoryID, err := s3disk.GenerateRepositoryID()
	if err != nil {
		t.Fatal(err)
	}
	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldSigner, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "online-2026-a", oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	newSigner, err := s3disk.NewEd25519ReferenceSigner(repositoryID, "online-2026-b", newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	publicKeys := map[string]ed25519.PublicKey{
		"online-2026-a": oldPublic,
		"online-2026-b": newPublic,
	}
	verifier, err := s3disk.NewEd25519ReferenceVerifier(repositoryID, publicKeys)
	if err != nil {
		t.Fatal(err)
	}
	return repositoryID, oldSigner, newSigner, verifier, publicKeys
}

func newSignedConsumer(t *testing.T, repository *s3disk.Repository, channel string, verifier s3disk.ReferenceVerifier, checkpoint s3disk.Watermark) *s3disk.Consumer {
	t.Helper()
	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(privateTestDirectory(t), "trusted.watermark"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, channel, s3disk.ConsumerOptions{
		ReferenceVerifier: verifier, Watermarks: watermarks, TrustedCheckpoint: &checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	return consumer
}

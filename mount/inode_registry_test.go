//go:build linux || darwin || freebsd

package mount

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/vibe-agi/s3disk"
)

func TestInodeIdentityByteBudgetRejectsLongPathBelowCountLimit(t *testing.T) {
	t.Parallel()
	identity := testInodeSnapshotIdentity(1, 1)
	value := strings.Repeat("deep/", 4096)
	requested := inodeIdentityRetainedBytes(value, s3disk.EntryFile)
	registry := newInodeIdentityRegistry(100_000, requested-1)

	_, err := registry.stableAttr(identity, value, s3disk.EntryFile)
	if !errors.Is(err, ErrInodeIdentityLimit) {
		t.Fatalf("stableAttr error = %v, want ErrInodeIdentityLimit", err)
	}
	if err == nil || !strings.Contains(err.Error(), "retained byte budget exceeded") ||
		!strings.Contains(err.Error(), fmt.Sprintf("requested=%d", requested)) {
		t.Fatalf("stableAttr error = %q, want retained-byte diagnostics", err)
	}
	if used, bytes := registry.usage(); used != 0 || bytes != 0 {
		t.Fatalf("usage after rejected long path = (%d, %d), want (0, 0)", used, bytes)
	}
	if registry.next != 2 {
		t.Fatalf("next inode after rejected long path = %d, want 2", registry.next)
	}
}

func TestInodeIdentityRepeatedTupleDoesNotConsumeBytesAgain(t *testing.T) {
	t.Parallel()
	identity := testInodeSnapshotIdentity(1, 1)
	value := "directory/item"
	requested := inodeIdentityRetainedBytes(value, s3disk.EntryFile)
	registry := newInodeIdentityRegistry(8, requested)

	first, err := registry.stableAttr(identity, value, s3disk.EntryFile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.stableAttr(identity, value, s3disk.EntryFile)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("repeated stable identity = %+v, want %+v", second, first)
	}
	if used, bytes := registry.usage(); used != 1 || bytes != requested {
		t.Fatalf("repeated identity usage = (%d, %d), want (1, %d)", used, bytes, requested)
	}
}

func TestInodeIdentityReleaseReclaimsBudgetWithoutReusingNumber(t *testing.T) {
	t.Parallel()
	identity := testInodeSnapshotIdentity(1, 1)
	value := "directory/item"
	requested := inodeIdentityRetainedBytes(value, s3disk.EntryFile)
	registry := newInodeIdentityRegistry(1, requested)

	first, err := registry.stableAttr(identity, value, s3disk.EntryFile)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.release(identity, value, s3disk.EntryFile, first.Ino) {
		t.Fatal("release did not remove the exact first identity")
	}
	if used, bytes, reclaimed := registry.stats(); used != 0 || bytes != 0 || reclaimed != 1 {
		t.Fatalf("released identity stats = (%d, %d, %d), want (0, 0, 1)", used, bytes, reclaimed)
	}
	if registry.identities != nil {
		t.Fatal("empty identity registry retained its map allocation")
	}

	second, err := registry.stableAttr(identity, value, s3disk.EntryFile)
	if err != nil {
		t.Fatal(err)
	}
	if second.Ino <= first.Ino {
		t.Fatalf("reallocated inode = %d, want greater than forgotten inode %d", second.Ino, first.Ino)
	}
	if registry.release(identity, value, s3disk.EntryFile, first.Ino) {
		t.Fatal("late first OnForget removed the second allocation")
	}
	repeated, err := registry.stableAttr(identity, value, s3disk.EntryFile)
	if err != nil {
		t.Fatal(err)
	}
	if repeated != second {
		t.Fatalf("identity after late release = %+v, want %+v", repeated, second)
	}
}

func TestInodeIdentityForgetChurnStaysWithinOneEntryBudget(t *testing.T) {
	t.Parallel()
	identity := testInodeSnapshotIdentity(1, 1)
	const cycles = 10_000
	value := "churned-item"
	requested := inodeIdentityRetainedBytes(value, s3disk.EntryFile)
	registry := newInodeIdentityRegistry(1, requested)

	var previous uint64
	for range cycles {
		attr, err := registry.stableAttr(identity, value, s3disk.EntryFile)
		if err != nil {
			t.Fatal(err)
		}
		if attr.Ino <= previous {
			t.Fatalf("inode sequence advanced from %d to %d", previous, attr.Ino)
		}
		previous = attr.Ino
		if !registry.release(identity, value, s3disk.EntryFile, attr.Ino) {
			t.Fatalf("release inode %d", attr.Ino)
		}
	}
	if used, bytes, reclaimed := registry.stats(); used != 0 || bytes != 0 || reclaimed != cycles {
		t.Fatalf("churn stats = (%d, %d, %d), want (0, 0, %d)", used, bytes, reclaimed, cycles)
	}
}

func TestNodeOnForgetReleasesOwnedInodeIdentity(t *testing.T) {
	t.Parallel()
	identity := testInodeSnapshotIdentity(2, 2)
	registry := newInodeIdentityRegistry(1, DefaultMaxInodeIdentityBytes)
	attr, err := registry.stableAttr(identity, "forgotten", s3disk.EntryFile)
	if err != nil {
		t.Fatal(err)
	}
	forgotten := &node{
		path: "forgotten", entryType: s3disk.EntryFile,
		snapshotBound: true, snapshot: identity,
		inodeIDs: registry, inodeNumber: attr.Ino,
	}
	forgotten.OnForget()
	forgotten.OnForget()
	if used, bytes, reclaimed := registry.stats(); used != 0 || bytes != 0 || reclaimed != 1 {
		t.Fatalf("OnForget stats = (%d, %d, %d), want (0, 0, 1)", used, bytes, reclaimed)
	}
}

func TestInodeIdentityCountBudgetIsDiagnosticAndDoesNotAdvance(t *testing.T) {
	t.Parallel()
	identity := testInodeSnapshotIdentity(1, 1)
	registry := newInodeIdentityRegistry(1, DefaultMaxInodeIdentityBytes)
	first, err := registry.stableAttr(identity, "first", s3disk.EntryFile)
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.stableAttr(identity, "second", s3disk.EntryFile)
	if !errors.Is(err, ErrInodeIdentityLimit) {
		t.Fatalf("stableAttr error = %v, want ErrInodeIdentityLimit", err)
	}
	if !strings.Contains(err.Error(), "identities used=1 limit=1") ||
		!strings.Contains(err.Error(), "retained bytes used=") ||
		!strings.Contains(err.Error(), "requested=") {
		t.Fatalf("stableAttr count-limit error = %q, want count and byte diagnostics", err)
	}
	if registry.next != 3 {
		t.Fatalf("next inode after count rejection = %d, want 3", registry.next)
	}
	repeated, err := registry.stableAttr(identity, "first", s3disk.EntryFile)
	if err != nil {
		t.Fatal(err)
	}
	if repeated != first {
		t.Fatalf("identity after count rejection = %+v, want %+v", repeated, first)
	}
}

func TestInodeIdentitySnapshotAndTypeConsumeSeparateBytes(t *testing.T) {
	t.Parallel()
	firstSnapshot := testInodeSnapshotIdentity(1, 1)
	secondSnapshot := testInodeSnapshotIdentity(2, 2)
	value := "same-path"
	fileBytes := inodeIdentityRetainedBytes(value, s3disk.EntryFile)
	directoryBytes := inodeIdentityRetainedBytes(value, s3disk.EntryDir)
	limit := fileBytes*2 + directoryBytes
	registry := newInodeIdentityRegistry(4, limit)

	var attrs []fs.StableAttr
	for _, tuple := range []struct {
		identity  snapshotIdentity
		entryType s3disk.EntryType
	}{
		{identity: firstSnapshot, entryType: s3disk.EntryFile},
		{identity: secondSnapshot, entryType: s3disk.EntryFile},
		{identity: firstSnapshot, entryType: s3disk.EntryDir},
	} {
		attr, err := registry.stableAttr(tuple.identity, value, tuple.entryType)
		if err != nil {
			t.Fatal(err)
		}
		attrs = append(attrs, attr)
	}
	for left := range attrs {
		for right := left + 1; right < len(attrs); right++ {
			if attrs[left].Ino == attrs[right].Ino {
				t.Fatalf("distinct tuple %d and %d reused inode %d", left, right, attrs[left].Ino)
			}
		}
	}
	if used, bytes := registry.usage(); used != 3 || bytes != limit {
		t.Fatalf("distinct tuple usage = (%d, %d), want (3, %d)", used, bytes, limit)
	}
	if _, err := registry.stableAttr(secondSnapshot, value, s3disk.EntryDir); !errors.Is(err, ErrInodeIdentityLimit) {
		t.Fatalf("stableAttr beyond exact boundary error = %v, want ErrInodeIdentityLimit", err)
	}
	if used, bytes := registry.usage(); used != 3 || bytes != limit {
		t.Fatalf("usage after boundary rejection = (%d, %d), want (3, %d)", used, bytes, limit)
	}
	if registry.next != 5 {
		t.Fatalf("next inode after boundary rejection = %d, want 5", registry.next)
	}
}

func TestInodeIdentityConcurrentAllocationHonorsByteBoundary(t *testing.T) {
	t.Parallel()
	identity := testInodeSnapshotIdentity(1, 1)
	const (
		attempts = 128
		capacity = 32
	)
	perIdentity := inodeIdentityRetainedBytes("p-000", s3disk.EntryFile)
	registry := newInodeIdentityRegistry(attempts, capacity*perIdentity)
	start := make(chan struct{})
	attrs := make([]fs.StableAttr, attempts)
	errs := make([]error, attempts)
	var wait sync.WaitGroup
	for index := range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			attrs[index], errs[index] = registry.stableAttr(
				identity, fmt.Sprintf("p-%03d", index), s3disk.EntryFile,
			)
		}()
	}
	close(start)
	wait.Wait()

	succeeded := make(map[uint64]struct{})
	for index, err := range errs {
		if err == nil {
			if attrs[index].Ino == 0 {
				t.Fatalf("successful allocation %d has zero inode", index)
			}
			succeeded[attrs[index].Ino] = struct{}{}
			continue
		}
		if !errors.Is(err, ErrInodeIdentityLimit) {
			t.Fatalf("allocation %d error = %v, want ErrInodeIdentityLimit", index, err)
		}
	}
	if len(succeeded) != capacity {
		t.Fatalf("successful unique inodes = %d, want %d", len(succeeded), capacity)
	}
	if used, bytes := registry.usage(); used != capacity || bytes != capacity*perIdentity {
		t.Fatalf("concurrent usage = (%d, %d), want (%d, %d)", used, bytes, capacity, capacity*perIdentity)
	}
}

func TestMountStatusReportsInodeIdentityByteUsage(t *testing.T) {
	t.Parallel()
	identity := testInodeSnapshotIdentity(1, 1)
	value := "status-item"
	requested := inodeIdentityRetainedBytes(value, s3disk.EntryFile)
	registry := newInodeIdentityRegistry(9, requested+1)
	first, err := registry.stableAttr(identity, value, s3disk.EntryFile)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.release(identity, value, s3disk.EntryFile, first.Ino) {
		t.Fatal("release first status identity")
	}
	if _, err := registry.stableAttr(identity, value, s3disk.EntryFile); err != nil {
		t.Fatal(err)
	}
	mounted := &Mount{
		inodeIDs: registry,
		status: MountStatus{
			InodeIdentitiesLimit:    9,
			InodeIdentityBytesLimit: requested + 1,
		},
	}
	status := mounted.Status()
	if status.InodeIdentitiesUsed != 1 || status.InodeIdentitiesLimit != 9 ||
		status.InodeIdentitiesReclaimed != 1 || status.InodeIdentityBytesUsed != requested ||
		status.InodeIdentityBytesLimit != requested+1 {
		t.Fatalf("Mount.Status inode budget = %+v", status)
	}
}

func testInodeSnapshotIdentity(generation uint64, marker byte) snapshotIdentity {
	return snapshotIdentity{generation: generation, commit: s3disk.Digest{marker}}
}

# Snapshot, backup, and key-rotation runbook

This document defines the recovery evidence shipped with s3disk and the work a
product operator must still own. The checked-in drills are safe, disposable
reference fixtures. They do not snapshot an operator's real workspace or
configure a production S3 provider.

## Publish an atomic source view

`Publisher` scans the exact directory passed to it. Its stable-read checks
reject many concurrent mutations, but they are not a whole-directory
transaction. For a strict publication, first create an application-consistent
filesystem snapshot, mount it read-only, and pass that mount—not the writable
workspace—to `s3disk`.

The producer must flush or quiesce application state before the snapshot. A
filesystem snapshot makes filesystem blocks atomic; it cannot make an
application's partially written database transaction valid.

The platform drills prove the expected handoff:

```sh
# macOS, unprivileged disposable APFS image plus COW shadow
./scripts/test-source-snapshot-macos.sh

# Linux, root-only disposable loop device plus LVM snapshot
sudo env "PATH=$PATH" ./scripts/test-source-snapshot-linux.sh
```

Both create an isolated volume, write a frozen source, establish the snapshot,
continue changing the live view, and publish from the read-only view. Cleanup
targets only resources allocated by the script.

The macOS drill uses a detached APFS disk image as the atomic checkpoint, then
attaches the base read-only while live writes go to an APFS COW shadow. This is
portable to GitHub's unprivileged macOS runner. A product storing ordinary
directories on another APFS volume must supply and certify its own privileged
snapshot/quiesce integration, or pause writers while creating a stable copy.

The Linux drill freezes an isolated ext4 filesystem briefly, creates an LVM
COW snapshot, unfreezes the producer, and mounts the snapshot `ro,noload`.
Production sizing must account for snapshot COW exhaustion and must abort a
publication if snapshot health is degraded.

## Backup set and consistency point

Stop or fence every publisher for the repository/channel before taking a
logical current-state backup. Preserve, as one recovery set:

- every object under the repository and share-root prefixes, including the
  repository descriptor, mutable signed references, roots, manifests, and
  immutable chunks;
- publisher publication journals, sealed session state, and sealed root WALs;
- consumer watermarks when rollback resistance must survive machine loss;
- the reference trust configuration and trusted checkpoints, delivered outside
  S3;
- recovery keys and reference signing keys in their independently protected
  KMS/HSM/secret backup systems.

Record the repository ID, channel, generation, commit digest, provider
version/retention status, object inventory, and backup checksum in an external,
tamper-evident manifest. Keep recovery keys separate from encrypted state. Test
provider versioning, object lock/retention, replication, lifecycle rules, and
restore permissions with the exact production account.

The automated MinIO drill copies and byte-hashes the full object inventory,
backs up the publisher journal and consumer watermark, deletes the original
objects and local state, restores into a fresh bucket and directory, verifies
the last committed bytes, and successfully publishes the next generation:

```sh
./scripts/test-minio.sh
```

It also proves that a restarted consumer rejects a validly signed older remote
reference below its restored watermark, and that a restore missing an immutable
chunk fails closed. This is mechanism evidence, not certification of AWS S3,
R2, Ceph, or another production provider.

## Restore procedure

1. Fence publishers and readers from the damaged namespace.
2. Verify the external backup manifest and restore every object into a new,
   empty namespace. Do not merge an unverified partial inventory with live
   state.
3. Restore recovery keys through the approved secret channel, then restore the
   sealed root WAL/session state, publication journal, and consumer watermarks
   to private local paths with their original repository/share/channel binding.
4. Open the repository using the original `RepositoryID`, storage profile,
   client-encryption key, and chunking configuration. A descriptor mismatch is
   a hard failure.
5. With publishers still fenced, refresh a new consumer using the approved
   reference verifier and restored watermark. Byte-check a representative
   snapshot closure and require all objects to exist.
6. Reconcile pending publication/root intents. Only then enable one publisher,
   publish a canary next generation, and verify it through a fresh reader.
7. Archive the drill log, inventories, identities, timings, and exceptions.

A coordinated restore of both old S3 state and its matching old local WAL and
watermark is not detectable by the current system. A commercial product that
requires protection against that rollback needs an independently protected
monotonic counter or transparency log and must include it in this procedure.

## Rotate and retire keys

For an Ed25519 reference-signing key:

1. distribute a verifier keyring containing both old and new public keys;
2. switch the publisher to the new signer while retaining the overlap verifier;
3. call `Publisher.ResignReference` and verify the unchanged generation and
   commit under the new key;
4. publish and read a later generation, back up the new journal/trust state,
   then remove the old public key after the complete reader fleet has advanced;
5. verify an old envelope is rejected by the new-only verifier.

For a local recovery key, configure `publisherstate.NewAESGCMKeyring` with the
new protector first and retained old protectors afterward. Load and CAS-rewrite
every sealed record, open it with a new-only keyring, back up the rewritten
state and new key, and only then retire the old key. The required old-only
failure is covered by
`TestFileSealedStateStoreRotatesRecoveryKeyThroughCAS`.

There is currently no certified in-place rotation or migration protocol for a
repository's `strict-share-isolation-v1` client-encryption key. Allocate a new
repository/share and republish instead; do not reinterpret signing-key or local
recovery-key tests as evidence for client-encryption-key rotation.

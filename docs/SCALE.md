# Scale validation

The repository includes a deterministic, opt-in workspace profile for
comparing publication, refresh, concurrent lazy-read time, and retained Go
heap across revisions and platforms:

```sh
./scripts/test-scale.sh
```

The default CI smoke profile uses 2,000 files of 1 KiB, three generations, and
eight concurrent readers. Every generation is read both through the core
Consumer and through an in-process WebDAV server: the WebDAV pass performs
Depth-1 `PROPFIND` for every directory, then concurrent GETs of every file with
byte-for-byte validation. It emits one `S3DISK_SCALE_EVIDENCE=<json>` record,
including `webdav_read_millis`, and GitHub Actions archives that record with the
exact source revision and runner environment. The defaults are deliberately
small enough for every pull request; they are a regression gate, not a
production capacity claim.

The profile is configurable within fail-closed bounds:

```sh
S3DISK_SCALE_FILES=50000 \
S3DISK_SCALE_FILE_BYTES=4096 \
S3DISK_SCALE_GENERATIONS=10 \
S3DISK_SCALE_READERS=32 \
./scripts/test-scale.sh
```

`S3DISK_SCALE_FILES` is bounded at 100,000, file size at 1 MiB, generations at
100, readers at 128, and aggregate source bytes at 512 MiB. These bounds keep a
mistyped CI variable from exhausting a shared worker. A product needing larger
tests should use a separately isolated harness and record machine, filesystem,
S3 provider, network, cache, and FUSE/kernel details.

The checked-in profile uses the deterministic in-memory Store so it isolates
core scan, protocol, and consumer behavior. It does not measure S3 request cost,
gateway consistency, network latency, FUSE notification latency, IDE watcher
delivery, or disk-cache cold-start behavior. Use `scripts/test-minio.sh` for the
pinned S3 adapter path, `scripts/test-mount-linux.sh` for real `/dev/fuse`, and
`scripts/test-mount-macos.sh` for a real macFUSE mount.
Production adoption still requires a workload-specific matrix covering the
actual backend, kernels, directory shapes, change rates, process termination,
restart, and monitoring thresholds.

For a longer bounded churn run:

```sh
./scripts/test-webdav-churn.sh
```

Its defaults are 5,000 files of 4 KiB, 20 generations, and 16 readers. The
`WebDAV sustained churn` workflow runs this profile weekly and also supports a
manual dispatch. This is a sustained regression profile, not a multi-day soak
or real-S3 capacity certification.

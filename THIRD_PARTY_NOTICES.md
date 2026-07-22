# Third-party notices

This inventory covers third-party modules compiled by the supported package
set on Linux, macOS, FreeBSD, or Windows at the versions pinned in `go.mod` and
`go.sum`. The machine-checked source of truth is
[`third_party/modules.txt`](third_party/modules.txt).

All linked Go dependencies use permissive licenses compatible with commercial
distribution, subject to their notice and license-text conditions. Include this
file, `NOTICE`, and the complete files in `third_party/licenses/` in every
applicable source or binary distribution. This inventory is not legal advice.

## Go toolchain and standard library

Compiled Go applications include portions of the Go runtime and standard
library. Their BSD-3-Clause terms and additional patent grant are reproduced in
[`Go-BSD-3-Clause.txt`](third_party/licenses/Go-BSD-3-Clause.txt) and
[`Go-PATENTS.txt`](third_party/licenses/Go-PATENTS.txt). The exact Go version
used for a binary must also be recorded in its release provenance.

## Apache License 2.0

The following modules are licensed under Apache-2.0. The complete common terms
are in [`Apache-2.0.txt`](third_party/licenses/Apache-2.0.txt). Required upstream
notices from AWS SDK for Go and smithy-go are reproduced in [`NOTICE`](NOTICE).
The mousetrap upstream license records: Copyright 2022 Alan Shreve
(@inconshreveable).

| Module | Version |
| --- | --- |
| `github.com/aws/aws-sdk-go-v2` | `v1.43.0` |
| `github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream` | `v1.7.14` |
| `github.com/aws/aws-sdk-go-v2/config` | `v1.32.31` |
| `github.com/aws/aws-sdk-go-v2/credentials` | `v1.19.30` |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` | `v1.18.31` |
| `github.com/aws/aws-sdk-go-v2/internal/configsources` | `v1.4.31` |
| `github.com/aws/aws-sdk-go-v2/internal/endpoints/v2` | `v2.7.31` |
| `github.com/aws/aws-sdk-go-v2/internal/v4a` | `v1.4.32` |
| `github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding` | `v1.13.13` |
| `github.com/aws/aws-sdk-go-v2/service/internal/checksum` | `v1.9.24` |
| `github.com/aws/aws-sdk-go-v2/service/internal/presigned-url` | `v1.13.31` |
| `github.com/aws/aws-sdk-go-v2/service/internal/s3shared` | `v1.19.32` |
| `github.com/aws/aws-sdk-go-v2/service/s3` | `v1.106.0` |
| `github.com/aws/aws-sdk-go-v2/service/signin` | `v1.5.0` |
| `github.com/aws/aws-sdk-go-v2/service/sso` | `v1.33.0` |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc` | `v1.38.0` |
| `github.com/aws/aws-sdk-go-v2/service/sts` | `v1.45.0` |
| `github.com/aws/smithy-go` | `v1.27.4` |
| `github.com/inconshreveable/mousetrap` | `v1.1.0` |
| `github.com/spf13/cobra` | `v1.10.2` |

## BSD 3-Clause

| Module | Version | Complete license |
| --- | --- | --- |
| `github.com/fsnotify/fsnotify` | `v1.10.1` | [`fsnotify-BSD-3-Clause.txt`](third_party/licenses/fsnotify-BSD-3-Clause.txt) |
| `github.com/hanwen/go-fuse/v2` | `v2.11.0` | [`go-fuse-BSD-3-Clause.txt`](third_party/licenses/go-fuse-BSD-3-Clause.txt) |
| `github.com/spf13/pflag` | `v1.0.10` | [`pflag-BSD-3-Clause.txt`](third_party/licenses/pflag-BSD-3-Clause.txt) |
| `golang.org/x/sys` | `v0.47.0` | [`x-sys-BSD-3-Clause.txt`](third_party/licenses/x-sys-BSD-3-Clause.txt) |

The Go project's additional patent grant reproduced in
[`Go-PATENTS.txt`](third_party/licenses/Go-PATENTS.txt) also accompanies
`golang.org/x/sys`. It is intentionally a direct module dependency because the
Windows `FileWatermarkStore` and `FilePublicationJournal` use `LockFileEx` for
cross-process CAS locking.

AWS SDK for Go and smithy-go contain compiled copies of the Go project's
`singleflight` implementation under their Apache-2.0 module trees. Its retained
BSD-3-Clause terms are reproduced in
[`go-singleflight-BSD-3-Clause.txt`](third_party/licenses/go-singleflight-BSD-3-Clause.txt).

## BSD 2-Clause

| Module | Version | Complete license |
| --- | --- | --- |
| `github.com/restic/chunker` | `v0.5.0` | [`restic-chunker-BSD-2-Clause.txt`](third_party/licenses/restic-chunker-BSD-2-Clause.txt) |

## Development and runtime tools not included in the Go deliverable

- The MinIO server image referenced by `testdata/minio.compose.yml` is an
  external AGPL-3.0 integration-test service. It is pulled at test time, is not
  linked into s3disk, and is not part of the product deliverable. Do not copy it
  into a redistributed product image or installer without a separate legal
  review. See the [upstream license notice](https://github.com/minio/minio).
- macFUSE is not contained in this repository or Go module. The macOS FUSE
  adapter uses a runtime installed separately by the user. macFUSE does not
  permit bundling with commercial software, automated download, or automated
  installation without specific prior written permission. See the [official
  macFUSE announcement](https://macfuse.github.io/2021/05/16/macfuse-4.1.2.html).
- The TLA+ tools JAR downloaded by `scripts/check-model.sh` is a development
  verification tool and is not part of the runtime deliverable. If build/test
  tooling is redistributed, audit and include its license separately.

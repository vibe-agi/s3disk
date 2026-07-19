# Contributing to s3disk

Thank you for helping improve s3disk. The project is an engineering preview,
so protocol, security, and compatibility changes require especially careful
review.

## Before opening a change

- Use GitHub Discussions or an issue for a substantial protocol or public API
  change before investing in an implementation.
- Report suspected vulnerabilities through the private process in
  [`SECURITY.md`](SECURITY.md), not through a public issue.
- Do not submit credentials, bearer URLs, customer data, private test fixtures,
  or output copied from a production environment.

## Development

Use the Go version selected by `go.mod` for normal development. Before opening
a pull request, run the checks relevant to the change:

```sh
go test ./...
go test -race ./...
go vet ./...
./scripts/check-project-license.sh
./scripts/check-third-party.sh
./scripts/check-fuzz-wiring.sh
./scripts/check-dco.sh HEAD
./scripts/test-dco.sh
./scripts/test-release-ref.sh
```

Changes to S3 behavior should also run `./scripts/test-minio.sh`. Changes to
the consistency protocol should run `./scripts/check-model.sh`. Changes to the
mount should run `./scripts/test-mount-linux.sh` on Linux with `/dev/fuse`.

Keep changes focused, add tests before or with the implementation, and update
the security and compatibility documentation when a boundary changes. New or
updated dependencies must be reflected in `third_party/modules.txt`,
`THIRD_PARTY_NOTICES.md`, `NOTICE`, and `third_party/licenses/` as applicable.

The runtime architecture has several non-negotiable boundaries:

- after the private initial handoff, S3 is the only runtime medium between A
  and B/C/D;
- B/C/D receive no reusable S3 credentials and mount a read-only view;
- one share has one fixed absolute expiry and cannot be silently renewed;
- ambiguous writes, rollback, incompatible stores, and corrupt state fail
  closed.

## Commit sign-off and license

s3disk is licensed under the Apache License 2.0. Under section 5 of that
license, intentional contributions submitted for inclusion are provided under
the same terms unless explicitly stated otherwise.

Every commit must include a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Add it with `git commit -s`. By signing off, you certify the Developer
Certificate of Origin 1.1 at <https://developercertificate.org/>: you created
the contribution or otherwise have the right to submit it under the project's
license. A sign-off is not a copyright assignment. CI checks every non-merge
commit in a pull request and requires a trailer which exactly matches that
commit's author identity.

# S3 backend commissioning

“S3 compatible” is an API-family description, not a consistency or conditional-
write guarantee. s3disk does not maintain a vendor allowlist. It commissions the
exact endpoint, bucket, prefix, credentials, gateway/proxy path, encryption
mode, and server version that production will use.

## Probe API

```go
report, err := repository.ProbeStoreCompatibilityWithOptions(ctx,
	s3disk.StoreCompatibilityProbeOptions{
		// SHA-256 of the release controller's canonical, non-secret inventory
		// for endpoint, bucket, region, addressing/TLS/proxy/encryption mode,
		// SDK settings, and the non-secret IAM principal identifier.
		DeploymentFingerprint: deploymentFingerprint,
		EvidenceID:             "commissioning-20260718-001",
		ImplementationVersion:  "s3disk-commercial-build+17",
	})
switch report.Status {
case s3disk.StoreCompatibilityPassed:
	// Eligible for the longer failure suite.
case s3disk.StoreCompatibilityIncompatible:
	// At least one Store-contract contradiction was observed.
case s3disk.StoreCompatibilityConfigurationError:
	// Fix bucket, region, endpoint, or addressing configuration, then rerun.
case s3disk.StoreCompatibilityPermissionDenied:
	// Fix commissioning IAM/bucket policy, then rerun.
case s3disk.StoreCompatibilityIndeterminate:
	// Retry only after resolving timeout, throttling, 5xx, or network state.
}
```

The report has a contract version, explicit `single_client_finite_probe` scope,
random probe ID, stable check IDs and redacted reason codes, a concise detail
and remediation hint, the in-process cause chain, and a separate cleanup result.
Its `evidence` object records an RFC 3339 UTC start time, duration in
nanoseconds, a domain-separated SHA-256 of the normalized repository prefix,
and the validated caller identifiers above. `Contenders` records the
concurrency used. `Complete` means all
`RequiredChecks` ran; it does not imply they passed.
`started_at` comes from the probing process's wall clock; it is not an attested
timestamp. The external evidence sealer should add a trusted receipt time when
that distinction matters.
The first public compatibility contract has not been released. Pre-release
refinements, including exact ambiguous-write reconciliation and post-delete
HEAD verification, remain contract version 1; the version changes only after a
released contract needs an incompatible successor.

`DeploymentFingerprint` is optional for API compatibility, but a commercial
commissioning record should supply it as exactly 64 lowercase hexadecimal
characters. The library cannot infer which non-secret fields constitute the
deployment, so the release controller must define one canonical inventory and
hash it consistently. Include the endpoint and bucket, but never access keys,
session tokens, private certificates, raw credentials, or other secrets. If an
authoritative, non-secret principal ID (for example a role ARN) matters to the
certification, include that ID in the controller's inventory. s3disk neither
discovers nor verifies the credential identity or provider/server version.

`EvidenceID` is limited to 128 ASCII bytes, starts with an alphanumeric
character, and then accepts only alphanumerics plus `.`, `_`, `:`, and `-`.
`ImplementationVersion` has the same bound and accepts alphanumerics plus `.`,
`_`, `+`, and `-`. Rejected options produce `configuration_error` before any
Store operation and are not copied into report JSON. `fully_bound` means only
that a repository prefix digest and all three validated caller fields are
present. It does not prove that those declarations are true or unique.

The prefix itself is never serialized. Its domain-separated digest prevents a
report for one prefix from being silently relabeled as another, provided the
consumer recomputes and checks it; it can still reveal a predictable prefix by
dictionary guessing. The pinned byte-level construction is:

```text
SHA-256(
  UTF-8("s3disk:store-compatibility:repository-prefix:v1") || 0x00 ||
  uint64-big-endian(len(normalized-prefix-UTF-8)) ||
  normalized-prefix-UTF-8
)
```

`normalized-prefix` is the exact `Repository` prefix after `NewRepository`
removes leading and trailing `/` bytes; an empty prefix is valid and still has
a nonempty digest. The output is 64 lowercase hexadecimal characters. More
importantly, neither that digest nor
`DeploymentFingerprint` is a signature. A report can be copied, altered, or
fabricated by whoever controls the process. A separate trusted release
controller must verify the expected inventory, recompute the digests, attach
authoritative control-plane facts, and sign or otherwise tamper-evidently seal
the complete report before treating it as commercial release evidence.

`ProbeStoreCompatibility` remains the source-compatible convenience method and
produces an unbound (`fully_bound: false`) report. Both APIs apply a five-minute
active-probe deadline when the caller context has none. An explicit
`TotalTimeout` may select a different active-probe limit and is capped at 30
minutes; an existing earlier context deadline still wins. Context deadlines
can constrain only a `Store` implementation that obeys `ctx` throughout its
request and body processing. Cleanup deliberately receives its own bounded
five-second context
so it can remove attempted keys after the active probe is canceled. The
reported duration includes that cleanup, so total wall time can extend by up to
the cleanup bound (and an invalid Store that ignores context can still hang).
`StoreCompatibilityError` matches `ErrStoreIncompatible` only when the probe
observed an actual semantic contradiction. It continues to unwrap
`ErrStoreMisconfigured`, `ErrAccessDenied`, `ErrRateLimited`,
`ErrStoreUnavailable`, context errors, and provider SDK errors.

The JSON form intentionally omits Go `error` values but retains a stable
`reason`, such as `access_denied`, `deadline_exceeded`, `rate_limited`,
`store_unavailable`, or `semantic_violation`. Preserve the ordinary error chain
separately if HTTP status, provider error code, request ID, or SDK diagnostics
are required for support.

An explicit provider `NotImplemented`/unsupported response is recorded as
`operation_unsupported` with an `incompatible` status. Unknown SDK errors remain
`unknown_operational_error`/`indeterminate` until the adapter can classify them;
they never receive an optimistic pass.

`ProbeID` identifies the random subtree:

```text
<prefix>/.s3disk/v1/probes/<probe-id>/...
```

The probe uses only small objects and never lists the bucket. It attempts to
delete every random key for which a write was attempted when the Store
implements `ObjectDeleter`.
Every delete is followed by `Store.Head`; only `ErrObjectNotFound` confirms that
the current object is absent. A nil no-op delete, an object that remains visible,
or an access, timeout, network, or other uncertain HEAD result is reported as a
cleanup failure. The cleanup report includes a stable redacted `reason`, a
key-free `detail`, and aggregate delete/visibility/verification counters. Its
in-process `Cause` retains provider diagnostics but remains excluded from JSON.
The whole cleanup pass shares one bounded deadline rather than receiving a new
timeout per key.

The presigned probe records a cleanup candidate before each conditional create.
If a create response is lost, it treats the key as owned only when a bounded
credentialed GET returns the exact payload containing the probe's fresh random
nonce. An unreconciled candidate is never deleted: cleanup performs only HEAD,
reports failure and `current_objects_may_remain` when it is still present, and
does not risk deleting a pre-existing collision.

Cleanup failure is an operational warning, not protocol incompatibility. On a
versioned bucket, HEAD normally observes `ErrObjectNotFound` after a current
delete marker is created; that verifies current absence but does not purge the
noncurrent version or the marker. The report therefore keeps
`historical_versions_may_remain` conservative even after verified cleanup.

The probe is write-capable and commissions A's exact publisher data-plane
policy. B/C/D do not have a read-only IAM role: they hold only a fixed root GET
bearer and authenticated exact-key GET bearers, with no `SecretAccessKey` or
signer. Commission that independent anonymous path with
`Store.ProbePresignedGetCompatibilityWithOptions` and the full S3-only lazy-read
integration test below. Do not copy a result obtained through an administrator,
different proxy, or different endpoint path into the production record.

For AWS, set `s3store.Config.ExpectedBucketOwner` to the 12-digit owning account
ID so every GET, HEAD, conditional PUT, and cleanup DELETE fails if endpoint or
bucket resolution reaches another account. New applications should use the AWS
default credential chain or `s3store.CredentialsProvider` for rotation;
`s3store.Config` intentionally contains no static secret-key fields before the
first public API release. `RetryMaxAttempts`
defaults to the SDK-compatible value of three and is constrained to 1–10. A
per-operation deadline also covers response-body reads: zero
`OperationTimeout` selects two minutes, an earlier caller deadline wins, and
30 minutes is the configuration maximum. Retries do not turn an ambiguous
conditional write into a known failure; the probe still performs the exact
read-back reconciliation described below.
The protocol plaintext object maximum remains 64 MiB. The adapter's raw
fallback/PUT ceiling is 64 MiB plus the fixed 52-byte client-encryption envelope
so a valid maximum-size plaintext chunk remains readable when encrypted;
individual encrypted reads use their smaller plaintext reference, metadata, or
exact chunk limit plus the same 52 bytes. There is no pre-release configuration
field that can raise the raw ceiling beyond that envelope-adjusted maximum or
silently lower a valid plaintext protocol limit.

## Presigned GET compatibility

```go
report, err := store.ProbePresignedGetCompatibilityWithOptions(ctx,
	s3store.PresignedGetCompatibilityProbeOptions{
		ObjectKeyPrefix: "private/commissioning/presigned-get",
		TLSRootCAPEM:    commissionedTLSRoots, // required for every HTTPS origin
	})
if err != nil {
	var diagnosis *s3store.PresignedGetCompatibilityError
	if errors.As(err, &diagnosis) {
		log.Printf("presigned check %s: status=%s reason=%s detail=%s",
			diagnosis.CheckID, diagnosis.Status, diagnosis.Reason, diagnosis.Detail)
	}
	return err
}
if !report.Compatible || !report.Complete {
	return errors.New("incomplete presigned GET commissioning")
}
```

This destructive finite probe creates two random exact keys with A's Store and
then exercises B's credential-free HTTP path. The current implementation sets
`RequiredChecks` to 14; the report field and code constants are authoritative
if a future pre-release refinement changes that number. The ordered stable IDs
are:

```text
configuration
probe-object-create
exact-get-presign
anonymous-request-headers
anonymous-initial-get
same-url-replacement-visibility
current-etag-not-modified
stale-etag-current-object
get-bearer-authorization-query-mutation-rejected
unsigned-anonymous-get-put-delete-rejected-unchanged
named-unsigned-header-overrides-confined
exact-key-path-binding
get-bearer-head-mutation-rejected
get-bearer-put-rejected-unchanged
```

Together those checks cover:

- usable exact `GetObject` presigning for both keys, a shorter source control
  from the same frozen signing context, and absence of reusable credential,
  proxy-authorization, or cookie headers;
- anonymous retrieval of complete objects whose ETag and optional Version ID
  match A's exact observations, visibility of a replacement through the same
  fixed URL, bodyless 304 for a current `If-None-Match`, and current bytes for
  a stale one;
- rejection when a valid longer `X-Amz-Expires` value is transplanted into the
  independently readable shorter bearer's otherwise identical signing context;
- public-policy controls after SigV4 authority is removed: unsigned source and
  target GET, source zero-byte and nonce-bearing nonempty PUT, and source DELETE
  must each return 400, 401, or 403 without changing either canary;
- eleven individually named unsigned override headers on the valid source GET:
  `X-HTTP-Method`, `X-HTTP-Method-Override`, `X-Method-Override`,
  `X-Original-Method`, `X-Rewrite-Method`, `X-Forwarded-Uri`,
  `X-Forwarded-Url`, `X-Original-Uri`, `X-Original-Url`, `X-Rewrite-Uri`, and
  `X-Rewrite-Url`. Each request must either return the exact source object or a
  bounded 400/401/403 rejection; it must not route to the target or mutate
  either canary;
- rejection when a live source bearer is changed to the independently proven
  readable target bearer's exact path, followed by exact source and target
  bearer revalidation;
- rejection of one sampled GET-to-HEAD mutation with no sampled object version
  in observable bounded response metadata, bracketed by a live source bearer;
- rejection of zero-byte and nonce-bearing nonempty PUT mutations made with
  the signed GET bearer; and
- full bytes plus ETag/Version ID read-back of both canaries, using the relevant
  credentialed Store reads and correct exact bearers around the negative
  families. A 4xx cannot pass after modifying either sampled object.

The probe builds a new direct transport with a private callback-free resolver;
it does not inherit ambient proxies. It rejects caller proxies, dialers,
alternate protocols, custom round trippers, TLS client certificates, TLS
verification/session callbacks, custom ciphers/curves/ALPN/ECH, secret-key
logging, caller-created certificate pools, and disabled certificate
verification. HTTPS requires bounded PEM roots in `TLSRootCAPEM` by default,
including for public CAs; the probe parses them into its own callback-free pool.
This avoids operating-system trust evaluators that may fetch AIA or revocation
data outside the locked S3 dialer. `DangerouslyAllowSystemTrustStore` is an
explicit interoperability opt-out and adds
`dangerous_system_trust_may_perform_non_s3_network_io` to the report. Redirect
and cookie policy is removed, and inherited context values such as `httptrace`
hooks are stripped from anonymous requests. Response header count, byte bounds,
single ETag, and optional Version ID rules match `presignedshare.Reader`.
A-side cleanup has a separate finite deadline and is reported independently.

A passing result is scoped as `single_endpoint_finite_probe`. With explicit TLS
roots it retains ten default limitations. These include
`future_provider_and_network_states_not_proven` and
`post_expiry_rejection_not_sampled`: waiting out a production share lifetime is
not appropriate inside a bounded commissioning call. It also retains
`other_http_methods_and_transient_side_effects_not_sampled`,
`arbitrary_query_and_historical_version_binding_not_proven`, and
`head_and_bodyless_status_wire_body_not_observable_with_net_http`, plus
`discarded_wire_metadata_and_extra_bytes_not_observable_with_net_http`,
`bucket_public_access_policy_not_fully_proven`,
`put_payload_variants_beyond_named_samples_not_proven`,
`arbitrary_unsigned_header_override_binding_not_proven`, and
`bucket_and_origin_binding_not_sampled`. The expiry-query sample does not prove
that every added query such as `versionId` is bound. The eleven override-header
samples do not prove arbitrary header names or values, and deliberately do not
invent a second host/origin. The zero-byte and nonce-bearing PUTs do not prove
every payload framing or content variant. The unsigned controls do not replace
a full BPA/IAM/public-access audit. Go's HTTP client suppresses response bodies
for HEAD and bodyless statuses such as 304, and its parser discards chunk
extensions and bytes beyond declared framing.
The commissioning probe disables connection reuse for every anonymous request
and refuses declared HEAD bodies, but it cannot inspect bytes or metadata that
`net/http` has discarded. This isolates the probe; it does not change the
runtime Reader or prove raw-wire confidentiality. Commercial provider
certification must therefore use a raw-wire HTTP/1.1 and HTTP/2 harness to rule
out canary bytes in bodyless responses, chunk extensions, and bytes beyond
Content-Length before release. Provider
certification must separately sample service-side denial after expiry and run
the full path with B constructed only from `presignedshare.Reader`, including
same-root updates and lazy chunks. A SigV4 URL can reveal an access-key ID and
temporary session token, but it must never give B the secret key or a reusable
signer. This pass samples only the named expiry-query, unsigned public-policy,
eleven override-header, path, HEAD, and zero/nonempty-PUT controls. Every
observable successful source response is compared against the independent
target canary and vice versa. Rejected responses are read only within a 4 KiB
bound; their bodies, status, bounded headers, and trailers are compared against
both random sampled objects and versions. Canary contents are never placed in
the report. Observable responses are also scanned for authority belonging only
to the other bearer: its complete raw URL, unique `X-Amz-Signature`, unique
capability-header values, and, when that path was absent from the request, its
escaped path/key. Signing values shared by the same frozen session, such as a
common credential/date or session token, are not independently classified as a
cross-bearer leak. This is exact-value sampling, not detection of every encoded
or transformed disclosure.
Informational 1xx or non-identity encoded negative responses are indeterminate
rather than a pass. The inspection detects exact sampled disclosure, but not
arbitrary encoding or transformation of the same data. Full bytes plus
ETag/Version ID credentialed read-backs and bracketing
bearers cover both sampled canaries around the negative families. They detect a
gateway that changes a canary and then reports 4xx, but cannot prove every
other method, header, query, node, unrelated side effect, or a transient
mutate-then-restore sequence safe.

`Compatible` is not, by itself, commercial provider admission. Admission must
fail closed unless all of the following independent evidence exists:

- a raw-wire HTTP/1.1 and HTTP/2 certification result for bodyless responses,
  chunk metadata, framing boundaries, and cross-canary/bearer leakage;
- a separately reviewed `GetObject`-only signing principal restricted to the
  one commissioned bucket/key scope and exact production origin, with no PUT,
  DELETE, LIST, or bucket-administration authority; and
- an archived BPA/IAM/public-access review covering bucket and access-point
  policies, ACLs, gateway/origin rules, and provider equivalents.

The finite probe cannot infer the configured bucket from an opaque endpoint,
prove that writer and signer configurations resolve to the same bucket/origin,
or enumerate the complete public-access policy graph. Its unsigned controls
exercise only the selected origin and two random keys. These facts remain
deployment limitations even when every stable check passes.

## What “incompatible” means

| Check | Required observation | Common reason for failure |
|---|---|---|
| Missing object | GET and HEAD return `ErrObjectNotFound` | Adapter does not normalize provider 404 errors |
| Conditional create | First `If-None-Match:*` succeeds; duplicate fails without changing the object | Header unsupported, stripped, or 409/412 mapped incorrectly |
| Replacement CAS | Current ETag succeeds; stale ETag fails; missing-key `If-Match` cannot create | `If-Match` unsupported/ignored or implemented as read-then-write |
| Version token | Every success returns a nonempty, bounded ETag; VersionID does not strengthen CAS | Adapter assumes ETag is an MD5, rewrites it, or conditions on VersionID |
| Immediate visibility | GET and HEAD after a completed write return the new bytes and ETag | CDN/cache endpoint, eventual replica, or stale gateway |
| Concurrent atomicity | Exactly one contender succeeds and final bytes/ETag equal that winner | Non-atomic HEAD-then-PUT emulation or a losing write applied despite its error |
| Conditional GET | Current ETag gives `ErrNotModified`; old ETag returns current bytes | Conditional header ignored, always-304 adapter, or stale cache |
| Adapter safety | Exact `MaxBytes` succeeds, smaller bound fails, buffers do not alias | Local Store adapter bug rather than cloud behavior |

ETags are opaque comparison tokens. The probe does not require hexadecimal
syntax, a fixed length, lowercase form, or equality to an MD5 digest. AWS notes
that multipart and several server-side encryption modes produce ETags that are
not MD5 digests. The only required property here is that the returned token is
usable for safe single-key conditional replacement.

## Why providers differ

- AWS S3 documents conditional writes with `If-None-Match:*` and `If-Match`,
  including 412 precondition failures and possible 409 conflicts under races.
  s3disk maps only a named `PreconditionFailed` response (or an otherwise
  unambiguous HTTP 412) to `ErrPrecondition`. `ConditionalRequestConflict`,
  `OperationAborted`, and status-only 409 responses are operationally
  ambiguous and map to `ErrStoreUnavailable`; they are not proof that a
  precondition evaluated false. [AWS conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
- Cloudflare R2 and MinIO AIStor currently list conditional headers for
  `PutObject`, but the exact deployed gateway and proxy still need a runtime
  atomicity test. [R2 S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/),
  [MinIO S3 compatibility](https://docs.min.io/aistor/developers/s3-api-compatibility/)
- Google Cloud Storage uses generation preconditions such as
  `x-goog-if-generation-match` for safe writes; standard XML `If-Match` support
  cannot be assumed to provide this library's generic PUT CAS. A future native
  adapter could translate the Store contract to generation tokens.
  [GCS request preconditions](https://cloud.google.com/storage/docs/request-preconditions)
- Ceph RGW, DigitalOcean Spaces, and Backblaze B2 document subsets or
  differences and do not provide enough general documentation to certify every
  deployed version for the required conditional PUT semantics. Runtime evidence
  decides, not the product name. [Ceph RGW object operations](https://docs.ceph.com/en/latest/radosgw/s3/objectops/),
  [DigitalOcean Spaces API](https://docs.digitalocean.com/reference/api/spaces/),
  [Backblaze B2 Put Object](https://www.backblaze.com/apidocs/s3-put-object)
- Alibaba OSS and Tencent COS expose provider-specific overwrite-prevention
  features. Those can support a dedicated adapter but are not evidence for
  generic ETag replacement CAS. [Alibaba S3 compatibility](https://www.alibabacloud.com/help/en/oss/developer-reference/compatibility-with-amazon-s3),
  [Tencent COS Put Object](https://cloud.tencent.com/document/product/436/7749)

Cloudflare also warns that custom-domain cache paths can serve stale objects or
cached 404 responses even though the direct R2 S3 API is strongly consistent.
Always commission the direct authenticated object endpoint, never a CDN URL.
[R2 consistency](https://developers.cloudflare.com/r2/reference/consistency/)

## Limits of a black-box probe

A finite, single-client test can disprove compatibility by finding one bad
history. It cannot prove that independent B/C/D clients routed to other gateway
nodes see the same history, or that every future execution is linearizable under
every network partition, crash, overload, or provider upgrade. A passed report
must therefore be described as a commissioning-probe result, never by itself as
provider certification. Commercial certification also needs repeated
independent-client stress, injected latency and partitions, ambiguous
write-timeout recovery, credential expiry, throttling, lifecycle/replication
policy review, and reruns after any material backend configuration change.

The SDK or an intermediary can also lose a successful conditional-write
response and expose only a later retry's 412. For each isolated probe key,
s3disk therefore reconciles such an ambiguous result with one bounded exact
GET. It treats the operation as applied only when the returned bytes match the
unique attempted payload and the returned version token is valid (and, for a
replacement, differs from the prior ETag). A missing object, inaccessible
reconciliation read, foreign bytes, invalid token, or ETag reuse remains a
failed or indeterminate check. This recovers one observed operation; it is not
evidence that the network was stable or that every ambiguous history is
distinguishable.

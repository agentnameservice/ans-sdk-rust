# Migrating from 0.1 to 0.2

ANS-6 verification introduces breaking model and configuration changes. The
workspace uses linked release versions, so these changes require a minor release
while the SDK is below 1.0.

## Configure badge trust explicitly

`AnsVerifier::new` now takes trusted TL domains:

```rust,no_run
use ans_verify::AnsVerifier;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let verifier = AnsVerifier::new(["transparency.ans.godaddy.com"]).await?;
# Ok(())
# }
```

For custom configuration, call `.trusted_ra_domains(...)` on `AnsVerifier`,
`ServerVerifier`, or `ClientVerifier` builders. Missing or empty allowlists fail
at build time. Choose hosts through deployment configuration; never copy the
trust list from the DNS records being verified.

Badge URLs must use HTTPS, and the HTTP TL client does not follow redirects.
HTTPS on a nondefault port remains supported when the host is trusted. A verifier
configured with `ScittTierPolicy::RequireScitt` and trusted signing keys can be
built without a badge-host allowlist.

## Handle optional event attestations

These existing public fields are now `Option` values because valid revocation
events and server-only registrations can omit them:

| Field | Migration |
| --- | --- |
| `AgentEvent::expires_at` | Handle absent event expiry |
| `Attestations::domain_validation` | Handle events without domain validation |
| `Attestations::identity_cert` | Handle registrations without a legacy identity certificate |
| `Attestations::server_cert` | Handle events without a legacy server certificate |

For certificate matching, prefer `Badge::identity_cert_fingerprints()` and
`Badge::server_cert_fingerprints()`. They handle V1 singular attestations and V2
rotation arrays. Missing certificate evidence never authorizes a peer.

`CertType` and `EventType` now preserve unfamiliar informational labels with
`Other(String)` and no longer implement `Copy`. Clone when ownership is needed.
Certificate-type labels are metadata; authentication compares fingerprints in
the appropriate server or identity array.

Badges can deserialize the defined `BadgeStatus::Unknown` value. Verification
routes it through failure policy; it is never a successful status. Status tokens
continue rejecting `UNKNOWN`, and unrecognized status strings remain errors.

## Use the full caller verification API

Authenticate requests with `verify_caller` or `verify_caller_with_content`.
`verify_proof`, `VerifyProofOptions`, and `ProofResult` are now available only
with the `test-support` feature. The possession-only utility cannot establish
ANS identity and commits replay state without that binding.

Remove `require_content_binding` fields and calls to
`with_required_content_binding()`. Content binding is unconditional, including
empty content. For received bodies, prefer `verify_caller_with_content` so
hashing happens after identity verification.

`PopError::new` and `PopError::with_source` are public so custom replay backends
and content callbacks can report failures. Use
`PopErrorKind::ReplayCacheUnavailable` for replay-service timeouts or transport
errors; verification fails closed and preserves the underlying error.

Verified artifact caches now bind entries to the complete signing-key
configuration, including TL names. Sharing a cache across configurations does
not share their trust decisions. Root-key refresh remains additive; cache
scoping does not introduce an in-band key-retirement protocol.

## Match cache retention to failure policy

When a badge cache is configured with `FailOpenWithCache`, builders require its
effective `hard_ttl` to be at least `max_staleness`. Set both values deliberately:

```rust
use ans_verify::CacheConfig;
use std::time::Duration;

let mut cache = CacheConfig::default();
cache.hard_ttl = Duration::from_secs(3600);
```

`BadgeCache::config()` exposes the effective configuration. Capacity eviction can
still remove entries sooner; `max_staleness` is an acceptance limit, not a
retention guarantee.

HTTP 429 and interrupted response bodies now use outage handling. HTTP 401/403,
404, and complete but malformed responses remain determinate failures and cannot
enable stale-cache fallback.

# ans-verify

Trust verification library for the Agent Name Service (ANS).

See the [0.2 migration guide](../../MIGRATING.md) for ANS-6 model and configuration changes.

## Overview

This crate implements the ANS trust verification flow, combining DNS lookups, transparency log badge retrieval, and certificate fingerprint comparison to verify agent identities.

## Quick Start

```rust
use ans_verify::{AnsVerifier, CertIdentity, CertFingerprint, VerificationOutcome};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = AnsVerifier::builder()
        .trusted_ra_domains(["transparency.ans.godaddy.com"])
        .with_caching()
        .build()
        .await?;

    // Server verification (client-side)
    // After TLS handshake, construct CertIdentity from the server certificate
    let server_cert = CertIdentity::from_der(&cert_der_bytes)?;
    let outcome = verifier.verify_server("agent.example.com", &server_cert).await;
    if outcome.is_success() {
        println!("Server verified");
    }

    // Client verification (server-side mTLS)
    let client_cert = CertIdentity::from_der(&client_cert_der)?;
    let outcome = verifier.verify_client(&client_cert).await;

    Ok(())
}
```

## Verification Flow

### Server Verification

When connecting to an ANS agent server:

1. DNS lookup `_ans-badge.{fqdn}` (fallback: `_ra-badge`) for the transparency log URL
2. Fetch badge from transparency log API
3. Validate badge status (Active, Warning, Deprecated allowed)
4. Compare server certificate fingerprint to badge attestation
5. Compare certificate CN to badge agent host
6. Optional: DANE/TLSA verification

### Client Verification (mTLS)

When accepting mTLS connections from ANS agent clients:

1. Extract FQDN from certificate CN, version from URI SAN
2. DNS lookup by FQDN, match badge to certificate version
3. Compare identity certificate fingerprint to badge attestation
4. Compare ANS name from URI SAN to badge

## Endpoint Discovery

The DNS layer also enumerates an agent's protocol endpoints from its
published discovery records. Two discovery profiles exist (ANS-3 §6):

| Profile | Records | Requirement (ANS-3 §6.1) |
|---|---|---|
| `ANS_TXT` | `_ans.{fqdn}` TXT rows (`v=ans1; version=…; p=…; mode=direct; url=…`) | Opt-in |
| `ANS_DNSAID` | SVCB rows at the bare FQDN with DNS-AID SvcParams (RFC 9460) | Default |

`DnsResolver::lookup_discovery` autodiscovers which profile the agent
publishes: it queries the SVCB rows first and falls back to the `_ans` TXT
rows only when no SVCB records exist. A lookup *error* propagates instead of
falling back, so an outage is never masked as a profile downgrade.

That probe order is an SDK convention — ANS-3 §3.1 orders DNS ahead of the
Transparency Log and does not rank the profiles against each other. SVCB goes
first because `ANS_DNSAID` is the default profile, so the first probe resolves
for an agent on the default and misses only one that opted into `ANS_TXT`
alone. SVCB rows also carry richer endpoint data (`cap`, `cap-sha256`,
`well-known`) where a TXT row carries only a URL. One wrinkle: in the
`["ANS_DNSAID", "ANS_TXT"]` transition union, §6.4 marks the SVCB rows
`Required=false` and the `_ans` TXT rows `Required=true`, so in that case
first-found-wins returns the rows with the weaker required flag. Discovery
records carry no trust weight either way — trust comes from the badge and
certificate fingerprints.

```rust
use ans_verify::{DiscoveryRecord, DnsResolver, HickoryDnsResolver};
use ans_types::Fqdn;

let resolver = HickoryDnsResolver::new().await?;
let fqdn = Fqdn::new("agent.example.com")?;

for record in resolver.get_discovery_records(&fqdn).await? {
    match &record {
        DiscoveryRecord::Svcb(svcb) => {
            // ANS_DNSAID: connection hints + capability locator
            println!(
                "{:?} on port {:?}, metadata: {:?}",
                svcb.protocol(),
                svcb.port(),
                svcb.metadata_url()
            );
        }
        DiscoveryRecord::Txt(txt) => {
            // ANS_TXT: direct endpoint URL
            println!("{:?} at {}", txt.protocol(), txt.url());
        }
        _ => {}
    }
}
```

SVCB rows carry the DNS-AID draft-02 params in the RFC 9460 Private-Use
`keyNNNNN` form: `key65400` (`cap`, the metadata URL), `key65401`
(`cap-sha256`, base64url SHA-256 of the metadata document), `key65402`
(`bap`, the authoritative protocol token), and `key65409` (`well-known`).
The two profiles share the `a2a`/`mcp` protocol tokens but spell HTTP
differently (`x-http` vs `http-api`); `AgentProtocol` normalizes both.

## Configuration

### DNS Presets

```rust
use ans_verify::AnsVerifier;

let verifier = AnsVerifier::builder()
    .trusted_ra_domains(["transparency.ans.godaddy.com"])
    .dns_cloudflare()  // or .dns_google(), .dns_quad9()
    .build()
    .await?;
```

### Failure Policies

| Policy | Behavior |
|---|---|
| `FailClosed` | Reject on any error (default) |
| `FailOpenWithCache` | Allow if a cached badge exists within max staleness |

### DANE/TLSA

```rust
use ans_verify::ServerVerifier;

let verifier = ServerVerifier::builder()
    .trusted_ra_domains(["transparency.ans.godaddy.com"])
    .with_dane_if_present()  // verify TLSA if records exist
    // or .require_dane()    // fail if no TLSA records
    .dane_port(8443)         // custom port (default: 443)
    .build()
    .await?;
```

### Badge Caching

```rust
let verifier = AnsVerifier::builder()
    .trusted_ra_domains(["transparency.ans.godaddy.com"])
    .with_caching()   // enable Moka-based TTL cache
    .build()
    .await?;
```

Configured DANE checks apply to every successful server verification, including badge cache hits, permitted stale-cache fallback, and SCITT verification. Construct `CertIdentity` from the actual certificate DER to support SPKI-based TLSA records; a fingerprint alone can check only `3 0 1`.

### Trusted RA Domains

ANS-6 badge verification requires a trusted-TL host allowlist configured out of band (§4.2). Configure it for every verifier that can use badge verification, including SCITT fallback:

```rust
let verifier = ServerVerifier::builder()
    .trusted_ra_domains(["tlog.example.com", "tlog2.example.com"])
    .build()
    .await?;
```

Missing or empty allowlists fail at build time. Badge URLs discovered via DNS TXT records must use HTTPS and name a configured host; the HTTP client does not follow redirects. HTTPS on a nondefault port remains supported. `RequireScitt` configurations with trusted signing keys can omit badge-host trust.

V2 badges use `serverCerts` and `identityCerts` arrays; verification accepts any matching fingerprint in the relevant array. Identity certificates may be absent for server-only registrations. V1 singular attestations remain readable. In the Rust model, optional `identity_cert`, `server_cert`, `domain_validation`, and `expires_at` fields are `Option`; code accessing these fields directly must handle their absence. Prefer the fingerprint iterators when matching certificates.

## SCITT Verification

Enable with `features = ["scitt"]` for offline-capable verification using signed status tokens and Merkle inclusion receipts from the transparency log.

### SCITT Flow

1. Reject duplicate SCITT headers, then parse `X-SCITT-Receipt` and `X-ANS-Status-Token`
2. Verify the status token: COSE_Sign1 signature, expiry, agent status
3. Match certificate fingerprint against the token's cert array
4. Verify the receipt's COSE_Sign1 signature and Merkle inclusion proof, then bind its full ANS name and agent identifier to the token and its host to the peer
5. Result: `ScittVerified` with tier (`FullScitt` or `StatusTokenVerified`)

Badge fallback is available only when both SCITT headers are absent and the configured `ScittTierPolicy` allows it. Present but invalid evidence rejects, including an expired token or invalid receipt. A valid token without a receipt yields `StatusTokenVerified`, even under `RequireScitt`; require `FullScitt` if your application needs an inclusion receipt. Status-token clock skew is capped at ten minutes.

```rust
use std::sync::Arc;
use ans_verify::{
    AnsVerifier, ScittConfig, ScittHeaders, ScittKeyStore, ScittTierPolicy,
};

let key_store = Arc::new(ScittKeyStore::from_c2sp_keys(&root_keys)?);

let verifier = AnsVerifier::builder()
    .with_caching()
    .trusted_ra_domains(["tlog.example.com"])
    .scitt_config(ScittConfig::new()
        .with_tier_policy(ScittTierPolicy::ScittWithBadgeFallback))
    .scitt_key_store(key_store)
    .build()
    .await?;

let headers = ScittHeaders::from_base64(
    receipt_header.as_deref(),
    status_token_header.as_deref(),
)?;

let outcome = verifier
    .verify_server_with_scitt("agent.example.com", &server_cert, &headers)
    .await;
```

### Agent-Side Header Supply

Use `ScittHeaderSupplier` for agents to maintain fresh SCITT artifacts:

```rust
use ans_verify::{ScittHeaderSupplier, HttpScittClient};

let supplier = ScittHeaderSupplier::new(agent_id, scitt_client, key_store);
let headers = supplier.current_headers().await;
// headers.receipt_base64 → X-SCITT-Receipt
// headers.status_token_base64 → X-ANS-Status-Token
```

### Inspect Live Artifacts

```bash
cargo run -p ans-verify --features scitt --example inspect_scitt -- \
  --tlog https://transparency.ans.godaddy.com \
  --agent-id b8a46f57-5599-4b4d-9a53-0313e5529694
```

### DPoP / Method B (A2A without mTLS)

When TLS is terminated at a proxy, the callee authenticates the caller from three artifacts on the HTTP request: a DPoP proof (`DPoP`), a status token (`X-ANS-Status-Token`), and a SCITT receipt (`X-SCITT-Receipt`). Missing status token is a hard reject. The receipt is required by default; `require_receipt: false` waives only its absence and must be an explicit deployment choice.

```rust
use ans_verify::{
    MemoryReplayCache, Signer, VerifyCallerOptions, attach_identity, verify_caller,
};

// Caller: this request carries no content, so the proof signs the empty digest.
let proof = attach_identity(&signer, "POST", "https://payments.example.com/api/task", None)?;

// Callee — pass the reconstructed request URL, not the proxy's local address
let identity = verify_caller(
    &proof,
    &headers,
    "POST",
    "https://payments.example.com/api/task",
    &key_store,
    &replay,
    VerifyCallerOptions::default().with_trusted_authority("payments.example.com"),
)
.await?;
```

Outbound minting: `Signer` / `attach_identity`. Inbound: `verify_caller` (three-proof bind) or `verify_proof` (possession only). Replay protection: `ReplayCache` / `MemoryReplayCache`.

Every proof must carry a valid `ans_content_digest`, including the empty-content digest when no content is sent (§7.13). Sign content with `attach_identity_with_content` / `Signer::sign_with_content`. On the callee, use `verify_caller_with_content`: its callback runs only after the proof is bound to a live identity. Enforce the body-size limit and read deadline there, hash after transfer-coding removal but before content decoding, and do not act on content until verification returns success. A digest mismatch or body-read error leaves the `jti` unconsumed. Recompression changes the digest; changing chunk framing does not.

The precomputed `content_sha256` option remains available for content already hashed behind an authentication boundary; `None` means empty content. Content binding is unconditional; the obsolete opt-in flags have been removed. Revision `1` is the only supported profile: an absent `ans_profile` selects it, malformed values reject, and unknown revisions reject with `UNSUPPORTED_PROFILE`. Profile selection is deferred by the spec.

Callee hardening: `VerifyCallerOptions::with_trusted_authority` rejects requests for authorities this callee does not answer as (ANS-6 §7.7), and `with_artifact_cache` (`VerifiedArtifactCache`) skips re-verifying a status token or receipt whose exact bytes verified before, while still enforcing token expiry (§4.6). On an unknown signing key, `PopError::is_unknown_key_id()` signals the refresh-and-retry pattern (§9.5) — pair with `RefreshableKeyStore::refresh_if_cooldown_elapsed`.

At the HTTP boundary, reject duplicate `DPoP`, `Authorization`, `X-SCITT-Receipt`, and `X-ANS-Status-Token` headers before selecting a value. Fail startup without a trusted authority source, incorporate the request's actual path in the comparison URL, and keep authorization parameters out of its unsigned query string. Multi-replica deployments must share a replay cache with atomic check-and-store and a deadline. With OAuth, the token validator must also compare `cnf.jkt` to the returned identity's `jkt`; proof verification checks `ath` but does not validate the access token.

A self-contained example runs both sides of the flow in-memory, including replay rejection, the authority allowlist, and the artifact cache:

```bash
cargo run -p ans-verify --features scitt,test-support --example local_dpop
```

Criterion benchmarks cover offline verification (status token, receipt at log sizes up to 2^30 entries, proof minting, and the full caller flow across deployment shapes: cold / artifact-cache warm and hot / no-receipt / parallel across all cores with a shared replay cache):

```bash
cargo bench -p ans-verify --features scitt,test-support
```

## Traits

Implement these traits for custom backends:

### `DnsResolver`

```rust
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn lookup_badge(&self, fqdn: &Fqdn) -> Result<DnsLookupResult<BadgeRecord>, DnsError>;
    async fn lookup_tlsa(&self, fqdn: &Fqdn, port: u16) -> Result<DnsLookupResult<TlsaRecord>, DnsError>;
    // Default methods: get_badge_records(), find_badge_for_version()
}
```

### `TransparencyLogClient`

```rust
#[async_trait]
pub trait TransparencyLogClient: Send + Sync {
    async fn fetch_badge(&self, url: &str) -> Result<Badge, TlogError>;
    async fn fetch_badge_by_id(&self, agent_id: Uuid) -> Result<Badge, TlogError>;
    async fn fetch_audit(&self, agent_id: Uuid, limit: Option<u32>, offset: Option<u32>)
        -> Result<AuditResponse, TlogError>;
}
```

### `ScittClient` (feature = "scitt")

```rust
#[async_trait]
pub trait ScittClient: Send + Sync {
    async fn fetch_receipt(&self, agent_id: Uuid) -> Result<Vec<u8>, ScittError>;
    async fn fetch_status_token(&self, agent_id: Uuid) -> Result<Vec<u8>, ScittError>;
    async fn fetch_root_keys(&self) -> Result<Vec<String>, ScittError>;
}
```

## Testing

Mock implementations are provided behind the `test-support` feature flag:

```toml
[dev-dependencies]
ans-verify = { ..., features = ["test-support"] }
```

```rust
use ans_verify::{MockDnsResolver, MockTransparencyLogClient, SvcbDiscoveryRecord};

let dns = Arc::new(MockDnsResolver::new()
    .with_records("agent.example.com", vec![badge_record])
    .with_svcb_discovery_records(
        "agent.example.com",
        vec![SvcbDiscoveryRecord::new("a2a", 443)],
    ));

let tlog = Arc::new(MockTransparencyLogClient::new()
    .with_badge("https://tlog.example.com/badge", badge));

let verifier = ServerVerifier::builder()
    .trusted_ra_domains(["tlog.example.com"])
    .dns_resolver(dns)
    .tlog_client(tlog)
    .build()
    .await?;
```

## Feature Flags

| Feature | Description |
|---|---|
| `rustls` | Enables `AnsServerCertVerifier` and `AnsClientCertVerifier` for rustls TLS integration |
| `scitt` | Enables SCITT verification and ANS-6 DPoP: `ScittKeyStore`, `verify_status_token`, `verify_receipt`, `ScittHeaderSupplier`, `HttpScittClient`, `Signer`, `verify_caller` |
| `fast-verify` | Uses `ring` for ECDSA P-256 verification (implies `scitt`); the default backend is `p256`. Both are tested in CI. Benchmark on your deployment target |
| `test-support` | Exposes `MockDnsResolver`, `MockTransparencyLogClient`, and `MockScittClient` for use in downstream integration tests |

## License

MIT

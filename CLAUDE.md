# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build all crates
cargo build --workspace

# Build release
cargo build --workspace --release

# Run all tests (includes test-support for mocks)
cargo test --workspace --features ans-verify/test-support,ans-verify/rustls

# Run all tests including SCITT
cargo test --workspace --features ans-verify/test-support,ans-verify/rustls,ans-verify/scitt

# Run tests for specific crate
cargo test -p ans-verify --features test-support
cargo test -p ans-verify --features test-support,scitt  # includes SCITT tests
cargo test -p ans-types
cargo test -p ans-client

# Run single test
cargo test -p ans-verify test_server_verification_success

# Run tests with logging
RUST_LOG=ans_verify=debug cargo test --workspace -- --nocapture

# Run examples
RUST_LOG=ans_verify=debug cargo run -p ans-verify --example verify_server
RUST_LOG=ans_verify=debug cargo run -p ans-verify --example verify_mtls_client

# Run SCITT examples
RUST_LOG=ans_verify=debug cargo run -p ans-verify --features scitt --example verify_server_scitt
RUST_LOG=ans_verify=debug cargo run -p ans-verify --features scitt --example verify_mtls_scitt

# Check formatting and lints
cargo fmt --all -- --check
cargo clippy --workspace --features ans-verify/test-support,ans-verify/rustls,ans-verify/scitt

# Fix formatting automatically
cargo fmt --all

# Fix clippy warnings automatically
cargo clippy --fix --workspace --features ans-verify/test-support,ans-verify/rustls,ans-verify/scitt --allow-dirty
```

## Required Checks

All changes must pass before merging:

```bash
cargo fmt --all -- --check                                                              # Formatting
cargo clippy --workspace --features ans-verify/test-support,ans-verify/rustls,ans-verify/scitt  # No warnings
cargo test --workspace --features ans-verify/test-support,ans-verify/rustls,ans-verify/scitt    # All tests pass
```

## Releasing

Releases are fully automated via [release-please](https://github.com/googleapis/release-please).
No local tooling required — everything happens in CI.

**How it works:**
1. Merge PRs to `main` using [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, etc.)
2. Release-please automatically creates/updates a **Release PR** with version bumps and CHANGELOG
3. When the team merges the Release PR, release-please creates a git tag + GitHub Release
4. The release workflow then runs full CI and publishes to crates.io

**Commit message conventions:**
- `feat: add new verification mode` → bumps minor version, appears under "Features"
- `fix: handle empty DNS response` → bumps patch version, appears under "Bug Fixes"
- `feat!: redesign verifier API` or `BREAKING CHANGE:` footer → bumps major version
- `chore:`, `ci:`, `docs:`, `test:` → no version bump, no changelog entry

**Commit sign-off (required):**
All commits must include a `Signed-off-by` trailer per the [Developer Certificate of Origin](https://developercertificate.org/).
Always commit with `git commit -s` (or add the trailer manually) — unsigned commits must be amended with `git commit --amend -s` before merging.

**What CI does on release (`.github/workflows/release.yml`):**
1. Runs full CI gate (fmt, clippy, test, MSRV, audit, cargo-deny)
2. Dry-run publish check
3. Publishes to crates.io in dependency order: `ans-types` → `ans-verify` + `ans-client`

**Prerequisites:**
- `CARGO_REGISTRY_TOKEN` secret configured in the `crates-io` GitHub environment

## Architecture

### Workspace Structure

This is a Cargo workspace with three crates following a layered dependency model:

```text
ans-types (foundation)
    ↓
ans-verify (depends on ans-types)
ans-client (depends on ans-types)
```

### Crate Responsibilities

**`ans-types`** — Shared domain types with no external dependencies beyond serialization:

- `Fqdn`: Validated FQDN with `ans_badge_name()` / `ra_badge_name()` methods for DNS queries
- `AnsName`: URI format parser (`ans://v1.0.0.agent.example.com`)
- `Version`: Semantic version comparison
- `Badge`, `BadgePayload`, `BadgeStatus`: Transparency log badge structures
- `CertFingerprint`: SHA-256 certificate fingerprint with `matches()` comparison

**`ans-verify`** — Trust verification with DNS and transparency log integration:

- `AnsVerifier`: High-level facade combining server and client verification
- `ServerVerifier`: Client-side TLS verification (verifies server certificates)
- `ClientVerifier`: Server-side mTLS verification (verifies client identity certificates)
- `DnsResolver` trait + `HickoryDnsResolver`: DNS `_ans-badge` / `_ra-badge` TXT record lookup
- `TransparencyLogClient` trait + `HttpTransparencyLogClient`: Badge API client
- `BadgeCache`: TTL-based Moka cache for badge responses
- DANE/TLSA verification via `DanePolicy` and `TlsaRecord`
- SCITT verification (behind `scitt` feature): `ScittConfig`, `ScittKeyStore`, `ScittHeaders`, `ScittHeaderSupplier`

**`ans-client`** — ANS Registry API client for agent registration and management:

- `AnsClient`: HTTP client with builder pattern for API configuration
- `AnsClientBuilder`: Fluent builder supporting JWT and API key auth
- Registration: `register_agent()`, `verify_acme()`, `verify_dns()`
- Discovery: `get_agent()`, `search_agents()`, `resolve_agent()`
- Certificates: `get_server_certificates()`, `get_identity_certificates()`, `submit_*_csr()`
- Revocation: `revoke_agent()` with RFC 5280 reason codes
- Models: Complete API request/response types matching OpenAPI spec

### Verification Flow

Server verification (`verify_server`):

1. Check badge cache by FQDN
2. DNS lookup: `_ans-badge.{fqdn}` TXT record (fallback: `_ra-badge.{fqdn}`) → transparency log URL
3. Fetch badge from transparency log API
4. Validate badge status (`Active`/`Warning`/`Deprecated` allowed)
5. Compare server certificate fingerprint to badge's `attestations.server_cert.fingerprint`
6. Compare certificate CN to badge's `agent.host`
7. Optional: DANE/TLSA verification if policy enabled

Client verification (`verify_client`) for mTLS:

1. Extract FQDN from certificate CN, version from URI SAN (`ans://...`)
2. DNS lookup by FQDN, match badge to certificate version
3. Compare identity certificate fingerprint to badge's `attestations.identity_cert.fingerprint`
4. Compare ANS name from URI SAN to badge's `ans_name`

### SCITT Verification Flow (feature = "scitt")

SCITT-enhanced verification (`verify_server_with_scitt` / `verify_client_with_scitt`):

1. Parse SCITT headers (`X-SCITT-Receipt`, `X-ANS-Status-Token`)
2. If status token present: verify COSE_Sign1 signature, check expiry, validate status
3. Match certificate fingerprint against token's cert array
4. If receipt present: verify Merkle inclusion proof
5. Result is `VerificationOutcome::ScittVerified` with verification tier

Fallback behavior (governed by `ScittTierPolicy`):
- `ScittWithBadgeFallback` (default): SCITT first, badge fallback only if headers absent
- `RequireScitt`: SCITT required, no badge fallback
- `BadgeWithScittEnhancement`: Badge first, SCITT enhances if headers present

Key rules:
- Present headers are final: any SCITT failure (including `TokenExpired`) = REJECT, no badge fallback
- Badge fallback only when SCITT headers are completely absent
- Terminal status (`REVOKED`/`EXPIRED`) = always reject regardless of policy

### Key Traits

All async traits use `#[async_trait]`:

```rust
// DNS resolution - implement for custom resolvers
pub trait DnsResolver: Send + Sync {
    async fn lookup_badge(&self, fqdn: &Fqdn) -> Result<DnsLookupResult<BadgeRecord>, DnsError>;
    async fn find_badge_for_version(&self, fqdn: &Fqdn, version: &Version) -> Result<Option<BadgeRecord>, DnsError>;
    async fn get_tlsa_records(&self, fqdn: &Fqdn, port: u16) -> Result<Vec<TlsaRecord>, DaneError>;
}

// Transparency log client - implement for custom backends
pub trait TransparencyLogClient: Send + Sync {
    async fn fetch_badge(&self, url: &Url) -> Result<Badge, TlogError>;
}
```

### Testing Patterns

Mock implementations are provided behind the `test-support` feature flag:

```rust
use ans_verify::{MockDnsResolver, MockTransparencyLogClient};

let dns = Arc::new(MockDnsResolver::new()
    .with_records("agent.example.com", vec![badge_record])
    .with_tlsa_records("agent.example.com", 443, vec![tlsa_record]));

let tlog = Arc::new(MockTransparencyLogClient::new()
    .with_badge("https://tlog.example.com/badge", badge));

let verifier = ServerVerifier::builder()
    .dns_resolver(dns)
    .tlog_client(tlog)
    .build()
    .await?;
```

Test fixtures use `rstest` for parameterized tests and `test-log` for tracing output.

## Rust Conventions

- MSRV: 1.88
- Edition: 2024
- Error handling: `thiserror` for error definitions, `Result<T, AnsError>` return types
- Async: `tokio` runtime, `async-trait` for trait methods
- Logging: `tracing` with structured fields (`tracing::debug!(fqdn = %fqdn, ...)`)
- HTTP: `reqwest` with `rustls-tls` (no OpenSSL dependency)
- DNS: `hickory-resolver` with DNSSEC support
- Runtime compatibility: must handle real-world DNS records including versionless `_ra-badge` TXT records from legacy deployments

## Domain Terminology

- **Badge**: Registration record from the transparency log containing agent metadata and certificate fingerprints
- **`_ans-badge` record**: DNS TXT record at `_ans-badge.{fqdn}` pointing to badge URL (legacy: `_ra-badge`)
- **ANS Name**: URI format `ans://v{major}.{minor}.{patch}.{fqdn}` in certificate URI SAN
- **Server cert**: Public CA certificate for TLS server identity
- **Identity cert**: ANS Private CA certificate for mTLS client authentication
- **TLSA record**: DANE certificate binding at `_{port}._tcp.{fqdn}`
- **SCITT**: Supply Chain Integrity, Transparency, and Trust — offline verification via receipts and status tokens
- **Receipt**: COSE_Sign1-wrapped Merkle inclusion proof from the transparency log
- **Status Token**: COSE_Sign1-signed current-status claim with certificate fingerprint arrays
- **COSE_Sign1**: CBOR Object Signing (RFC 9052) — used for receipt and status token signatures
- **C2SP key**: Key format `{issuer}+{key_id_hex}+{spki_base64}` for transparency log root keys

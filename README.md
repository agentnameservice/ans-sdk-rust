# ANS Rust Libraries

Rust libraries for the Agent Name Service (ANS) ecosystem.

## Crates

| Crate | Description | Status |
|-------|-------------|--------|
| [`ans-types`](crates/ans-types) | Shared types for ANS (Badge, Fqdn, AnsName, etc.) | Ready |
| [`ans-verify`](crates/ans-verify) | Trust verification library | Ready |
| [`ans-client`](crates/ans-client) | ANS API client for registration | Ready |

## Overview

The ANS architecture uses a dual-certificate model:

| Certificate Type | Issuer | Contains | Purpose |
|-----------------|--------|----------|---------|
| Public Server Certificate | Public CA (e.g., Let's Encrypt) | FQDN in SAN | Server TLS identity |
| Private Identity Certificate | ANS Private CA | FQDN as CN, ANSName as URI SAN | Agent identity for mTLS |

Verification relies on:
- **DNS `_ans-badge` TXT records** pointing to the transparency log (with `_ra-badge` fallback)
- **Transparency Log API** returning badges with status and certificate fingerprints
- **Certificate fingerprint comparison** to ensure the presented certificate matches the registered identity
- **DANE/TLSA records** (optional) for additional certificate binding via DNSSEC
- **SCITT verification** (optional) for offline-capable trust via signed status tokens and Merkle inclusion receipts

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
# For verification
ans-verify = { git = "https://github.com/agentnameservice/ans-sdk-rust" }

# For API client
ans-client = { git = "https://github.com/agentnameservice/ans-sdk-rust" }

# For shared types only
ans-types = { git = "https://github.com/agentnameservice/ans-sdk-rust" }

tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## API Client Quick Start

```rust
use ans_client::{AnsClient, models::*};

#[tokio::main]
async fn main() -> ans_client::Result<()> {
    // Create client with JWT authentication
    let client = AnsClient::builder()
        .base_url("https://api.godaddy.com")
        .jwt("your-jwt-token")
        .build()?;

    // Search for agents
    let mut criteria = SearchCriteria::default();
    criteria.agent_host = Some("example.com".into());
    let results = client.search_agents(&criteria, Some(10), None).await?;

    for agent in results.agents {
        println!("{}: {}", agent.ans_name, agent.agent_display_name);
    }

    Ok(())
}
```

### Registration Flow

```rust
use ans_client::{AnsClient, models::*};

#[tokio::main]
async fn main() -> ans_client::Result<()> {
    let client = AnsClient::builder()
        .base_url("https://api.godaddy.com")
        .jwt("your-jwt-token")
        .build()?;

    // Step 1: Register agent
    let endpoint = AgentEndpoint::new("https://agent.example.com/mcp", Protocol::Mcp)
        .with_transports(vec![Transport::StreamableHttp]);

    let request = AgentRegistrationRequest::new(
        "my-agent",
        "agent.example.com",
        "1.0.0",
        std::fs::read_to_string("agent.example.com/identity_v1.0.0.csr")?,
        vec![endpoint],
    )
    .with_description("My AI agent")
    .with_server_csr_pem(std::fs::read_to_string("agent.example.com/server_v1.0.0.csr")?);

    let pending = client.register_agent(&request).await?;
    println!("Agent ID: {:?}", pending.agent_id);
    println!("Next steps: {:?}", pending.next_steps);

    // Step 2: Configure ACME challenge from pending.challenges
    // ... set up DNS-01 or HTTP-01 challenge ...

    // Step 3: Verify domain ownership
    let agent_id = pending.agent_id.unwrap();
    let status = client.verify_acme(&agent_id).await?;

    // Step 4: Configure DNS records from pending.dns_records
    // ... set up _ans-badge TXT record, etc. ...

    // Step 5: Verify DNS configuration
    let status = client.verify_dns(&agent_id).await?;
    println!("Final status: {:?}", status.status);

    Ok(())
}
```

### Authentication Methods

```rust
// JWT authentication
let client = AnsClient::builder()
    .base_url("https://api.godaddy.com")
    .jwt("your-jwt-token")
    .build()?;

// API key authentication
let client = AnsClient::builder()
    .base_url("https://api.godaddy.com")
    .api_key("your-key", "your-secret")
    .build()?;
```

## Verification Quick Start

### Server Verification (Client verifying Server)

```rust
use ans_verify::{AnsVerifier, CertFingerprint, CertIdentity, VerificationOutcome};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = AnsVerifier::builder()
        .with_caching()
        .build()
        .await?;

    // After TLS handshake, extract server certificate info
    let server_cert = CertIdentity::new(
        Some("agent.example.com".to_string()),
        vec!["agent.example.com".to_string()],
        vec![],
        CertFingerprint::from_der(&cert_der_bytes),
    );

    match verifier.verify_server("agent.example.com", &server_cert).await {
        VerificationOutcome::Verified { badge, .. } => {
            println!("Verified ANS agent: {}", badge.agent_name());
        }
        VerificationOutcome::NotAnsAgent { fqdn } => {
            println!("Not a registered ANS agent: {}", fqdn);
        }
        outcome => {
            println!("Verification failed: {:?}", outcome);
        }
    }

    Ok(())
}
```

### Client Verification (Server verifying mTLS Client)

```rust
use ans_verify::{AnsVerifier, CertFingerprint, CertIdentity, VerificationOutcome};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = AnsVerifier::builder()
        .with_caching()
        .build()
        .await?;

    // After mTLS handshake, extract client certificate info
    // The identity cert must contain URI SAN with ANS name (ans://v1.0.0.agent.example.com)
    let client_cert = CertIdentity::new(
        Some("agent.example.com".to_string()),
        vec!["agent.example.com".to_string()],
        vec!["ans://v1.0.0.agent.example.com".to_string()],
        CertFingerprint::from_der(&cert_der_bytes),
    );

    match verifier.verify_client(&client_cert).await {
        VerificationOutcome::Verified { badge, .. } => {
            println!("Verified ANS agent: {}", badge.agent_name());
            // Process requests from this client
        }
        outcome => {
            println!("Verification failed: {:?}", outcome);
            // Reject connection
        }
    }

    Ok(())
}
```

## SCITT Verification (Optional)

SCITT (Supply Chain Integrity, Transparency, and Trust) provides offline-capable verification using cryptographically signed artifacts from the transparency log. Enable with `features = ["scitt"]`.

### How It Works

| Artifact | Format | Purpose |
|----------|--------|---------|
| **Status Token** | `COSE_Sign1` (CBOR) | Signed claim of current agent status, certificate fingerprints, and expiry |
| **Receipt** | `COSE_Sign1` (CBOR) | Merkle inclusion proof that the agent event is in the transparency log |
| **Root Keys** | C2SP format | ECDSA P-256 public keys for verifying token/receipt signatures |

### SCITT-Enhanced Server Verification

```rust
use std::sync::Arc;
use ans_verify::{
    AnsVerifier, CertFingerprint, CertIdentity, ScittConfig, ScittHeaders,
    ScittKeyStore, ScittTierPolicy, VerificationOutcome,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse root keys from the transparency log
    let root_keys = vec!["tlog.example.com+deadbeef+base64...".to_string()];
    let key_store = Arc::new(ScittKeyStore::from_c2sp_keys(&root_keys)?);

    let verifier = AnsVerifier::builder()
        .with_caching()
        .scitt_config(ScittConfig::new()
            .with_tier_policy(ScittTierPolicy::ScittWithBadgeFallback))
        .scitt_key_store(key_store)
        .build()
        .await?;

    // Extract SCITT headers from the HTTP response
    let headers = ScittHeaders::from_base64(
        Some(receipt_b64),       // X-SCITT-Receipt header
        Some(status_token_b64),  // X-ANS-Status-Token header
    )?;

    let server_cert = CertIdentity::new(
        Some("agent.example.com".to_string()),
        vec!["agent.example.com".to_string()],
        vec![],
        CertFingerprint::from_der(&cert_der_bytes),
    );

    match verifier.verify_server_with_scitt("agent.example.com", &server_cert, &headers).await {
        VerificationOutcome::ScittVerified { tier, status_token, .. } => {
            println!("SCITT verified (tier: {tier:?}, status: {:?})", status_token.payload.status);
        }
        VerificationOutcome::Verified { badge, .. } => {
            println!("Badge fallback: {}", badge.agent_name());
        }
        outcome => println!("Failed: {outcome:?}"),
    }

    Ok(())
}
```

### Tier Policies

| Policy | Behavior |
|--------|----------|
| `ScittWithBadgeFallback` | Try SCITT first, fall back to badge if no headers (default) |
| `RequireScitt` | SCITT required, no badge fallback |
| `BadgeWithScittEnhancement` | Badge first, upgrade to SCITT if headers present |

### Verification Tiers

| Tier | Meaning |
|------|---------|
| `FullScitt` | Status token + receipt both verified |
| `StatusTokenVerified` | Status token verified, receipt missing or invalid |
| `BadgeOnly` | Traditional badge-based verification |

### Inspect SCITT Artifacts

Use the `inspect_scitt` example to explore real artifacts from a transparency log:

```bash
cargo run -p ans-verify --features scitt --example inspect_scitt -- \
  --tlog https://transparency.ans.godaddy.com \
  --agent-id b8a46f57-5599-4b4d-9a53-0313e5529694
```

## Configuration

### Verifier Builder Options

```rust
let verifier = AnsVerifier::builder()
    // Enable badge caching (recommended)
    .with_caching()

    // Or with custom cache configuration
    .with_cache_config(CacheConfig {
        max_entries: 1000,
        default_ttl: Duration::from_secs(300),
        refresh_threshold: Duration::from_secs(60),
    })

    // Set failure policy
    .failure_policy(FailurePolicy::FailClosed)  // Default: reject on any error
    // Or: FailurePolicy::FailOpenWithCache { max_staleness: Duration::from_secs(600) }

    // Custom DNS resolver (for testing or special configurations)
    .dns_resolver(Arc::new(custom_resolver))

    // Custom transparency log client
    .tlog_client(Arc::new(custom_client))

    // DANE/TLSA verification (optional)
    .dane_policy(DanePolicy::ValidateIfPresent)  // Check TLSA if present
    // Or: .require_dane()  // Fail if no TLSA records
    // Or: .with_dane_if_present()  // Shorthand for ValidateIfPresent
    .dane_port(443)  // Port for TLSA lookup (default: 443)

    // Trusted RA domains (optional, defense-in-depth)
    .trusted_ra_domains(["tlog.example.com", "tlog2.example.com"])

    .build()
    .await?;
```

### Failure Policies

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `FailClosed` | Reject on any error | High security (default) |
| `FailOpenWithCache` | Use cached badge if fresh enough | Balance availability/security |

### DANE/TLSA Policies

DANE binds certificates to DNS names via TLSA records, providing additional verification when DNSSEC is enabled.

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `Disabled` | Skip TLSA verification | Default, no DANE overhead |
| `ValidateIfPresent` | Verify TLSA if records exist, skip if not | Opportunistic security |
| `Required` | Require TLSA records to exist and match | High security with DNSSEC |

### DNS Resolver Configuration

```rust
let verifier = AnsVerifier::builder()
    // Use Cloudflare DNS
    .dns_cloudflare()

    // Or Cloudflare DNS-over-TLS
    .dns_cloudflare_tls()

    // Or Google Public DNS
    .dns_google()

    // Or Quad9 (includes malware blocking)
    .dns_quad9()

    // Or custom nameservers
    .dns_nameservers(&[
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(8, 8, 8, 8),
    ])

    .build()
    .await?;
```

| Preset | Servers | Features |
|--------|---------|----------|
| `dns_cloudflare()` | 1.1.1.1, 1.0.0.1 | Fast, privacy-focused |
| `dns_cloudflare_tls()` | 1.1.1.1 (DoT) | Encrypted queries |
| `dns_google()` | 8.8.8.8, 8.8.4.4 | Reliable, global |
| `dns_google_tls()` | 8.8.8.8 (DoT) | Encrypted queries |
| `dns_quad9()` | 9.9.9.9 | Malware blocking |

## Verification Outcomes

| Outcome | Meaning |
|---------|---------|
| `Verified` | Certificate matches registered ANS agent (badge-based) |
| `ScittVerified` | Certificate verified via SCITT status token (+ optional receipt) |
| `NotAnsAgent` | No `_ans-badge` or `_ra-badge` DNS record found |
| `InvalidStatus` | Badge status is `EXPIRED` or `REVOKED` |
| `FingerprintMismatch` | Certificate fingerprint doesn't match badge |
| `HostnameMismatch` | Certificate CN doesn't match badge agent.host |
| `AnsNameMismatch` | URI SAN doesn't match badge ansName (mTLS only) |
| `ScittError` | SCITT verification failed (signature, expiry, Merkle proof, etc.) |
| `DnsError` | DNS lookup failed |
| `TlogError` | Transparency log API error |
| `DaneError` | DANE/TLSA verification failed |
| `CertError` | Certificate parsing failure |
| `ParseError` | FQDN or AnsName parse failure |

## Badge Status Values

| Status | Valid for Connections | Description |
|--------|----------------------|-------------|
| `Active` | Yes | Agent is registered and in good standing |
| `Warning` | Yes | Certificate expires within 30 days |
| `Deprecated` | Yes | AHP has marked this version for retirement; consumers should migrate |
| `Expired` | No | Certificate has expired |
| `Revoked` | No | Registration has been explicitly revoked |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AnsVerifier                               │
│  ┌─────────────────────┐     ┌─────────────────────┐            │
│  │   ServerVerifier    │     │   ClientVerifier    │            │
│  │  (client-side TLS)  │     │  (server-side mTLS) │            │
│  │  + DANE/TLSA verify │     │                     │            │
│  └──────────┬──────────┘     └──────────┬──────────┘            │
│             │                           │                        │
│  ┌──────────┴───────────────────────────┴──────────┐            │
│  │           SCITT Verification (optional)          │            │
│  │  ScittKeyStore ← verify_status_token()           │            │
│  │                 ← verify_receipt()                │            │
│  └──────────────────────────────────────────────────┘            │
└─────────────┬───────────────────────────┬───────────────────────┘
              │                           │
              ▼                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                         BadgeCache                               │
│                    (TTL-based caching)                          │
└─────────────────────────────────────────────────────────────────┘
              │                           │
              ▼                           ▼
┌──────────────────────┐     ┌────────────────────────────────────┐
│     DnsResolver      │     │    TransparencyLogClient           │
│ (_ans-badge lookup)  │     │      (badge API)                   │
│  (TLSA lookup)       │     │                                    │
└──────────────────────┘     └────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        AnsClient                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  Registration │ Discovery │ Certificates │ Revocation       ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              ANS Registry API (HTTP/JSON)                   ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Testing

The libraries include mock implementations behind the `test-support` feature flag:

```toml
[dev-dependencies]
ans-verify = { ..., features = ["test-support"] }
```

```rust
use ans_verify::{MockDnsResolver, MockTransparencyLogClient, TlsaRecord};

let dns_resolver = Arc::new(
    MockDnsResolver::new()
        .with_records("agent.example.com", vec![badge_record])
        .with_tlsa_records("agent.example.com", 443, vec![tlsa_record])
);

let tlog_client = Arc::new(
    MockTransparencyLogClient::new()
        .with_badge("https://tlog.example.com/badge", badge)
);

let verifier = ServerVerifier::builder()
    .dns_resolver(dns_resolver)
    .tlog_client(tlog_client)
    .with_dane_if_present()
    .build()
    .await?;
```

Run tests:
```bash
# Core tests
cargo test --workspace --features ans-verify/test-support

# Including SCITT tests
cargo test --workspace --features ans-verify/test-support,ans-verify/scitt
```

## Logging

The libraries use the `tracing` crate for structured logging:

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

tracing_subscriber::registry()
    .with(tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "ans_verify=info".into()))
    .with(tracing_subscriber::fmt::layer())
    .init();
```

Run with environment variable for different log levels:
```bash
RUST_LOG=ans_verify=debug cargo run  # Detailed verification steps
RUST_LOG=ans_client=debug cargo run  # API request/response details
```

## TLS Integration (rustls)

The `ans-verify` crate provides optional rustls integration for verifying certificates during TLS handshakes.

Enable the feature:
```toml
[dependencies]
ans-verify = { ..., features = ["rustls"] }
```

### Server Certificate Verification (Client-side)

Use `AnsServerCertVerifier` to verify server certificates match the ANS badge during the TLS handshake:

```rust
use ans_verify::{AnsVerifier, AnsServerCertVerifier, CertFingerprint, DanePolicy};
use std::sync::Arc;

// Pre-fetch the badge to get expected fingerprint
let verifier = AnsVerifier::builder()
    .dane_policy(DanePolicy::ValidateIfPresent)
    .with_caching()
    .build()
    .await?;

let badge = verifier.prefetch("agent.example.com").await?;
let expected_fp = CertFingerprint::parse(badge.server_cert_fingerprint())?;

// Create TLS config with ANS verification
let server_verifier = AnsServerCertVerifier::new(expected_fp)?;

let tls_config = rustls::ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(server_verifier))
    .with_no_client_auth();
```

### Client Certificate Verification (Server-side mTLS)

Use `AnsClientCertVerifier` for the TLS handshake (validates chain to Private CA), then verify against the badge post-handshake:

```rust
use ans_verify::{AnsClientCertVerifier, AnsVerifier, CertIdentity, VerificationOutcome};
use std::sync::Arc;

// Load Private CA for TLS handshake validation
let client_verifier = AnsClientCertVerifier::from_pem(&ca_pem)?;

let server_config = rustls::ServerConfig::builder()
    .with_client_cert_verifier(Arc::new(client_verifier))
    .with_single_cert(server_certs, server_key)?;

// After TLS handshake, verify client against badge
let verifier = AnsVerifier::builder().with_caching().build().await?;

// Extract client cert identity from the TLS connection
let cert_identity = CertIdentity::from_der(client_cert_der)?;

match verifier.verify_client(&cert_identity).await {
    VerificationOutcome::Verified { badge, .. } => {
        println!("Verified ANS agent: {}", badge.agent_name());
    }
    outcome => {
        println!("Verification failed: {:?}", outcome);
    }
}
```

## Examples

See the `crates/ans-verify/examples/` directory:

| Example | Description | Features |
|---------|-------------|----------|
| `verify_server.rs` | Server verification flow | - |
| `verify_mtls_client.rs` | mTLS client verification flow | - |
| `gen_test_certs.rs` | Generate CA, server, and client certificates | - |
| `local_mtls.rs` | Self-contained mTLS demo (generates certs in-memory) | `rustls`, `test-support` |
| `mcp_mtls_client.rs` | Connect to real MCP server with ANS verification | `rustls` |
| `inspect_scitt.rs` | Fetch and verify SCITT artifacts from a live transparency log | `scitt` |
| `verify_server_scitt.rs` | SCITT-enhanced server verification flow | `scitt` |
| `verify_mtls_scitt.rs` | SCITT-enhanced mTLS client verification flow | `scitt` |

### Generate Test Certificates

```bash
cargo run -p ans-verify --example gen_test_certs -- --output-dir ./test-certs
```

### Run Local mTLS Demo

This self-contained example generates certificates in-memory, then runs a TLS server and client with mock DNS and transparency log:

```bash
cargo run -p ans-verify --example local_mtls --features "rustls,test-support"
```

### Connect to Real MCP Server

Requires ANS identity certificates issued by the Private CA:

```bash
ANS_CERT_PATH=/path/to/identity.crt \
ANS_KEY_PATH=/path/to/identity.key \
ANS_SERVER_URL=https://agent.example.com/mcp \
cargo run -p ans-verify --example mcp_mtls_client --features rustls
```

### SCITT Inspector

Fetch and verify real SCITT artifacts from a transparency log:

```bash
cargo run -p ans-verify --features scitt --example inspect_scitt -- \
  --tlog https://transparency.ans.godaddy.com \
  --agent-id b8a46f57-5599-4b4d-9a53-0313e5529694
```

### Basic Verification Examples

```bash
RUST_LOG=ans_verify=debug cargo run -p ans-verify --example verify_server
RUST_LOG=ans_verify=debug cargo run -p ans-verify --example verify_mtls_client
```

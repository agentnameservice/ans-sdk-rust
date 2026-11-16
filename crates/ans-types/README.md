# ans-types

Shared domain types for the Agent Name Service (ANS) ecosystem.

## Overview

This crate provides the foundational types used across all ANS crates. It defines the core domain vocabulary with a small dependency set (`serde` for serialization, `sha2`/`hex`/`subtle` for fingerprints, `chrono`/`url`/`uuid` for domain types).

## Types

### `Fqdn`

Validated Fully Qualified Domain Name. Normalizes to lowercase and strips trailing dots.

```rust
use ans_types::Fqdn;

let fqdn = Fqdn::new("agent.example.com")?;
assert_eq!(fqdn.ans_badge_name(), "_ans-badge.agent.example.com");
assert_eq!(fqdn.tlsa_name(443), "_443._tcp.agent.example.com");
```

### `Version`

Semantic version (major.minor.patch) with comparison support.

```rust
use ans_types::Version;

let v = Version::parse("v1.2.3")?; // "v" prefix is optional
assert_eq!(v.to_string(), "v1.2.3");
assert!(Version::parse("1.0.0")? < Version::parse("2.0.0")?);
```

### `AnsName`

ANS URI format parser for `ans://v{version}.{fqdn}` URIs found in certificate Subject Alternative Names.

```rust
use ans_types::AnsName;

let name = AnsName::parse("ans://v1.0.0.agent.example.com")?;
assert_eq!(name.fqdn().as_str(), "agent.example.com");
assert_eq!(*name.version(), ans_types::Version::new(1, 0, 0));
```

### `Badge`

Transparency log badge containing agent metadata, certificate attestations, and status. Deserialized from the Transparency Log API response.

Key fields:
- `status` — `Active`, `Warning`, `Deprecated`, `Expired`, or `Revoked`
- `payload.attestations` — Server and identity certificate fingerprints
- `payload.agent` — Agent host, version, endpoints

### `CertFingerprint`

SHA-256 certificate fingerprint with case-insensitive comparison.

```rust
use ans_types::CertFingerprint;

// Compute from DER bytes
let fp = CertFingerprint::from_der(der_bytes);

// Parse from string
let fp = CertFingerprint::parse("SHA256:abcd...")?;
assert!(fp.matches("sha256:ABCD...")); // case-insensitive
```

### SCITT Types

These types support SCITT verification in `ans-verify` but live here because they have no crypto dependencies:

- **`StatusTokenPayload`** — Decoded status token payload with agent ID, status, ANS name, certificate fingerprints, and expiry timestamps
- **`CertEntry`** — Certificate fingerprint + type (e.g., `X509-DV-SERVER`) from status token cert arrays
- **`VerificationTier`** — `BadgeOnly`, `StatusTokenVerified`, or `FullScitt`

```rust
use ans_types::{VerificationTier, StatusTokenPayload, CertEntry};

assert!(VerificationTier::FullScitt.is_scitt());
assert!(VerificationTier::FullScitt.has_receipt());
assert!(!VerificationTier::BadgeOnly.is_scitt());
```

## Error Types

- `ParseError` — Invalid FQDN, version, ANS name, or URL format
- `CryptoError` — Certificate parsing failures, invalid fingerprints, missing extensions

## License

New original contributions use [Apache-2.0](LICENSE). Legacy MIT-licensed
material retains its [MIT terms](LICENSES/MIT.txt); see [NOTICE](NOTICE).
The package license expression is `Apache-2.0 AND MIT`.

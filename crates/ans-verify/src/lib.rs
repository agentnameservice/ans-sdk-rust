#![warn(missing_docs)]

//! # ANS Trust Verification Library
//!
//! This library implements the ANS (Agent Name Service) Trust Verification Flow,
//! providing tools for verifying agent identity and trust status.
//!
//! ## Overview
//!
//! The ANS architecture uses a dual-certificate model:
//! - **Public Server Certificate**: Issued by a public CA (e.g., Let's Encrypt)
//! - **Private Identity Certificate**: Issued by the ANS Private CA
//!
//! Verification relies on:
//! - DNS `_ans-badge` TXT records pointing to the transparency log (with `_ra-badge` fallback)
//! - Transparency Log API returning badges with status and certificate fingerprints
//! - Certificate fingerprint comparison
//! - Optional DANE/TLSA verification for additional DNS-based certificate binding
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ans_verify::{AnsVerifier, VerificationOutcome, CertIdentity};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let verifier = AnsVerifier::new().await?;
//!
//!     // After TLS handshake, extract server certificate and verify
//!     let cert_der: &[u8] = &[]; // Your certificate bytes
//!     let cert_identity = CertIdentity::from_der(cert_der)?;
//!
//!     let outcome = verifier
//!         .verify_server("agent.example.com", &cert_identity)
//!         .await;
//!
//!     match outcome {
//!         VerificationOutcome::Verified { badge, .. } => {
//!             println!("Verified ANS agent: {}", badge.agent_name());
//!         }
//!         VerificationOutcome::NotAnsAgent { fqdn } => {
//!             println!("Not a registered ANS agent: {}", fqdn);
//!         }
//!         _ => println!("Verification failed"),
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Endpoint Discovery
//!
//! Beyond trust verification, the DNS layer can enumerate an agent's
//! protocol endpoints from its published discovery records.
//! [`DnsResolver::lookup_discovery`] autodiscovers which discovery profile
//! the agent publishes: it probes the `ANS_DNSAID` SVCB rows at the bare FQDN
//! (RFC 9460) first, then the `ANS_TXT` rows at `_ans.{fqdn}`. That probe
//! order is an SDK convention rather than a spec requirement — see
//! [`DnsResolver::lookup_discovery`] for why, and for what it means in the
//! `ANS_TXT` / `ANS_DNSAID` transition union.
//!
//! ```rust,no_run
//! use ans_verify::{DiscoveryRecord, DnsResolver, HickoryDnsResolver};
//! use ans_types::Fqdn;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let resolver = HickoryDnsResolver::new().await?;
//! let fqdn = Fqdn::new("agent.example.com")?;
//!
//! for record in resolver.get_discovery_records(&fqdn).await? {
//!     match &record {
//!         DiscoveryRecord::Svcb(svcb) => {
//!             println!(
//!                 "{:?} endpoint on port {:?}, metadata at {:?}",
//!                 svcb.protocol(),
//!                 svcb.port(),
//!                 svcb.metadata_url()
//!             );
//!         }
//!         DiscoveryRecord::Txt(txt) => {
//!             println!("{:?} endpoint at {}", txt.protocol(), txt.url());
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! - DNS-based badge discovery via `_ans-badge` TXT records (with `_ra-badge` fallback)
//! - Endpoint discovery via `ANS_DNSAID` SVCB records (RFC 9460, DNS-AID `SvcParams`)
//!   with automatic fallback to `ANS_TXT` `_ans` TXT records
//! - Transparency Log API integration for badge retrieval
//! - Certificate fingerprint verification (SHA-256)
//! - Optional DANE/TLSA verification with configurable policies
//! - DNSSEC validation support
//! - Configurable DNS resolvers (System, Cloudflare, Google, Quad9)
//! - Response caching with configurable TTL
//! - Async-first design with tokio
//! - Optional rustls integration for TLS handshake verification
//! - Optional SCITT `DPoP` (ANS-6 Flavor B) for application-layer A2A authentication

mod cache;
mod dane;
mod dns;
mod error;
mod tlog;
mod verify;

#[cfg(feature = "rustls")]
mod rustls_verifier;

#[cfg(feature = "scitt")]
mod scitt;

#[cfg(feature = "scitt")]
mod pop;

// Re-export types from ans-types for convenience
pub use ans_types::{
    AgentEvent, AgentInfo, AnsName, Attestations, Badge, BadgePayload, BadgeStatus,
    CertAttestation, CertFingerprint, CryptoError, EventType, Fqdn, MerkleProof, ParseError,
    Producer, Version,
};

// Re-export from this crate
pub use cache::{BadgeCache, CacheConfig, CacheKey, CachedBadge};
pub use dane::{
    DanePolicy, DaneVerificationResult, TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage,
};
#[cfg(any(test, feature = "test-support"))]
pub use dns::MockDnsResolver;
pub use dns::{
    AgentProtocol, BadgeRecord, DiscoveryRecord, DnsLookupResult, DnsResolver, DnsResolverConfig,
    HickoryDnsResolver, SvcbDiscoveryRecord, TxtDiscoveryRecord,
};
pub use error::{
    AnsError, AnsResult, DaneError, DnsError, HttpError, TlogError, VerificationError,
};
#[cfg(any(test, feature = "test-support"))]
pub use tlog::MockTransparencyLogClient;
pub use tlog::{AuditResponse, HttpTransparencyLogClient, TransparencyLogClient};
pub use verify::{
    AnsVerifier, AnsVerifierBuilder, CertIdentity, ClientVerifier, FailurePolicy, ServerVerifier,
    VerificationOutcome,
};

#[cfg(feature = "scitt")]
pub use verify::{ScittConfig, ScittTierPolicy};

#[cfg(feature = "rustls")]
pub use rustls_verifier::{AnsClientCertVerifier, AnsServerCertVerifier};

#[cfg(feature = "scitt")]
pub use scitt::{
    ClockFn, HttpScittClient, KeyRefreshHandle, ReceiptCache, RefreshableKeyStore, ScittClient,
    ScittError, ScittHeaderSupplier, ScittHeaders, ScittKeyStore, ScittOutgoingHeaders,
    ScittRefreshHandle, ScittVerificationCache, StatusTokenCache, TrustedKey, VerifiedReceipt,
    VerifiedStatusToken, system_clock, verify_receipt, verify_status_token, verify_status_token_at,
};

#[cfg(feature = "scitt")]
pub use pop::{
    CallerIdentity, DEFAULT_ARTIFACT_CACHE_ENTRIES, DEFAULT_POP_SKEW, DEFAULT_REPLAY_MAX_ENTRIES,
    DPOP_HEADER, MAX_JTI_SIZE, MAX_PROOF_SIZE, MemoryReplayCache, PopError, PopErrorKind,
    ProofResult, ReplayCache, Signer, VerifiedArtifactCache, VerifyCallerOptions,
    VerifyProofOptions, access_token_from_authorization, attach_identity, normalize_authority,
    normalize_htu, reject_duplicate_header, request_authority, verify_caller, verify_proof,
};

#[cfg(all(feature = "scitt", any(test, feature = "test-support")))]
pub use scitt::{
    MockScittClient, ParsedCoseSign1, compute_sig_structure_digest, matches_identity_cert,
    matches_server_cert, parse_cose_sign1,
};

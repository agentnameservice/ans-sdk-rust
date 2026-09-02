//! SCITT (Supply Chain Integrity, Transparency, and Trust) verification.
//!
//! This module provides offline verification of agent identity via
//! SCITT receipts (Merkle inclusion proofs) and status tokens (signed
//! current-status claims). It is gated behind the `scitt` feature flag.
//!
//! # Architecture
//!
//! - **`error`**: [`ScittError`] enum covering all SCITT failure modes
//! - **`headers`**: [`ScittHeaders`] for extracting SCITT artifacts from HTTP headers
//!
//! # Feature flag
//!
//! All types in this module require `features = ["scitt"]` in `Cargo.toml`.
//! The lightweight data types ([`VerificationTier`], [`StatusTokenPayload`],
//! [`CertEntry`]) live in `ans-types` and are always available.

mod client;
mod cose;
mod error;
mod headers;
mod merkle;
mod receipt;
mod refreshable_key_store;
mod root_keys;
mod scitt_cache;
mod status_token;
mod supplier;
mod verification_cache;

use std::sync::Arc;

/// A function that returns the current Unix timestamp in seconds.
///
/// Defaults to [`system_clock`]. Override in tests to control time-sensitive
/// security checks (token expiry, cooldown gating) without wall-clock coupling.
pub type ClockFn = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Returns the system UTC clock. This is the default used by all SCITT components.
pub fn system_clock() -> ClockFn {
    Arc::new(|| chrono::Utc::now().timestamp())
}

// ── Public API (intended for external consumers) ─────────────────────────────
pub use client::{HttpScittClient, ScittClient};
pub use error::ScittError;
pub use headers::ScittHeaders;
pub use receipt::{VerifiedReceipt, verify_receipt};
pub use refreshable_key_store::{KeyRefreshHandle, RefreshableKeyStore};
pub use root_keys::{ScittKeyStore, TrustedKey};
pub use scitt_cache::{ReceiptCache, StatusTokenCache};
pub use status_token::{VerifiedStatusToken, verify_status_token, verify_status_token_at};
pub use supplier::{ScittHeaderSupplier, ScittOutgoingHeaders, ScittRefreshHandle};
pub use verification_cache::ScittVerificationCache;

// ── Internal API (used by verify.rs and pop, not re-exported from lib.rs) ────
pub use status_token::{MAX_CLOCK_SKEW_TOLERANCE_SECS, matches_identity_cert, matches_server_cert};
pub use verification_cache::{CachedScittOutcome, hash_bytes};

// ── Test-support API (internal primitives exposed for integration tests) ─────
#[cfg(any(test, feature = "test-support"))]
pub use client::MockScittClient;
#[cfg(any(test, feature = "test-support"))]
pub use cose::{ParsedCoseSign1, compute_sig_structure_digest, parse_cose_sign1};

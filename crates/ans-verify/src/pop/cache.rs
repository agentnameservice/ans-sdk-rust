//! Cache of verified SCITT artifacts for re-presented headers (ANS-6 §4.6).

use std::sync::Arc;

use ans_types::StatusTokenPayload;
use moka::future::Cache;
use sha2::{Digest, Sha256};

use super::proof::LeafCert;
use crate::scitt::VerifiedReceipt;

/// Default maximum cached entries per artifact type.
pub const DEFAULT_ARTIFACT_CACHE_ENTRIES: u64 = 1024;

/// Cache of verified status tokens and receipts, keyed by artifact bytes.
///
/// Peers re-present their SCITT artifacts on every request, and
/// re-presentation does not imply re-verification (ANS-6 §4.6). Passing this
/// cache in [`super::VerifyCallerOptions`] lets [`super::verify_caller`]
/// re-run cryptographic verification only when the presented bytes change or
/// a cached token's `exp` passes. The `DPoP` possession proof is never
/// cached — it is single-use by design — but the parsed `x5c[0]` certificate
/// is reused for identical entry bytes; its validity window and signature
/// still check on every request.
///
/// Scope one cache per trusted-key-store configuration: a hit vouches for
/// the exact bytes under the key store they first verified against.
///
/// Cloning is cheap and shares the underlying storage.
#[derive(Clone)]
pub struct VerifiedArtifactCache {
    status_tokens: Cache<[u8; 32], Arc<StatusTokenPayload>>,
    receipts: Cache<[u8; 32], Arc<VerifiedReceipt>>,
    // Parsed x5c[0] entries, keyed by the entry's base64 bytes. Entries are
    // pure functions of their key preimage (no trust decision is cached);
    // the time-dependent validity check still runs per request. Sync cache:
    // the proof path has no await points.
    proof_certs: moka::sync::Cache<[u8; 32], Arc<LeafCert>>,
}

impl std::fmt::Debug for VerifiedArtifactCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedArtifactCache")
            .field("status_tokens", &self.status_tokens.entry_count())
            .field("receipts", &self.receipts.entry_count())
            .field("proof_certs", &self.proof_certs.entry_count())
            .finish()
    }
}

impl Default for VerifiedArtifactCache {
    fn default() -> Self {
        Self::new(DEFAULT_ARTIFACT_CACHE_ENTRIES)
    }
}

impl VerifiedArtifactCache {
    /// Build a cache holding up to `max_entries` status tokens and as many
    /// receipts. `max_entries == 0` uses [`DEFAULT_ARTIFACT_CACHE_ENTRIES`].
    ///
    /// Expired status tokens are rejected at read time regardless of
    /// residency, so the bound is a memory ceiling, not a freshness control.
    pub fn new(max_entries: u64) -> Self {
        let max_entries = if max_entries == 0 {
            DEFAULT_ARTIFACT_CACHE_ENTRIES
        } else {
            max_entries
        };
        Self {
            status_tokens: Cache::new(max_entries),
            receipts: Cache::new(max_entries),
            proof_certs: moka::sync::Cache::new(max_entries),
        }
    }

    /// Cache key: SHA-256 of the artifact bytes.
    pub(crate) fn key(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    pub(crate) async fn status(&self, key: &[u8; 32]) -> Option<Arc<StatusTokenPayload>> {
        self.status_tokens.get(key).await
    }

    pub(crate) async fn store_status(&self, key: [u8; 32], payload: Arc<StatusTokenPayload>) {
        self.status_tokens.insert(key, payload).await;
    }

    pub(crate) async fn receipt(&self, key: &[u8; 32]) -> Option<Arc<VerifiedReceipt>> {
        self.receipts.get(key).await
    }

    pub(crate) async fn store_receipt(&self, key: [u8; 32], receipt: Arc<VerifiedReceipt>) {
        self.receipts.insert(key, receipt).await;
    }

    pub(crate) fn proof_cert(&self, key: &[u8; 32]) -> Option<Arc<LeafCert>> {
        self.proof_certs.get(key)
    }

    pub(crate) fn store_proof_cert(&self, key: [u8; 32], cert: Arc<LeafCert>) {
        self.proof_certs.insert(key, cert);
    }
}

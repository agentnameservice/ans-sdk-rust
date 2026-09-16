//! Verifier-side caches for SCITT verification results.
//!
//! These caches eliminate redundant cryptographic operations when the same
//! status token or receipt bytes are verified repeatedly (e.g., multiple
//! HTTP requests over a single TLS connection).
//!
//! # Architecture
//!
//! Two layers, checked in order:
//!
//! - **Layer 2 (outcome cache)**: Keyed by `(cert_fingerprint, token_hash,
//!   receipt_hash?)`. A hit skips *all* verification — no crypto, no
//!   fingerprint comparison, no cache lookups into Layer 1. This is the
//!   fast path for repeated requests from the same peer.
//!
//! - **Layer 1 (crypto caches)**: Content-addressed caches for individual
//!   verified artifacts. A token cache hit skips the ECDSA signature
//!   verification (~1ms). A receipt cache hit skips Merkle proof + ECDSA.
//!   Fingerprint comparison still runs (trivially cheap).
//!
//! Only successful verifications are cached. Errors (bad signatures,
//! expired tokens, terminal status) are never stored.
//!
//! # Relationship to existing caches
//!
//! [`StatusTokenCache`](super::scitt_cache::StatusTokenCache) and
//! [`ReceiptCache`](super::scitt_cache::ReceiptCache) are **agent-side**
//! caches keyed by agent UUID, used by [`ScittHeaderSupplier`](super::supplier::ScittHeaderSupplier).
//! This module provides **verifier-side** caches keyed by content and trust
//! scope. The scope includes the trusted key IDs, public keys, and TL names,
//! so a result verified under one trust configuration cannot satisfy another.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::future::Cache;
use moka::policy::Expiry;
use sha2::{Digest, Sha256};

use ans_types::{CertFingerprint, VerificationTier};

use super::receipt::VerifiedReceipt;
use super::status_token::VerifiedStatusToken;

/// Default maximum cache entries per layer.
const DEFAULT_MAX_ENTRIES: u64 = 1000;

/// Default receipt cache TTL: 24 hours.
///
/// Receipts are immutable Merkle proofs — once verified, the result never
/// changes. 24h is a conservative operational default to bound memory.
const DEFAULT_RECEIPT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

// ── Layer 2 types ───────────────────────────────────────────────────────

/// Cache key for the Layer 2 outcome cache.
///
/// Combines the certificate fingerprint, trust-scoped status token hash, and
/// optional trust-scoped receipt hash. This naturally provides connection-level
/// deduplication: within a single TLS connection the cert never changes,
/// and the agent typically sends the same token on every request.
#[derive(Clone, Hash, PartialEq, Eq)]
struct OutcomeKey {
    /// Raw bytes of the certificate fingerprint (SHA-256).
    cert_fingerprint_bytes: [u8; 32],
    /// Hash of the trust scope and raw status token bytes.
    token_hash: [u8; 32],
    /// Hash of the trust scope and raw receipt bytes, if present.
    receipt_hash: Option<[u8; 32]>,
}

impl fmt::Debug for OutcomeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutcomeKey")
            .field("cert_fp", &hex::encode(self.cert_fingerprint_bytes))
            .field("token", &hex::encode(self.token_hash))
            .field("receipt", &self.receipt_hash.map(hex::encode))
            .finish()
    }
}

/// Cached SCITT verification outcome (Layer 2 value).
///
/// Contains everything needed to reconstruct a
/// [`VerificationOutcome::ScittVerified`](crate::VerificationOutcome::ScittVerified)
/// without any cryptographic work.
#[derive(Debug, Clone)]
pub struct CachedScittOutcome {
    pub(crate) verified_token: Arc<VerifiedStatusToken>,
    pub(crate) tier: VerificationTier,
    pub(crate) matched_fingerprint: CertFingerprint,
    /// Token expiry timestamp (for TTL and freshness checks).
    pub(crate) exp: i64,
}

// ── Expiry policies ─────────────────────────────────────────────────────

/// Per-entry expiry for the Layer 1 token cache.
///
/// Each token's TTL is derived from its `exp` claim. Tokens within the
/// clock-skew window (exp slightly in the past) will get TTL 0 and be
/// evicted immediately — this is acceptable since it only affects the
/// last ~60s of a token's typically multi-hour lifetime.
struct TokenContentExpiry;

impl Expiry<[u8; 32], Arc<VerifiedStatusToken>> for TokenContentExpiry {
    fn expire_after_create(
        &self,
        _key: &[u8; 32],
        value: &Arc<VerifiedStatusToken>,
        _created_at: Instant,
    ) -> Option<Duration> {
        let now = chrono::Utc::now().timestamp();
        let remaining = (value.payload.exp - now).max(0).cast_unsigned();
        Some(Duration::from_secs(remaining))
    }

    fn expire_after_update(
        &self,
        _key: &[u8; 32],
        value: &Arc<VerifiedStatusToken>,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        let now = chrono::Utc::now().timestamp();
        let remaining = (value.payload.exp - now).max(0).cast_unsigned();
        Some(Duration::from_secs(remaining))
    }
}

/// Per-entry expiry for the Layer 2 outcome cache.
struct OutcomeExpiry;

impl Expiry<OutcomeKey, Arc<CachedScittOutcome>> for OutcomeExpiry {
    fn expire_after_create(
        &self,
        _key: &OutcomeKey,
        value: &Arc<CachedScittOutcome>,
        _created_at: Instant,
    ) -> Option<Duration> {
        let now = chrono::Utc::now().timestamp();
        let remaining = (value.exp - now).max(0).cast_unsigned();
        Some(Duration::from_secs(remaining))
    }

    fn expire_after_update(
        &self,
        _key: &OutcomeKey,
        value: &Arc<CachedScittOutcome>,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        let now = chrono::Utc::now().timestamp();
        let remaining = (value.exp - now).max(0).cast_unsigned();
        Some(Duration::from_secs(remaining))
    }
}

// ── Main cache struct ───────────────────────────────────────────────────

/// Verifier-side cache for SCITT verification results.
///
/// Eliminates redundant ECDSA signature verification and Merkle proof
/// computation when the same status tokens and receipts are presented
/// repeatedly (e.g., multiple HTTP requests over one TLS connection).
///
/// Created automatically by [`AnsVerifierBuilder::with_caching`](crate::AnsVerifierBuilder::with_caching)
/// or explicitly via [`AnsVerifierBuilder::with_scitt_verification_cache`](crate::AnsVerifierBuilder::with_scitt_verification_cache).
///
/// # Example
///
/// ```rust,ignore
/// use ans_verify::{AnsVerifier, ScittVerificationCache};
///
/// let verifier = AnsVerifier::builder()
///     .trusted_ra_domains(["transparency.ans.godaddy.com"])
///     .with_caching() // enables badge + SCITT verification caching
///     .build()
///     .await?;
///
/// // Or with custom sizing:
/// let verifier = AnsVerifier::builder()
///     .trusted_ra_domains(["transparency.ans.godaddy.com"])
///     .with_scitt_verification_cache(ScittVerificationCache::new(5000))
///     .build()
///     .await?;
/// ```
#[allow(clippy::struct_field_names)]
pub struct ScittVerificationCache {
    /// Layer 1: Content-addressed store for verified status tokens.
    /// Key = hash of the trust scope and raw token bytes.
    token_cache: Cache<[u8; 32], Arc<VerifiedStatusToken>>,
    /// Layer 1: Content-addressed store for verified receipts.
    /// Key = hash of the trust scope and raw receipt bytes.
    receipt_cache: Cache<[u8; 32], Arc<VerifiedReceipt>>,
    /// Layer 2: Full outcome store keyed by
    /// (`cert_fingerprint`, `token_hash`, `receipt_hash`?).
    outcome_cache: Cache<OutcomeKey, Arc<CachedScittOutcome>>,
}

impl fmt::Debug for ScittVerificationCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScittVerificationCache")
            .field("token_entries", &self.token_cache.entry_count())
            .field("receipt_entries", &self.receipt_cache.entry_count())
            .field("outcome_entries", &self.outcome_cache.entry_count())
            .finish()
    }
}

impl ScittVerificationCache {
    /// Create a new cache with the given maximum entries per layer.
    pub fn new(max_entries: u64) -> Self {
        let token_cache = Cache::builder()
            .max_capacity(max_entries)
            .expire_after(TokenContentExpiry)
            .build();

        let receipt_cache = Cache::builder()
            .max_capacity(max_entries)
            .time_to_live(DEFAULT_RECEIPT_TTL)
            .build();

        let outcome_cache = Cache::builder()
            .max_capacity(max_entries)
            .expire_after(OutcomeExpiry)
            .build();

        Self {
            token_cache,
            receipt_cache,
            outcome_cache,
        }
    }

    /// Create a new cache with default settings (1000 entries per layer).
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }

    // ── Layer 2: Outcome cache ──────────────────────────────────────────

    /// Look up a cached SCITT verification outcome.
    ///
    /// Returns `Some` if this exact `(cert, token, receipt)` combination
    /// was previously verified successfully and the token has not expired.
    pub(crate) async fn get_outcome(
        &self,
        cert_fingerprint: &CertFingerprint,
        token_hash: &[u8; 32],
        receipt_hash: Option<&[u8; 32]>,
    ) -> Option<Arc<CachedScittOutcome>> {
        let key = OutcomeKey {
            cert_fingerprint_bytes: *cert_fingerprint.as_bytes(),
            token_hash: *token_hash,
            receipt_hash: receipt_hash.copied(),
        };
        let outcome = self.outcome_cache.get(&key).await?;

        // Belt-and-suspenders expiry check (Moka handles eviction
        // asynchronously, so a just-expired entry could still be returned).
        let now = chrono::Utc::now().timestamp();
        if now >= outcome.exp {
            return None;
        }
        Some(outcome)
    }

    /// Store a successful SCITT verification outcome in the Layer 2 cache.
    pub(crate) async fn insert_outcome(
        &self,
        cert_fingerprint: &CertFingerprint,
        token_hash: &[u8; 32],
        receipt_hash: Option<&[u8; 32]>,
        outcome: CachedScittOutcome,
    ) {
        let key = OutcomeKey {
            cert_fingerprint_bytes: *cert_fingerprint.as_bytes(),
            token_hash: *token_hash,
            receipt_hash: receipt_hash.copied(),
        };
        self.outcome_cache.insert(key, Arc::new(outcome)).await;
    }

    // ── Layer 1: Token cache ────────────────────────────────────────────

    /// Look up a cached verified status token by content hash.
    ///
    /// Returns `Some` if this exact token was previously verified and has
    /// not expired. Skips the expensive ECDSA P-256 signature verification.
    pub(crate) async fn get_verified_token(
        &self,
        token_hash: &[u8; 32],
    ) -> Option<Arc<VerifiedStatusToken>> {
        let token = self.token_cache.get(token_hash).await?;

        // Re-check expiry — the Moka per-entry TTL handles eviction, but
        // there is a small race window where an expired entry is still
        // readable. This check closes it.
        let now = chrono::Utc::now().timestamp();
        if now >= token.payload.exp {
            return None;
        }
        Some(token)
    }

    /// Store a verified status token in the Layer 1 cache.
    pub(crate) async fn insert_verified_token(
        &self,
        token_hash: [u8; 32],
        token: Arc<VerifiedStatusToken>,
    ) {
        self.token_cache.insert(token_hash, token).await;
    }

    // ── Layer 1: Receipt cache ──────────────────────────────────────────

    /// Look up a cached verified receipt by content hash.
    ///
    /// Returns `Some` if this exact receipt was previously verified. Skips
    /// Merkle proof computation and ECDSA signature verification.
    pub(crate) async fn get_verified_receipt(
        &self,
        receipt_hash: &[u8; 32],
    ) -> Option<Arc<VerifiedReceipt>> {
        self.receipt_cache.get(receipt_hash).await
    }

    /// Store a verified receipt in the Layer 1 cache.
    pub(crate) async fn insert_verified_receipt(
        &self,
        receipt_hash: [u8; 32],
        receipt: Arc<VerifiedReceipt>,
    ) {
        self.receipt_cache.insert(receipt_hash, receipt).await;
    }

    // ── Diagnostics ─────────────────────────────────────────────────────

    /// Returns the number of entries in the Layer 1 token cache.
    pub fn token_entry_count(&self) -> u64 {
        self.token_cache.entry_count()
    }

    /// Returns the number of entries in the Layer 1 receipt cache.
    pub fn receipt_entry_count(&self) -> u64 {
        self.receipt_cache.entry_count()
    }

    /// Returns the number of entries in the Layer 2 outcome cache.
    pub fn outcome_entry_count(&self) -> u64 {
        self.outcome_cache.entry_count()
    }
}

impl Default for ScittVerificationCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Compute SHA-256 hash of a byte slice.
///
/// Used to derive content-addressed cache keys from raw token/receipt bytes.
/// Cost is ~1μs for typical SCITT artifacts (~500 bytes), negligible compared
/// to the ECDSA verification (~1ms) it helps skip.
pub fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ans_types::{BadgeStatus, CertEntry, CertFingerprint, StatusTokenPayload};
    use uuid::Uuid;

    use super::*;

    // ── Test helpers ────────────────────────────────────────────────────

    fn make_verified_token(exp: i64) -> VerifiedStatusToken {
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        VerifiedStatusToken {
            payload: StatusTokenPayload::new(
                Uuid::nil(),
                BadgeStatus::Active,
                0,
                exp,
                ans_types::AnsName::parse("ans://v1.0.0.agent.example.com").unwrap(),
                vec![],
                vec![CertEntry::new(fp, ans_types::CertType::X509DvServer)],
                BTreeMap::new(),
            ),
            key_id: [0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    fn make_verified_token_with_status(exp: i64, status: BadgeStatus) -> VerifiedStatusToken {
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        VerifiedStatusToken {
            payload: StatusTokenPayload::new(
                Uuid::nil(),
                status,
                0,
                exp,
                ans_types::AnsName::parse("ans://v1.0.0.agent.example.com").unwrap(),
                vec![],
                vec![CertEntry::new(fp, ans_types::CertType::X509DvServer)],
                BTreeMap::new(),
            ),
            key_id: [0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    fn make_verified_receipt(tree_size: u64, leaf_index: u64) -> VerifiedReceipt {
        VerifiedReceipt {
            tree_size,
            leaf_index,
            root_hash: [0u8; 32],
            event_bytes: b"test-event".to_vec(),
            key_id: [0xDE, 0xAD, 0xBE, 0xEF],
            iss: None,
            iat: None,
        }
    }

    fn future_exp() -> i64 {
        chrono::Utc::now().timestamp() + 3600
    }

    fn past_exp() -> i64 {
        946_684_800 // year 2000
    }

    fn cert_fp(seed: u8) -> CertFingerprint {
        CertFingerprint::from_bytes([seed; 32])
    }

    fn token_hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn receipt_hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // ── hash_bytes ──────────────────────────────────────────────────────

    #[test]
    fn hash_bytes_deterministic() {
        let input = b"hello world";
        let h1 = hash_bytes(input);
        let h2 = hash_bytes(input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_bytes_different_inputs_differ() {
        let h1 = hash_bytes(b"input-a");
        let h2 = hash_bytes(b"input-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_bytes_empty_input() {
        let h = hash_bytes(b"");
        // SHA-256 of empty string is a well-known constant
        assert_eq!(
            hex::encode(h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ── Construction ────────────────────────────────────────────────────

    #[test]
    fn with_defaults_creates_valid_cache() {
        let cache = ScittVerificationCache::with_defaults();
        assert_eq!(cache.token_entry_count(), 0);
        assert_eq!(cache.receipt_entry_count(), 0);
        assert_eq!(cache.outcome_entry_count(), 0);
    }

    #[test]
    fn custom_max_entries() {
        let cache = ScittVerificationCache::new(5000);
        assert_eq!(cache.token_entry_count(), 0);
        // Verify it constructs without panic (max capacity is internal to Moka)
        let _ = format!("{cache:?}");
    }

    #[test]
    fn debug_format() {
        let cache = ScittVerificationCache::with_defaults();
        let dbg = format!("{cache:?}");
        assert!(dbg.contains("ScittVerificationCache"));
        assert!(dbg.contains("token_entries"));
        assert!(dbg.contains("receipt_entries"));
        assert!(dbg.contains("outcome_entries"));
    }

    #[test]
    fn default_trait_impl() {
        let cache = ScittVerificationCache::default();
        assert_eq!(cache.token_entry_count(), 0);
    }

    const fn _assert_send_sync<T: Send + Sync>() {}
    const _: () = _assert_send_sync::<ScittVerificationCache>();

    // ── Layer 1: Token cache ────────────────────────────────────────────

    #[tokio::test]
    async fn token_cache_hit_returns_verified_token() {
        let cache = ScittVerificationCache::with_defaults();
        let hash = token_hash(1);
        let token = Arc::new(make_verified_token(future_exp()));

        cache.insert_verified_token(hash, token.clone()).await;
        let cached = cache.get_verified_token(&hash).await;

        assert!(cached.is_some());
        assert_eq!(cached.unwrap().key_id, token.key_id);
    }

    #[tokio::test]
    async fn token_cache_miss_returns_none() {
        let cache = ScittVerificationCache::with_defaults();
        let result = cache.get_verified_token(&token_hash(99)).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn token_cache_different_hashes_independent() {
        let cache = ScittVerificationCache::with_defaults();
        let token_a = Arc::new(make_verified_token(future_exp()));
        let token_b = Arc::new(make_verified_token(future_exp()));

        cache
            .insert_verified_token(token_hash(1), token_a.clone())
            .await;
        cache
            .insert_verified_token(token_hash(2), token_b.clone())
            .await;

        // Run pending tasks for Moka to update counts
        cache.token_cache.run_pending_tasks().await;
        assert_eq!(cache.token_entry_count(), 2);

        let a = cache.get_verified_token(&token_hash(1)).await.unwrap();
        let b = cache.get_verified_token(&token_hash(2)).await.unwrap();
        assert!(Arc::ptr_eq(&a, &token_a));
        assert!(Arc::ptr_eq(&b, &token_b));
    }

    #[tokio::test]
    async fn token_cache_expired_returns_none() {
        let cache = ScittVerificationCache::with_defaults();
        let token = Arc::new(make_verified_token(past_exp()));

        cache.insert_verified_token(token_hash(1), token).await;

        // Manual expiry check catches it even before Moka eviction
        let result = cache.get_verified_token(&token_hash(1)).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn token_cache_overwrite_with_newer_token() {
        let cache = ScittVerificationCache::with_defaults();
        let exp1 = future_exp();
        let exp2 = future_exp() + 1800;
        let token1 = Arc::new(make_verified_token(exp1));
        let token2 = Arc::new(make_verified_token(exp2));

        cache.insert_verified_token(token_hash(1), token1).await;
        cache.insert_verified_token(token_hash(1), token2).await;

        let cached = cache.get_verified_token(&token_hash(1)).await.unwrap();
        assert_eq!(cached.payload.exp, exp2);
    }

    #[tokio::test]
    async fn token_cache_non_active_status_cached() {
        let cache = ScittVerificationCache::with_defaults();
        let token = Arc::new(make_verified_token_with_status(
            future_exp(),
            BadgeStatus::Warning,
        ));

        cache
            .insert_verified_token(token_hash(1), token.clone())
            .await;
        let cached = cache.get_verified_token(&token_hash(1)).await;

        assert!(cached.is_some());
        assert_eq!(cached.unwrap().payload.status, BadgeStatus::Warning);
    }

    #[tokio::test]
    async fn token_cache_entry_count() {
        let cache = ScittVerificationCache::with_defaults();

        cache
            .insert_verified_token(token_hash(1), Arc::new(make_verified_token(future_exp())))
            .await;
        cache
            .insert_verified_token(token_hash(2), Arc::new(make_verified_token(future_exp())))
            .await;
        cache
            .insert_verified_token(token_hash(3), Arc::new(make_verified_token(future_exp())))
            .await;

        cache.token_cache.run_pending_tasks().await;
        assert_eq!(cache.token_entry_count(), 3);
    }

    // ── Layer 1: Receipt cache ──────────────────────────────────────────

    #[tokio::test]
    async fn receipt_cache_hit_returns_verified_receipt() {
        let cache = ScittVerificationCache::with_defaults();
        let hash = receipt_hash(1);
        let receipt = Arc::new(make_verified_receipt(10, 3));

        cache.insert_verified_receipt(hash, receipt.clone()).await;
        let cached = cache.get_verified_receipt(&hash).await;

        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.tree_size, 10);
        assert_eq!(cached.leaf_index, 3);
    }

    #[tokio::test]
    async fn receipt_cache_miss_returns_none() {
        let cache = ScittVerificationCache::with_defaults();
        let result = cache.get_verified_receipt(&receipt_hash(99)).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn receipt_cache_different_hashes_independent() {
        let cache = ScittVerificationCache::with_defaults();
        let r1 = Arc::new(make_verified_receipt(5, 0));
        let r2 = Arc::new(make_verified_receipt(10, 7));

        cache.insert_verified_receipt(receipt_hash(1), r1).await;
        cache.insert_verified_receipt(receipt_hash(2), r2).await;

        cache.receipt_cache.run_pending_tasks().await;
        assert_eq!(cache.receipt_entry_count(), 2);

        let c1 = cache.get_verified_receipt(&receipt_hash(1)).await.unwrap();
        let c2 = cache.get_verified_receipt(&receipt_hash(2)).await.unwrap();
        assert_eq!(c1.tree_size, 5);
        assert_eq!(c2.tree_size, 10);
    }

    #[tokio::test]
    async fn receipt_cache_overwrite() {
        let cache = ScittVerificationCache::with_defaults();
        cache
            .insert_verified_receipt(receipt_hash(1), Arc::new(make_verified_receipt(5, 2)))
            .await;
        cache
            .insert_verified_receipt(receipt_hash(1), Arc::new(make_verified_receipt(20, 15)))
            .await;

        let cached = cache.get_verified_receipt(&receipt_hash(1)).await.unwrap();
        assert_eq!(cached.tree_size, 20);
        assert_eq!(cached.leaf_index, 15);
    }

    #[tokio::test]
    async fn receipt_cache_entry_count() {
        let cache = ScittVerificationCache::with_defaults();
        cache
            .insert_verified_receipt(receipt_hash(1), Arc::new(make_verified_receipt(1, 0)))
            .await;
        cache
            .insert_verified_receipt(receipt_hash(2), Arc::new(make_verified_receipt(2, 1)))
            .await;

        cache.receipt_cache.run_pending_tasks().await;
        assert_eq!(cache.receipt_entry_count(), 2);
    }

    // ── Layer 2: Outcome cache ──────────────────────────────────────────

    fn make_outcome(exp: i64, tier: VerificationTier) -> CachedScittOutcome {
        CachedScittOutcome {
            verified_token: Arc::new(make_verified_token(exp)),
            tier,
            matched_fingerprint: cert_fp(0),
            exp,
        }
    }

    #[tokio::test]
    async fn outcome_cache_hit_exact_match() {
        let cache = ScittVerificationCache::with_defaults();
        let fp = cert_fp(1);
        let th = token_hash(1);
        let rh = receipt_hash(1);
        let outcome = make_outcome(future_exp(), VerificationTier::FullScitt);

        cache
            .insert_outcome(&fp, &th, Some(&rh), outcome.clone())
            .await;
        let cached = cache.get_outcome(&fp, &th, Some(&rh)).await;

        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.tier, VerificationTier::FullScitt);
    }

    #[tokio::test]
    async fn outcome_cache_miss_on_different_cert() {
        let cache = ScittVerificationCache::with_defaults();
        let th = token_hash(1);
        let outcome = make_outcome(future_exp(), VerificationTier::StatusTokenVerified);

        cache.insert_outcome(&cert_fp(1), &th, None, outcome).await;

        // Different cert fingerprint → miss
        let result = cache.get_outcome(&cert_fp(2), &th, None).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn outcome_cache_miss_on_different_token() {
        let cache = ScittVerificationCache::with_defaults();
        let fp = cert_fp(1);
        let outcome = make_outcome(future_exp(), VerificationTier::StatusTokenVerified);

        cache
            .insert_outcome(&fp, &token_hash(1), None, outcome)
            .await;

        // Different token hash → miss
        let result = cache.get_outcome(&fp, &token_hash(2), None).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn outcome_cache_miss_on_different_receipt() {
        let cache = ScittVerificationCache::with_defaults();
        let fp = cert_fp(1);
        let th = token_hash(1);
        let outcome = make_outcome(future_exp(), VerificationTier::FullScitt);

        cache
            .insert_outcome(&fp, &th, Some(&receipt_hash(1)), outcome)
            .await;

        // Different receipt hash → miss
        let result = cache.get_outcome(&fp, &th, Some(&receipt_hash(2))).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn outcome_cache_receipt_present_vs_absent_differ() {
        let cache = ScittVerificationCache::with_defaults();
        let fp = cert_fp(1);
        let th = token_hash(1);
        let rh = receipt_hash(1);

        // Insert with receipt
        let outcome_full = make_outcome(future_exp(), VerificationTier::FullScitt);
        cache
            .insert_outcome(&fp, &th, Some(&rh), outcome_full)
            .await;

        // Insert without receipt (different key)
        let outcome_token_only = make_outcome(future_exp(), VerificationTier::StatusTokenVerified);
        cache
            .insert_outcome(&fp, &th, None, outcome_token_only)
            .await;

        cache.outcome_cache.run_pending_tasks().await;
        assert_eq!(cache.outcome_entry_count(), 2);

        // Both retrievable independently
        let with_receipt = cache.get_outcome(&fp, &th, Some(&rh)).await.unwrap();
        assert_eq!(with_receipt.tier, VerificationTier::FullScitt);

        let without_receipt = cache.get_outcome(&fp, &th, None).await.unwrap();
        assert_eq!(without_receipt.tier, VerificationTier::StatusTokenVerified);
    }

    #[tokio::test]
    async fn outcome_cache_expired_returns_none() {
        let cache = ScittVerificationCache::with_defaults();
        let outcome = make_outcome(past_exp(), VerificationTier::StatusTokenVerified);

        cache
            .insert_outcome(&cert_fp(1), &token_hash(1), None, outcome)
            .await;

        // Manual expiry check catches it
        let result = cache.get_outcome(&cert_fp(1), &token_hash(1), None).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn outcome_cache_entry_count() {
        let cache = ScittVerificationCache::with_defaults();

        // Insert 3 different outcomes
        for seed in 1..=3 {
            cache
                .insert_outcome(
                    &cert_fp(seed),
                    &token_hash(seed),
                    None,
                    make_outcome(future_exp(), VerificationTier::StatusTokenVerified),
                )
                .await;
        }

        cache.outcome_cache.run_pending_tasks().await;
        assert_eq!(cache.outcome_entry_count(), 3);
    }

    #[tokio::test]
    async fn outcome_cache_overwrite_updates_tier() {
        let cache = ScittVerificationCache::with_defaults();
        let fp = cert_fp(1);
        let th = token_hash(1);

        // First: token-only
        cache
            .insert_outcome(
                &fp,
                &th,
                None,
                make_outcome(future_exp(), VerificationTier::StatusTokenVerified),
            )
            .await;

        // Overwrite with same key
        cache
            .insert_outcome(
                &fp,
                &th,
                None,
                make_outcome(future_exp(), VerificationTier::FullScitt),
            )
            .await;

        let cached = cache.get_outcome(&fp, &th, None).await.unwrap();
        assert_eq!(cached.tier, VerificationTier::FullScitt);
    }

    // ── Cross-layer independence ────────────────────────────────────────

    #[tokio::test]
    async fn layers_are_independent() {
        let cache = ScittVerificationCache::with_defaults();

        // Inserting in Layer 1 does not affect Layer 2
        cache
            .insert_verified_token(token_hash(1), Arc::new(make_verified_token(future_exp())))
            .await;
        cache
            .insert_verified_receipt(receipt_hash(1), Arc::new(make_verified_receipt(5, 2)))
            .await;

        let outcome = cache
            .get_outcome(&cert_fp(1), &token_hash(1), Some(&receipt_hash(1)))
            .await;
        assert!(
            outcome.is_none(),
            "Layer 1 entries should not create Layer 2 hits"
        );

        // And vice versa: Layer 2 insert does not affect Layer 1
        cache
            .insert_outcome(
                &cert_fp(1),
                &token_hash(2),
                None,
                make_outcome(future_exp(), VerificationTier::StatusTokenVerified),
            )
            .await;

        let token = cache.get_verified_token(&token_hash(2)).await;
        assert!(
            token.is_none(),
            "Layer 2 entries should not create Layer 1 hits"
        );
    }

    // ── Concurrency ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn concurrent_reads_and_writes() {
        let cache = Arc::new(ScittVerificationCache::with_defaults());
        let exp = future_exp();

        // Spawn 10 concurrent writers
        let mut handles = Vec::new();
        for i in 0..10u8 {
            let cache = cache.clone();
            handles.push(tokio::spawn(async move {
                let token = Arc::new(make_verified_token(exp));
                cache.insert_verified_token(token_hash(i), token).await;

                let receipt = Arc::new(make_verified_receipt(i.into(), 0));
                cache
                    .insert_verified_receipt(receipt_hash(i), receipt)
                    .await;

                cache
                    .insert_outcome(
                        &cert_fp(i),
                        &token_hash(i),
                        None,
                        make_outcome(exp, VerificationTier::StatusTokenVerified),
                    )
                    .await;
            }));
        }

        // Wait for all writers
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all entries readable
        for i in 0..10u8 {
            assert!(cache.get_verified_token(&token_hash(i)).await.is_some());
            assert!(cache.get_verified_receipt(&receipt_hash(i)).await.is_some());
            assert!(
                cache
                    .get_outcome(&cert_fp(i), &token_hash(i), None)
                    .await
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn concurrent_reads_during_population() {
        let cache = Arc::new(ScittVerificationCache::with_defaults());
        let exp = future_exp();

        // Insert one entry
        let token = Arc::new(make_verified_token(exp));
        cache
            .insert_verified_token(token_hash(1), token.clone())
            .await;

        // Spawn concurrent readers + one writer
        let mut handles = Vec::new();
        for _ in 0..20 {
            let cache = cache.clone();
            handles.push(tokio::spawn(async move {
                // Read existing entry
                let _ = cache.get_verified_token(&token_hash(1)).await;
                // Read non-existent entry
                let _ = cache.get_verified_token(&token_hash(99)).await;
            }));
        }

        // Also write concurrently
        let cache2 = cache.clone();
        handles.push(tokio::spawn(async move {
            let token = Arc::new(make_verified_token(exp));
            cache2.insert_verified_token(token_hash(2), token).await;
        }));

        for handle in handles {
            handle.await.unwrap();
        }

        // Original entry still intact
        assert!(cache.get_verified_token(&token_hash(1)).await.is_some());
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn outcome_key_with_all_zeros() {
        let cache = ScittVerificationCache::with_defaults();
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        let th = [0u8; 32];
        let rh = [0u8; 32];

        cache
            .insert_outcome(
                &fp,
                &th,
                Some(&rh),
                make_outcome(future_exp(), VerificationTier::FullScitt),
            )
            .await;

        let result = cache.get_outcome(&fp, &th, Some(&rh)).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn token_expiring_exactly_now_returns_none() {
        let cache = ScittVerificationCache::with_defaults();
        let now = chrono::Utc::now().timestamp();
        let token = Arc::new(make_verified_token(now));

        cache.insert_verified_token(token_hash(1), token).await;

        // `now >= exp` should trigger, returning None
        let result = cache.get_verified_token(&token_hash(1)).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn outcome_expiring_exactly_now_returns_none() {
        let cache = ScittVerificationCache::with_defaults();
        let now = chrono::Utc::now().timestamp();
        let outcome = make_outcome(now, VerificationTier::StatusTokenVerified);

        cache
            .insert_outcome(&cert_fp(1), &token_hash(1), None, outcome)
            .await;

        let result = cache.get_outcome(&cert_fp(1), &token_hash(1), None).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn same_token_different_agents_same_cache_entry() {
        // Content-addressed: same token bytes → same hash → same entry
        // regardless of which agent sent them.
        let cache = ScittVerificationCache::with_defaults();
        let hash = token_hash(42);
        let token = Arc::new(make_verified_token(future_exp()));

        cache.insert_verified_token(hash, token.clone()).await;

        // Any lookup with the same hash hits
        let cached = cache.get_verified_token(&hash).await;
        assert!(cached.is_some());
        assert!(Arc::ptr_eq(&cached.unwrap(), &token));
    }

    #[tokio::test]
    async fn outcome_stores_correct_fingerprint() {
        let cache = ScittVerificationCache::with_defaults();
        let fp = cert_fp(42);
        let outcome = CachedScittOutcome {
            verified_token: Arc::new(make_verified_token(future_exp())),
            tier: VerificationTier::StatusTokenVerified,
            matched_fingerprint: fp.clone(),
            exp: future_exp(),
        };

        cache
            .insert_outcome(&fp, &token_hash(1), None, outcome)
            .await;

        let cached = cache.get_outcome(&fp, &token_hash(1), None).await.unwrap();
        assert_eq!(cached.matched_fingerprint, fp);
    }

    #[tokio::test]
    async fn outcome_stores_correct_tier() {
        let cache = ScittVerificationCache::with_defaults();

        for (seed, tier) in [
            (1u8, VerificationTier::StatusTokenVerified),
            (2, VerificationTier::FullScitt),
        ] {
            let outcome = make_outcome(future_exp(), tier);
            cache
                .insert_outcome(&cert_fp(seed), &token_hash(seed), None, outcome)
                .await;
        }

        let c1 = cache
            .get_outcome(&cert_fp(1), &token_hash(1), None)
            .await
            .unwrap();
        assert_eq!(c1.tier, VerificationTier::StatusTokenVerified);

        let c2 = cache
            .get_outcome(&cert_fp(2), &token_hash(2), None)
            .await
            .unwrap();
        assert_eq!(c2.tier, VerificationTier::FullScitt);
    }
}

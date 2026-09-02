//! Badge caching with TTL and background refresh support.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use moka::future::Cache;
use tokio::sync::RwLock;

use ans_types::{Badge, Fqdn, Version};

/// Cache configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CacheConfig {
    /// Maximum number of entries in the cache.
    pub max_entries: u64,
    /// Default time-to-live for cached badges.
    ///
    /// This is the *freshness* window: normal reads ([`BadgeCache::get`] and
    /// friends) serve an entry only while it is younger than this.
    pub default_ttl: Duration,
    /// Time before TTL when refresh is recommended.
    pub refresh_threshold: Duration,
    /// How long entries stay resident after insertion (hard eviction bound).
    ///
    /// Between `default_ttl` and `hard_ttl` an entry is *stale*: invisible to
    /// normal reads but still available to the `*_allow_stale` getters, which
    /// exist for fail-open fallback under a lookup outage (ANS-6 §9.2). A
    /// deployment using `FailurePolicy::FailOpenWithCache` should keep this
    /// at or above its `max_staleness`. Values below `default_ttl` are
    /// clamped up to it.
    pub hard_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1000,
            default_ttl: Duration::from_secs(300), // 5 minutes
            refresh_threshold: Duration::from_secs(60), // 1 minute before expiry
            hard_ttl: Duration::from_secs(1200),   // 20 minutes
        }
    }
}

impl CacheConfig {
    /// Create a new configuration with custom TTL.
    ///
    /// The stale-residency bound ([`Self::hard_ttl`]) scales to 4× the
    /// freshness TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            default_ttl: ttl,
            refresh_threshold: Duration::from_secs(ttl.as_secs() / 5),
            hard_ttl: ttl.saturating_mul(4),
            ..Default::default()
        }
    }
}

/// Cache key for badge lookups.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacheKey {
    /// Key by FQDN and version.
    FqdnVersion(String, Version),
    /// Key by badge URL.
    Url(String),
}

impl CacheKey {
    /// Create a key for FQDN and version.
    pub fn fqdn_version(fqdn: &Fqdn, version: &Version) -> Self {
        Self::FqdnVersion(fqdn.as_str().to_lowercase(), version.clone())
    }

    /// Create a key for URL.
    pub fn url(url: &str) -> Self {
        Self::Url(url.to_string())
    }
}

/// Cached badge entry with metadata.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CachedBadge {
    /// The cached badge.
    pub badge: Badge,
    /// When the badge was fetched.
    pub fetched_at: Instant,
    /// TTL for this entry.
    pub ttl: Duration,
}

impl CachedBadge {
    /// Create a new cached badge.
    pub fn new(badge: Badge, ttl: Duration) -> Self {
        Self {
            badge,
            fetched_at: Instant::now(),
            ttl,
        }
    }

    /// Check if the cached badge is still valid.
    pub fn is_valid(&self) -> bool {
        self.fetched_at.elapsed() < self.ttl
    }

    /// Check if the badge should be refreshed soon.
    pub fn should_refresh(&self, threshold: Duration) -> bool {
        let remaining = self.ttl.saturating_sub(self.fetched_at.elapsed());
        remaining < threshold
    }

    /// Get the remaining TTL.
    pub fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.fetched_at.elapsed())
    }
}

/// Badge cache with TTL support.
///
/// All badges are cached by `FqdnVersion`. A secondary version index tracks which
/// versions are cached per FQDN, enabling `get_all_for_fqdn()` to scan all cached
/// badges for a given host during rolling deployments.
pub struct BadgeCache {
    cache: Cache<CacheKey, CachedBadge>,
    config: CacheConfig,
    /// Secondary index: FQDN (lowercased) → set of cached versions.
    /// Enables `get_all_for_fqdn()` without requiring moka prefix scans.
    version_index: RwLock<HashMap<String, Vec<Version>>>,
}

impl fmt::Debug for BadgeCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BadgeCache")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl BadgeCache {
    /// Create a new cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        let cache = Cache::builder()
            .max_capacity(config.max_entries)
            .time_to_live(config.hard_ttl.max(config.default_ttl))
            .build();

        Self {
            cache,
            config,
            version_index: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new cache with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    /// Get a cached badge by key.
    pub async fn get(&self, key: &CacheKey) -> Option<CachedBadge> {
        self.cache.get(key).await.filter(CachedBadge::is_valid)
    }

    /// Get a cached badge by key, including entries past their freshness TTL.
    ///
    /// For fail-open fallback under a lookup outage (ANS-6 §9.2): the caller
    /// is expected to bound acceptance with its own staleness threshold via
    /// [`CachedBadge::fetched_at`]. Entries remain readable until the
    /// [`CacheConfig::hard_ttl`] eviction bound.
    pub async fn get_allow_stale(&self, key: &CacheKey) -> Option<CachedBadge> {
        self.cache.get(key).await
    }

    /// Insert a badge into the cache.
    pub async fn insert(&self, key: CacheKey, badge: Badge) {
        let cached = CachedBadge::new(badge, self.config.default_ttl);
        self.cache.insert(key, cached).await;
    }

    /// Insert a badge with a custom soft TTL.
    ///
    /// The soft TTL controls when [`CachedBadge::is_valid`] returns false (i.e., when
    /// reads treat the entry as stale). The underlying moka cache still uses the
    /// global `default_ttl` for hard eviction. This means entries may be filtered out
    /// by `is_valid()` before moka evicts them.
    pub async fn insert_with_ttl(&self, key: CacheKey, badge: Badge, ttl: Duration) {
        let cached = CachedBadge::new(badge, ttl);
        self.cache.insert(key, cached).await;
    }

    /// Invalidate a cache entry.
    pub async fn invalidate(&self, key: &CacheKey) {
        self.cache.invalidate(key).await;
    }

    /// Clear all entries from the cache.
    pub async fn clear(&self) {
        self.cache.invalidate_all();
        self.cache.run_pending_tasks().await;
        self.version_index.write().await.clear();
    }

    /// Check if a cached badge should be refreshed.
    pub fn should_refresh(&self, cached: &CachedBadge) -> bool {
        cached.should_refresh(self.config.refresh_threshold)
    }

    /// Get the number of entries in the cache.
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Get a badge by FQDN and version.
    pub async fn get_by_fqdn_version(&self, fqdn: &Fqdn, version: &Version) -> Option<CachedBadge> {
        self.get(&CacheKey::fqdn_version(fqdn, version)).await
    }

    /// [`Self::get_by_fqdn_version`], including entries past their freshness
    /// TTL. See [`Self::get_allow_stale`].
    pub async fn get_by_fqdn_version_allow_stale(
        &self,
        fqdn: &Fqdn,
        version: &Version,
    ) -> Option<CachedBadge> {
        self.get_allow_stale(&CacheKey::fqdn_version(fqdn, version))
            .await
    }

    /// Insert a badge keyed by FQDN and version, updating the version index.
    ///
    /// The version index enables `get_all_for_fqdn()` to discover all cached
    /// badges for a given host.
    pub async fn insert_for_fqdn_version(&self, fqdn: &Fqdn, version: &Version, badge: Badge) {
        self.insert_for_fqdn_version_with_ttl(fqdn, version, badge, self.config.default_ttl)
            .await;
    }

    /// [`Self::insert_for_fqdn_version`] with a custom soft (freshness) TTL.
    ///
    /// See [`Self::insert_with_ttl`] for the soft/hard TTL distinction.
    pub async fn insert_for_fqdn_version_with_ttl(
        &self,
        fqdn: &Fqdn,
        version: &Version,
        badge: Badge,
        ttl: Duration,
    ) {
        self.insert_with_ttl(CacheKey::fqdn_version(fqdn, version), badge, ttl)
            .await;

        let key = fqdn.as_str().to_lowercase();
        let mut index = self.version_index.write().await;
        let versions = index.entry(key).or_default();
        if !versions.contains(version) {
            versions.push(version.clone());
        }
    }

    /// Get all cached badges for an FQDN across all known versions.
    ///
    /// Reads the version index to find which versions are cached, then fetches
    /// each one. Filters out expired entries.
    pub async fn get_all_for_fqdn(&self, fqdn: &Fqdn) -> Vec<CachedBadge> {
        self.collect_for_fqdn(fqdn, false).await
    }

    /// [`Self::get_all_for_fqdn`], including entries past their freshness
    /// TTL. See [`Self::get_allow_stale`].
    pub async fn get_all_for_fqdn_allow_stale(&self, fqdn: &Fqdn) -> Vec<CachedBadge> {
        self.collect_for_fqdn(fqdn, true).await
    }

    async fn collect_for_fqdn(&self, fqdn: &Fqdn, allow_stale: bool) -> Vec<CachedBadge> {
        let key = fqdn.as_str().to_lowercase();
        let index = self.version_index.read().await;
        let versions = match index.get(&key) {
            Some(v) => v.clone(),
            None => return Vec::new(),
        };
        drop(index); // Release read lock before async cache lookups

        let mut results = Vec::new();
        for version in &versions {
            let key = CacheKey::fqdn_version(fqdn, version);
            let cached = if allow_stale {
                self.get_allow_stale(&key).await
            } else {
                self.get(&key).await
            };
            if let Some(cached) = cached {
                results.push(cached);
            }
        }
        results
    }

    /// Invalidate all cached badges for an FQDN (all versions).
    pub async fn invalidate_fqdn(&self, fqdn: &Fqdn) {
        let key = fqdn.as_str().to_lowercase();
        let mut index = self.version_index.write().await;
        if let Some(versions) = index.remove(&key) {
            for version in &versions {
                self.cache
                    .invalidate(&CacheKey::fqdn_version(fqdn, version))
                    .await;
            }
        }
    }

    /// Set the known versions for an FQDN from DNS records.
    ///
    /// Called after DNS lookup to pre-populate the version index with all
    /// discovered versions, even before badges are fetched.
    pub async fn set_version_index(&self, fqdn: &Fqdn, versions: Vec<Version>) {
        let key = fqdn.as_str().to_lowercase();
        let mut index = self.version_index.write().await;
        index.insert(key, versions);
    }
}

impl Default for BadgeCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn create_test_badge() -> Badge {
        test_badge_from_json("test.example.com", "v1.0.0", "SHA256:bbb", "SHA256:aaa")
    }

    fn test_badge_from_json(
        host: &str,
        version: &str,
        server_fp: &str,
        identity_fp: &str,
    ) -> Badge {
        serde_json::from_value(serde_json::json!({
            "status": "ACTIVE",
            "schemaVersion": "V1",
            "payload": {
                "logId": Uuid::new_v4().to_string(),
                "producer": {
                    "event": {
                        "ansId": Uuid::new_v4().to_string(),
                        "ansName": format!("ans://{version}.{host}"),
                        "eventType": "AGENT_REGISTERED",
                        "agent": { "host": host, "name": "Test Agent", "version": version },
                        "attestations": {
                            "domainValidation": "ACME-DNS-01",
                            "identityCert": { "fingerprint": identity_fp, "type": "X509-OV-CLIENT" },
                            "serverCert": { "fingerprint": server_fp, "type": "X509-DV-SERVER" }
                        },
                        "expiresAt": (Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
                        "issuedAt": Utc::now().to_rfc3339(),
                        "raId": "test-ra",
                        "timestamp": Utc::now().to_rfc3339()
                    },
                    "keyId": "test-key",
                    "signature": "test-sig"
                }
            }
        })).expect("test badge JSON should be valid")
    }

    #[tokio::test]
    async fn test_cache_insert_and_get() {
        let cache = BadgeCache::with_defaults();
        let badge = create_test_badge();
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let version = Version::new(1, 0, 0);

        cache
            .insert_for_fqdn_version(&fqdn, &version, badge.clone())
            .await;

        let cached = cache.get_by_fqdn_version(&fqdn, &version).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().badge.agent_host(), "test.example.com");
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = BadgeCache::with_defaults();
        let fqdn = Fqdn::new("unknown.example.com").unwrap();

        let cached = cache
            .get_by_fqdn_version(&fqdn, &Version::new(1, 0, 0))
            .await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_invalidate() {
        let cache = BadgeCache::with_defaults();
        let badge = create_test_badge();
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let version = Version::new(1, 0, 0);

        cache.insert_for_fqdn_version(&fqdn, &version, badge).await;
        assert!(cache.get_by_fqdn_version(&fqdn, &version).await.is_some());

        cache
            .invalidate(&CacheKey::fqdn_version(&fqdn, &version))
            .await;
        assert!(cache.get_by_fqdn_version(&fqdn, &version).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_by_version() {
        let cache = BadgeCache::with_defaults();
        let badge = create_test_badge();
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let version = Version::new(1, 0, 0);

        cache.insert_for_fqdn_version(&fqdn, &version, badge).await;

        let cached = cache.get_by_fqdn_version(&fqdn, &version).await;
        assert!(cached.is_some());

        // Different version should not be found
        let cached = cache
            .get_by_fqdn_version(&fqdn, &Version::new(2, 0, 0))
            .await;
        assert!(cached.is_none());
    }

    #[test]
    fn test_cached_badge_validity() {
        let badge = create_test_badge();
        let cached = CachedBadge::new(badge, Duration::from_secs(60));

        assert!(cached.is_valid());
        // With 60s TTL just created (remaining ~60s) and 10s threshold, should not refresh yet
        assert!(!cached.should_refresh(Duration::from_secs(10)));
    }

    #[test]
    fn test_cached_badge_should_refresh() {
        let badge = create_test_badge();
        let cached = CachedBadge::new(badge, Duration::from_secs(30));

        // With 30s TTL and 60s threshold, should recommend refresh
        assert!(cached.should_refresh(Duration::from_secs(60)));

        // With 30s TTL and 10s threshold, should not recommend refresh yet
        assert!(!cached.should_refresh(Duration::from_secs(10)));
    }

    fn create_test_badge_versioned(version: &str) -> Badge {
        test_badge_from_json(
            "test.example.com",
            version,
            &format!("SHA256:{version}-server-fp"),
            "SHA256:aaa",
        )
    }

    #[tokio::test]
    async fn test_version_index_populated_on_tracked_insert() {
        let cache = BadgeCache::with_defaults();
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 0, 1);

        cache
            .insert_for_fqdn_version(&fqdn, &v1, create_test_badge_versioned("v1.0.0"))
            .await;
        cache
            .insert_for_fqdn_version(&fqdn, &v2, create_test_badge_versioned("v1.0.1"))
            .await;

        // Version index should contain both versions
        let index = cache.version_index.read().await;
        let versions = index.get("test.example.com").unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.contains(&v1));
        assert!(versions.contains(&v2));
    }

    #[tokio::test]
    async fn test_get_all_for_fqdn_returns_all_versions() {
        let cache = BadgeCache::with_defaults();
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 0, 1);

        cache
            .insert_for_fqdn_version(&fqdn, &v1, create_test_badge_versioned("v1.0.0"))
            .await;
        cache
            .insert_for_fqdn_version(&fqdn, &v2, create_test_badge_versioned("v1.0.1"))
            .await;

        let all = cache.get_all_for_fqdn(&fqdn).await;
        assert_eq!(all.len(), 2);

        let versions: Vec<String> = all
            .iter()
            .map(|c| c.badge.agent_version().to_string())
            .collect();
        assert!(versions.contains(&"v1.0.0".to_string()));
        assert!(versions.contains(&"v1.0.1".to_string()));
    }

    #[tokio::test]
    async fn test_get_all_for_fqdn_empty_for_unknown() {
        let cache = BadgeCache::with_defaults();
        let fqdn = Fqdn::new("unknown.example.com").unwrap();

        let all = cache.get_all_for_fqdn(&fqdn).await;
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn test_invalidate_fqdn_clears_all_versions() {
        let cache = BadgeCache::with_defaults();
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 0, 1);

        cache
            .insert_for_fqdn_version(&fqdn, &v1, create_test_badge_versioned("v1.0.0"))
            .await;
        cache
            .insert_for_fqdn_version(&fqdn, &v2, create_test_badge_versioned("v1.0.1"))
            .await;

        // Verify all entries exist
        assert_eq!(cache.get_all_for_fqdn(&fqdn).await.len(), 2);

        // Invalidate all
        cache.invalidate_fqdn(&fqdn).await;

        // All entries should be gone
        assert!(cache.get_all_for_fqdn(&fqdn).await.is_empty());
        assert!(cache.get_by_fqdn_version(&fqdn, &v1).await.is_none());
        assert!(cache.get_by_fqdn_version(&fqdn, &v2).await.is_none());
    }

    #[tokio::test]
    async fn test_set_version_index() {
        let cache = BadgeCache::with_defaults();
        let fqdn = Fqdn::new("test.example.com").unwrap();

        cache
            .set_version_index(&fqdn, vec![Version::new(1, 0, 0), Version::new(2, 0, 0)])
            .await;

        // Index set, but no badges cached yet — get_all should return empty
        let all = cache.get_all_for_fqdn(&fqdn).await;
        assert!(all.is_empty());

        // Now insert a badge for one version
        cache
            .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), create_test_badge())
            .await;

        let all = cache.get_all_for_fqdn(&fqdn).await;
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn test_tracked_insert_idempotent() {
        let cache = BadgeCache::with_defaults();
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let v1 = Version::new(1, 0, 0);

        // Insert same version twice
        cache
            .insert_for_fqdn_version(&fqdn, &v1, create_test_badge())
            .await;
        cache
            .insert_for_fqdn_version(&fqdn, &v1, create_test_badge())
            .await;

        // Version should appear only once in the index
        let index = cache.version_index.read().await;
        let versions = index.get("test.example.com").unwrap();
        assert_eq!(versions.len(), 1);
    }

    #[tokio::test]
    async fn test_clear_resets_version_index() {
        let cache = BadgeCache::with_defaults();
        let fqdn = Fqdn::new("test.example.com").unwrap();

        cache
            .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), create_test_badge())
            .await;
        assert!(!cache.get_all_for_fqdn(&fqdn).await.is_empty());

        cache.clear().await;
        assert!(cache.get_all_for_fqdn(&fqdn).await.is_empty());
    }

    /// A stale entry (past its freshness TTL, within the hard eviction bound)
    /// is invisible to normal reads but served by the `*_allow_stale` getters.
    #[tokio::test]
    async fn test_stale_entry_visible_only_to_allow_stale_reads() {
        let cache = BadgeCache::with_defaults();
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let version = Version::new(1, 0, 0);

        cache
            .insert_for_fqdn_version_with_ttl(&fqdn, &version, create_test_badge(), Duration::ZERO)
            .await;

        assert!(cache.get_by_fqdn_version(&fqdn, &version).await.is_none());
        assert!(cache.get_all_for_fqdn(&fqdn).await.is_empty());

        let stale = cache
            .get_by_fqdn_version_allow_stale(&fqdn, &version)
            .await
            .unwrap();
        assert!(!stale.is_valid());
        assert_eq!(cache.get_all_for_fqdn_allow_stale(&fqdn).await.len(), 1);
    }

    /// Fresh entries are served by both read paths.
    #[tokio::test]
    async fn test_allow_stale_reads_also_serve_fresh_entries() {
        let cache = BadgeCache::with_defaults();
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let version = Version::new(1, 0, 0);

        cache
            .insert_for_fqdn_version(&fqdn, &version, create_test_badge())
            .await;

        assert!(cache.get_by_fqdn_version(&fqdn, &version).await.is_some());
        assert!(
            cache
                .get_by_fqdn_version_allow_stale(&fqdn, &version)
                .await
                .is_some()
        );
    }
}

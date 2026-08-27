//! Replay cache for single-use `DPoP` proof identifiers.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;

use super::error::{PopError, PopErrorKind};

/// Default in-memory cache entry ceiling.
///
/// Size for the in-flight window: `max_entries ≥ peak RPS × (skew + grace)`.
/// At the defaults that is roughly 800 req/s; above that the cache fails
/// closed for every caller.
pub const DEFAULT_REPLAY_MAX_ENTRIES: usize = 100_000;

/// Groups entries by expiry generation (seconds). Eviction drops whole
/// generations; over-retention is the safe direction.
const BUCKET_WIDTH_SECS: i64 = 5;

/// Records `DPoP` proof identifiers to reject reuse.
///
/// `check_and_store` MUST be atomic: it reports whether a key was already
/// present and, only if not, records it. A non-error `true` is a replay; a
/// non-error `false` means the key was stored. An error (for example capacity)
/// MUST fail closed — never silently admit a possibly-replayed proof.
///
/// `key` is a fixed-width digest of the proof's `jti`, never the raw claim.
#[async_trait]
pub trait ReplayCache: Send + Sync {
    /// Returns `true` if `key` is already recorded and still within expiry.
    async fn check_and_store(&self, key: &str, exp_unix: i64) -> Result<bool, PopError>;
}

/// In-process, bounded [`ReplayCache`].
///
/// Blocks replay only within a single process. Multi-replica deployments
/// serving the same `htu` authority need a shared backend.
pub struct MemoryReplayCache {
    inner: Mutex<Inner>,
}

struct Inner {
    index: HashMap<String, i64>,
    buckets: HashMap<i64, HashSet<String>>,
    max_entries: usize,
    now: fn() -> i64,
}

impl std::fmt::Debug for MemoryReplayCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.debug_struct("MemoryReplayCache")
            .field("len", &inner.index.len())
            .field("max_entries", &inner.max_entries)
            .finish()
    }
}

impl MemoryReplayCache {
    /// Build a bounded cache. `max_entries == 0` uses [`DEFAULT_REPLAY_MAX_ENTRIES`].
    pub fn new(max_entries: usize) -> Self {
        let max_entries = if max_entries == 0 {
            DEFAULT_REPLAY_MAX_ENTRIES
        } else {
            max_entries
        };
        Self {
            inner: Mutex::new(Inner {
                index: HashMap::new(),
                buckets: HashMap::new(),
                max_entries,
                now: now_unix,
            }),
        }
    }

    /// Number of entries currently held. Compare to [`Self::cap`] to alarm
    /// on saturation before the cache starts failing closed.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .index
            .len()
    }

    /// Returns `true` if the cache currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Configured entry ceiling.
    pub fn cap(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .max_entries
    }

    /// Drop expired generations. Called automatically from `check_and_store`.
    pub fn evict_expired(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = (inner.now)();
        inner.evict(now);
    }

    #[cfg(test)]
    pub(crate) fn with_clock(self, now: fn() -> i64) -> Self {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .now = now;
        self
    }
}

#[async_trait]
impl ReplayCache for MemoryReplayCache {
    async fn check_and_store(&self, key: &str, exp_unix: i64) -> Result<bool, PopError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = (inner.now)();
        inner.evict(now);

        if let Some(existing) = inner.index.get(key).copied() {
            if existing > now {
                return Ok(true);
            }
            inner.remove(key, existing);
        }

        if inner.index.len() >= inner.max_entries {
            return Err(PopError::new(
                PopErrorKind::ReplayCacheFull,
                "replay cache at capacity; cannot record proof id",
            ));
        }
        inner.add(key.to_string(), exp_unix);
        Ok(false)
    }
}

impl Inner {
    fn bucket_of(exp: i64) -> i64 {
        exp.div_euclid(BUCKET_WIDTH_SECS)
    }

    fn add(&mut self, key: String, exp: i64) {
        let id = Self::bucket_of(exp);
        self.index.insert(key.clone(), exp);
        self.buckets.entry(id).or_default().insert(key);
    }

    fn remove(&mut self, key: &str, exp: i64) {
        self.index.remove(key);
        let id = Self::bucket_of(exp);
        if let Some(bucket) = self.buckets.get_mut(&id) {
            bucket.remove(key);
            if bucket.is_empty() {
                self.buckets.remove(&id);
            }
        }
    }

    fn evict(&mut self, now: i64) {
        let stale: Vec<i64> = self
            .buckets
            .keys()
            .copied()
            .filter(|id| (*id + 1) * BUCKET_WIDTH_SECS <= now)
            .collect();
        for id in stale {
            if let Some(keys) = self.buckets.remove(&id) {
                for key in keys {
                    if self.index.get(&key).copied().map(Self::bucket_of) == Some(id) {
                        self.index.remove(&key);
                    }
                }
            }
        }
    }
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

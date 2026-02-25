//! L1 in-memory cache using moka.
//!
//! TinyLFU admission policy, size-aware eviction, per-entry TTL.
//! Fastest tier — sub-microsecond lookups.

use std::time::Duration;

use moka::sync::Cache;

/// L1 in-memory embedding cache.
///
/// Keys are blake3 content hashes. Values are embedding vectors.
pub struct L1MemoryCache {
    cache: Cache<String, Vec<f32>>,
}

impl L1MemoryCache {
    /// Create a new L1 cache with the given max entry count.
    pub fn new(max_entries: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .time_to_idle(Duration::from_secs(3600)) // 1 hour idle TTL
            .time_to_live(Duration::from_secs(86400)) // 24 hour max TTL
            .build();

        Self { cache }
    }

    /// Get an embedding by content hash.
    pub fn get(&self, content_hash: &str) -> Option<Vec<f32>> {
        self.cache.get(content_hash)
    }

    /// Insert an embedding keyed by content hash.
    pub fn insert(&self, content_hash: String, embedding: Vec<f32>) {
        self.cache.insert(content_hash, embedding);
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Invalidate all entries.
    pub fn clear(&self) {
        self.cache.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let cache = L1MemoryCache::new(100);
        let hash = "abc123".to_string();
        let vec = vec![1.0, 2.0, 3.0];
        cache.insert(hash.clone(), vec.clone());
        assert_eq!(cache.get(&hash), Some(vec));
    }

    #[test]
    fn miss_returns_none() {
        let cache = L1MemoryCache::new(100);
        assert_eq!(cache.get("nonexistent"), None);
    }

    #[test]
    fn clear_empties_cache() {
        let cache = L1MemoryCache::new(100);
        cache.insert("a".to_string(), vec![1.0]);
        cache.insert("b".to_string(), vec![2.0]);
        cache.clear();
        // moka may not immediately reflect invalidation in entry_count,
        // but get should return None.
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.get("b"), None);
    }
}

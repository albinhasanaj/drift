//! 3-tier embedding cache coordinator.
//!
//! L1 (moka in-memory) → L2 (SQLite persistent) → L3 (precomputed mmap).
//! Write-through: on miss, compute embedding, write to L1 + L2.

pub mod l1_memory;
pub mod l2_sqlite;
pub mod l3_precomputed;

pub use l1_memory::L1MemoryCache;
pub use l2_sqlite::L2SqliteCache;
pub use l3_precomputed::L3PrecomputedCache;

use tracing::debug;

/// Orchestrates lookups across all three cache tiers.
///
/// Lookup order: L3 (precomputed) → L1 (memory) → L2 (SQLite).
/// L3 is checked first because it's zero-latency memory-mapped data.
pub struct CacheCoordinator {
    pub l1: L1MemoryCache,
    pub l2: L2SqliteCache,
    pub l3: L3PrecomputedCache,
}

/// Result of a cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheHitTier {
    L1,
    L2,
    L3,
    Miss,
}

impl CacheCoordinator {
    /// Create a new coordinator with the given L1 capacity (in-memory L2 only).
    pub fn new(l1_capacity: u64) -> Self {
        Self {
            l1: L1MemoryCache::new(l1_capacity),
            l2: L2SqliteCache::new(),
            l3: L3PrecomputedCache::new(),
        }
    }

    /// D-01: Create a coordinator with a file-backed L2 cache.
    pub fn new_with_db_path(l1_capacity: u64, db_path: &std::path::Path) -> Self {
        Self {
            l1: L1MemoryCache::new(l1_capacity),
            l2: L2SqliteCache::open(db_path),
            l3: L3PrecomputedCache::new(),
        }
    }

    /// Look up an embedding by content hash across all tiers.
    ///
    /// On L2/L3 hit, promotes to L1 for faster subsequent access.
    pub fn get(&self, content_hash: &str) -> (Option<Vec<f32>>, CacheHitTier) {
        // L3: precomputed (zero-latency).
        if let Some(vec) = self.l3.get(content_hash) {
            debug!(hash = content_hash, tier = "L3", "cache hit");
            // Promote to L1.
            self.l1.insert(content_hash.to_string(), vec.clone());
            return (Some(vec.clone()), CacheHitTier::L3);
        }

        // L1: in-memory (sub-microsecond).
        if let Some(vec) = self.l1.get(content_hash) {
            debug!(hash = content_hash, tier = "L1", "cache hit");
            return (Some(vec), CacheHitTier::L1);
        }

        // L2: SQLite (millisecond).
        if let Some(vec) = self.l2.get(content_hash) {
            debug!(hash = content_hash, tier = "L2", "cache hit");
            // Promote to L1.
            self.l1.insert(content_hash.to_string(), vec.clone());
            return (Some(vec), CacheHitTier::L2);
        }

        (None, CacheHitTier::Miss)
    }

    /// Store an embedding in L1 and L2 (write-through).
    pub fn put(&mut self, content_hash: String, embedding: &[f32]) {
        self.l1.insert(content_hash.clone(), embedding.to_vec());
        self.l2.insert(content_hash, embedding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn miss_on_empty() {
        let coord = CacheCoordinator::new(100);
        let (result, tier) = coord.get("nonexistent");
        assert!(result.is_none());
        assert_eq!(tier, CacheHitTier::Miss);
    }

    #[test]
    fn l1_hit() {
        let coord = CacheCoordinator::new(100);
        coord.l1.insert("hash1".to_string(), vec![1.0, 2.0]);
        let (result, tier) = coord.get("hash1");
        assert_eq!(result, Some(vec![1.0, 2.0]));
        assert_eq!(tier, CacheHitTier::L1);
    }

    #[test]
    fn l2_hit_promotes_to_l1() {
        let mut coord = CacheCoordinator::new(100);
        coord.l2.insert("hash2".to_string(), &[3.0, 4.0]);

        let (result, tier) = coord.get("hash2");
        assert_eq!(result, Some(vec![3.0, 4.0]));
        assert_eq!(tier, CacheHitTier::L2);

        // Should now be in L1.
        let (result2, tier2) = coord.get("hash2");
        assert_eq!(result2, Some(vec![3.0, 4.0]));
        assert_eq!(tier2, CacheHitTier::L1);
    }

    #[test]
    fn l3_hit_promotes_to_l1() {
        let mut entries = HashMap::new();
        entries.insert("hash3".to_string(), vec![5.0, 6.0]);

        let mut coord = CacheCoordinator::new(100);
        coord.l3 = L3PrecomputedCache::load(entries);

        let (result, tier) = coord.get("hash3");
        assert_eq!(result, Some(vec![5.0, 6.0]));
        assert_eq!(tier, CacheHitTier::L3);

        // L3 is always checked first, so subsequent lookups still report L3.
        // But the value is also now in L1 for when L3 is unavailable.
        assert!(coord.l1.get("hash3").is_some());
    }

    #[test]
    fn put_writes_to_l1_and_l2() {
        let mut coord = CacheCoordinator::new(100);
        coord.put("hash4".to_string(), &[7.0, 8.0]);

        assert_eq!(coord.l1.get("hash4"), Some(vec![7.0, 8.0]));
        assert_eq!(coord.l2.get("hash4"), Some(vec![7.0, 8.0]));
    }
}

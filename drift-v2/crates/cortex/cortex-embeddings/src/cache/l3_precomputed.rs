//! L3 precomputed embedding cache.
//!
//! Memory-mapped precomputed embeddings for frequently-accessed content.
//! Loaded at startup, zero-latency lookups.

use std::collections::HashMap;

/// L3 precomputed embedding cache.
///
/// Stores a fixed set of embeddings loaded at startup. In production,
/// these would be memory-mapped from a binary file for zero-copy access.
/// For now, uses an in-memory HashMap populated during initialization.
pub struct L3PrecomputedCache {
    embeddings: HashMap<String, Vec<f32>>,
}

impl L3PrecomputedCache {
    /// Create an empty L3 cache.
    pub fn new() -> Self {
        Self {
            embeddings: HashMap::new(),
        }
    }

    /// Load precomputed embeddings from a map.
    ///
    /// In production, this would memory-map a binary file containing
    /// `(content_hash, embedding)` pairs serialized contiguously.
    pub fn load(entries: HashMap<String, Vec<f32>>) -> Self {
        Self {
            embeddings: entries,
        }
    }

    /// Look up a precomputed embedding by content hash.
    pub fn get(&self, content_hash: &str) -> Option<&Vec<f32>> {
        self.embeddings.get(content_hash)
    }

    /// Number of precomputed embeddings.
    pub fn len(&self) -> usize {
        self.embeddings.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.embeddings.is_empty()
    }
}

impl Default for L3PrecomputedCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_and_get() {
        let mut entries = HashMap::new();
        entries.insert("hash1".to_string(), vec![1.0, 2.0, 3.0]);
        entries.insert("hash2".to_string(), vec![4.0, 5.0, 6.0]);

        let cache = L3PrecomputedCache::load(entries);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("hash1"), Some(&vec![1.0, 2.0, 3.0]));
        assert!(cache.get("missing").is_none());
    }

    #[test]
    fn empty_cache() {
        let cache = L3PrecomputedCache::new();
        assert!(cache.is_empty());
        assert!(cache.get("anything").is_none());
    }
}

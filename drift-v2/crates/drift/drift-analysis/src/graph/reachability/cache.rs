//! LRU reachability cache with invalidation on graph changes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use drift_core::types::collections::FxHashMap;
use petgraph::graph::NodeIndex;

use super::types::{ReachabilityResult, TraversalDirection};

/// Cache key: (node, direction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKey {
    node: NodeIndex,
    direction: TraversalDirection,
}

/// Cached reachability entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    result: ReachabilityResult,
    generation: u64,
}

/// LRU reachability cache with generation-based invalidation.
///
/// When the graph is mutated (edge added/removed, node added/removed),
/// call `invalidate_node()` or `invalidate_all()` to clear stale entries.
pub struct ReachabilityCache {
    entries: Mutex<FxHashMap<CacheKey, CacheEntry>>,
    generation: AtomicU64,
    max_entries: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl ReachabilityCache {
    /// Create a new cache with the given maximum entry count.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(FxHashMap::default()),
            generation: AtomicU64::new(0),
            max_entries,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Look up a cached reachability result.
    pub fn get(&self, node: NodeIndex, direction: TraversalDirection) -> Option<ReachabilityResult> {
        let key = CacheKey { node, direction };
        let current_gen = self.generation.load(Ordering::Acquire);
        let entries = self.entries.lock().unwrap();

        if let Some(entry) = entries.get(&key) {
            if entry.generation == current_gen {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.result.clone());
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Store a reachability result in the cache.
    pub fn put(&self, result: ReachabilityResult, direction: TraversalDirection) {
        let key = CacheKey {
            node: result.source,
            direction,
        };
        let current_gen = self.generation.load(Ordering::Acquire);
        let mut entries = self.entries.lock().unwrap();

        // Evict if at capacity (simple: clear oldest half)
        if entries.len() >= self.max_entries {
            let to_remove: Vec<CacheKey> = entries
                .keys()
                .take(self.max_entries / 2)
                .copied()
                .collect();
            for k in to_remove {
                entries.remove(&k);
            }
        }

        entries.insert(key, CacheEntry {
            result,
            generation: current_gen,
        });
    }

    /// Invalidate cache entries for a specific node (both directions).
    pub fn invalidate_node(&self, node: NodeIndex) {
        let mut entries = self.entries.lock().unwrap();
        entries.remove(&CacheKey { node, direction: TraversalDirection::Forward });
        entries.remove(&CacheKey { node, direction: TraversalDirection::Inverse });

        // Also invalidate any entry whose reachable set contains this node
        let to_remove: Vec<CacheKey> = entries
            .iter()
            .filter(|(_, entry)| entry.result.reachable.contains(&node))
            .map(|(key, _)| *key)
            .collect();
        for k in to_remove {
            entries.remove(&k);
        }
    }

    /// Invalidate all cache entries (e.g., after a graph rebuild).
    pub fn invalidate_all(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Get cache hit count.
    pub fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Get cache miss count.
    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Get current number of entries.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }
}

//! Content-hash deduplication with TTL eviction.
//!
//! Prevents duplicate memories from being created when the same event
//! fires multiple times (e.g., rapid re-scans). Uses blake3 hash of
//! (event_type + entity_id + key fields). TTL: 60 seconds.
//! Capacity: 10,000 entries with LRU eviction.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// In-memory deduplication cache with TTL eviction.
pub struct EventDeduplicator {
    /// Map of content_hash → insertion time.
    seen: HashMap<String, Instant>,
    /// TTL for dedup entries.
    ttl: Duration,
    /// Maximum capacity before forced eviction.
    max_capacity: usize,
}

impl EventDeduplicator {
    /// Create a new deduplicator with default settings (60s TTL, 10k capacity).
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            ttl: Duration::from_secs(60),
            max_capacity: 10_000,
        }
    }

    /// Create a deduplicator with custom TTL and capacity.
    pub fn with_config(ttl: Duration, max_capacity: usize) -> Self {
        Self {
            seen: HashMap::new(),
            ttl,
            max_capacity,
        }
    }

    /// Check if an event is a duplicate. Returns true if duplicate (should skip).
    /// If not a duplicate, records the hash and returns false.
    pub fn is_duplicate(&mut self, event_type: &str, entity_id: &str, extra: &str) -> bool {
        let hash = compute_dedup_hash(event_type, entity_id, extra);
        self.is_duplicate_by_hash(&hash)
    }

    /// Check by pre-computed hash. Returns true if duplicate.
    pub fn is_duplicate_by_hash(&mut self, hash: &str) -> bool {
        let now = Instant::now();

        // Evict expired entries periodically (when at capacity)
        if self.seen.len() >= self.max_capacity {
            self.evict_expired(now);
        }

        // If still at capacity after eviction, evict oldest entries
        if self.seen.len() >= self.max_capacity {
            self.evict_oldest(self.max_capacity / 4);
        }

        // Check if we've seen this hash recently
        if let Some(inserted) = self.seen.get(hash) {
            if now.duration_since(*inserted) < self.ttl {
                return true; // Duplicate
            }
            // Expired — treat as new
        }

        // Record this hash
        self.seen.insert(hash.to_string(), now);
        false
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    /// Evict all entries older than TTL.
    fn evict_expired(&mut self, now: Instant) {
        self.seen.retain(|_, inserted| now.duration_since(*inserted) < self.ttl);
    }

    /// Evict the N oldest entries.
    fn evict_oldest(&mut self, count: usize) {
        if count == 0 || self.seen.is_empty() {
            return;
        }

        let mut entries: Vec<(String, Instant)> = self.seen.drain().collect();
        entries.sort_by_key(|(_, t)| *t);

        // Re-insert all except the oldest `count`
        for (hash, time) in entries.into_iter().skip(count) {
            self.seen.insert(hash, time);
        }
    }
}

impl Default for EventDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a dedup hash from event fields using blake3.
///
/// The `extra` field MUST include content-varying fields (score, severity, reason)
/// to prevent distinct events with the same entity_id from being deduplicated.
/// Callers should build extra as `"score=0.5;severity=high"` or similar.
pub fn compute_dedup_hash(event_type: &str, entity_id: &str, extra: &str) -> String {
    let input = format!("{}:{}:{}", event_type, entity_id, extra);
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

/// Build a dedup extra string from key-value pairs.
/// Ensures content-varying fields (score, severity, etc.) are included in the hash.
pub fn build_dedup_extra(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_event_not_duplicate() {
        let mut dedup = EventDeduplicator::new();
        assert!(!dedup.is_duplicate("on_pattern_approved", "p1", ""));
    }

    #[test]
    fn test_same_event_is_duplicate() {
        let mut dedup = EventDeduplicator::new();
        assert!(!dedup.is_duplicate("on_pattern_approved", "p1", ""));
        assert!(dedup.is_duplicate("on_pattern_approved", "p1", ""));
    }

    #[test]
    fn test_different_events_not_duplicate() {
        let mut dedup = EventDeduplicator::new();
        assert!(!dedup.is_duplicate("on_pattern_approved", "p1", ""));
        assert!(!dedup.is_duplicate("on_pattern_approved", "p2", ""));
        assert!(!dedup.is_duplicate("on_violation_fixed", "p1", ""));
    }

    #[test]
    fn test_ttl_expiry() {
        let mut dedup = EventDeduplicator::with_config(Duration::from_millis(10), 100);
        assert!(!dedup.is_duplicate("on_pattern_approved", "p1", ""));
        std::thread::sleep(Duration::from_millis(20));
        // After TTL, same event should not be duplicate
        assert!(!dedup.is_duplicate("on_pattern_approved", "p1", ""));
    }

    #[test]
    fn test_capacity_eviction() {
        let mut dedup = EventDeduplicator::with_config(Duration::from_secs(60), 10);
        for i in 0..20 {
            dedup.is_duplicate("event", &i.to_string(), "");
        }
        // Should not exceed max_capacity (may be less due to eviction)
        assert!(dedup.len() <= 10);
    }

    #[test]
    fn test_clear() {
        let mut dedup = EventDeduplicator::new();
        dedup.is_duplicate("event", "e1", "");
        assert_eq!(dedup.len(), 1);
        dedup.clear();
        assert_eq!(dedup.len(), 0);
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = compute_dedup_hash("on_pattern_approved", "p1", "");
        let h2 = compute_dedup_hash("on_pattern_approved", "p1", "");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_for_different_input() {
        let h1 = compute_dedup_hash("on_pattern_approved", "p1", "");
        let h2 = compute_dedup_hash("on_pattern_approved", "p2", "");
        assert_ne!(h1, h2);
    }
}

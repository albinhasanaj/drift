//! Session-aware deduplication: skip already-sent, merge duplicate candidates.

use std::collections::HashSet;

use crate::ranking::scorer::ScoredCandidate;

/// Deduplicate candidates:
/// 1. Remove memories already sent in this session (`sent_ids`).
/// 2. Remove duplicate memory IDs (keep highest-scored).
pub fn deduplicate(candidates: Vec<ScoredCandidate>, sent_ids: &[String]) -> Vec<ScoredCandidate> {
    let sent: HashSet<&str> = sent_ids.iter().map(|s| s.as_str()).collect();
    let mut seen: HashSet<String> = HashSet::new();

    candidates
        .into_iter()
        .filter(|c| {
            let id = &c.memory.id;
            // Skip already-sent memories.
            if sent.contains(id.as_str()) {
                return false;
            }
            // Skip duplicates (candidates are pre-sorted by score, so first wins).
            seen.insert(id.clone())
        })
        .collect()
}

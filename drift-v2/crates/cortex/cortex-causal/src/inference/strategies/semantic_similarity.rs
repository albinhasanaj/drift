//! Semantic similarity inference strategy (weight 0.3).
//! Uses pre-computed content hashes as a proxy for semantic similarity.
//! In production, this would use embedding cosine similarity.

use cortex_core::memory::BaseMemory;

/// Weight for this strategy in composite scoring.
pub const WEIGHT: f64 = 0.3;

/// Score semantic similarity between two memories.
/// Uses tag overlap and summary similarity as a lightweight proxy.
pub fn score(source: &BaseMemory, target: &BaseMemory) -> f64 {
    let tag_score = tag_overlap(source, target);
    let type_score = if source.memory_type == target.memory_type {
        0.3
    } else {
        0.0
    };
    let hash_score = if source.content_hash == target.content_hash {
        1.0
    } else {
        0.0
    };

    // Weighted combination of signals.
    (tag_score * 0.5 + type_score * 0.2 + hash_score * 0.3).min(1.0)
}

/// Jaccard similarity of tags.
fn tag_overlap(a: &BaseMemory, b: &BaseMemory) -> f64 {
    if a.tags.is_empty() && b.tags.is_empty() {
        return 0.0;
    }
    let set_a: std::collections::HashSet<&str> = a.tags.iter().map(|s| s.as_str()).collect();
    let set_b: std::collections::HashSet<&str> = b.tags.iter().map(|s| s.as_str()).collect();
    let intersection = set_a.intersection(&set_b).count() as f64;
    let union = set_a.union(&set_b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

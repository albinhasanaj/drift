//! Pattern matching inference strategy (weight 0.15).
//! Memories sharing linked patterns suggest causal relationships.

use cortex_core::memory::BaseMemory;

/// Weight for this strategy in composite scoring.
pub const WEIGHT: f64 = 0.15;

/// Score pattern-based causal inference.
pub fn score(source: &BaseMemory, target: &BaseMemory) -> f64 {
    if source.linked_patterns.is_empty() || target.linked_patterns.is_empty() {
        return 0.0;
    }

    let source_patterns: std::collections::HashSet<&str> = source
        .linked_patterns
        .iter()
        .map(|p| p.pattern_name.as_str())
        .collect();
    let target_patterns: std::collections::HashSet<&str> = target
        .linked_patterns
        .iter()
        .map(|p| p.pattern_name.as_str())
        .collect();

    let shared = source_patterns.intersection(&target_patterns).count();
    let total = source_patterns.union(&target_patterns).count();

    if total == 0 {
        return 0.0;
    }

    // Jaccard with a boost for multiple shared patterns.
    let jaccard = shared as f64 / total as f64;
    let multi_boost = if shared > 1 {
        0.1 * (shared - 1) as f64
    } else {
        0.0
    };

    (jaccard + multi_boost).min(1.0)
}

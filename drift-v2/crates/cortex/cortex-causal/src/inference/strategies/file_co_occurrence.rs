//! File co-occurrence inference strategy (weight 0.1).
//! Memories linked to the same files suggest a causal relationship.

use cortex_core::memory::BaseMemory;

/// Weight for this strategy in composite scoring.
pub const WEIGHT: f64 = 0.1;

/// Score file co-occurrence between two memories.
pub fn score(source: &BaseMemory, target: &BaseMemory) -> f64 {
    if source.linked_files.is_empty() || target.linked_files.is_empty() {
        return 0.0;
    }

    let source_files: std::collections::HashSet<&str> = source
        .linked_files
        .iter()
        .map(|f| f.file_path.as_str())
        .collect();
    let target_files: std::collections::HashSet<&str> = target
        .linked_files
        .iter()
        .map(|f| f.file_path.as_str())
        .collect();

    let shared = source_files.intersection(&target_files).count();
    let total = source_files.union(&target_files).count();

    if total == 0 {
        return 0.0;
    }

    shared as f64 / total as f64
}

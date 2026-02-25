//! Entity overlap inference strategy (weight 0.25).
//! Memories referencing the same files, functions, or patterns are likely related.

use cortex_core::memory::BaseMemory;

/// Weight for this strategy in composite scoring.
pub const WEIGHT: f64 = 0.25;

/// Score entity overlap between two memories.
pub fn score(source: &BaseMemory, target: &BaseMemory) -> f64 {
    let file_score = file_overlap(source, target);
    let function_score = function_overlap(source, target);
    let pattern_score = pattern_overlap(source, target);

    // Weighted combination.
    (file_score * 0.4 + function_score * 0.35 + pattern_score * 0.25).min(1.0)
}

fn file_overlap(a: &BaseMemory, b: &BaseMemory) -> f64 {
    if a.linked_files.is_empty() && b.linked_files.is_empty() {
        return 0.0;
    }
    let set_a: std::collections::HashSet<&str> = a
        .linked_files
        .iter()
        .map(|f| f.file_path.as_str())
        .collect();
    let set_b: std::collections::HashSet<&str> = b
        .linked_files
        .iter()
        .map(|f| f.file_path.as_str())
        .collect();
    jaccard(&set_a, &set_b)
}

fn function_overlap(a: &BaseMemory, b: &BaseMemory) -> f64 {
    if a.linked_functions.is_empty() && b.linked_functions.is_empty() {
        return 0.0;
    }
    let set_a: std::collections::HashSet<&str> = a
        .linked_functions
        .iter()
        .map(|f| f.function_name.as_str())
        .collect();
    let set_b: std::collections::HashSet<&str> = b
        .linked_functions
        .iter()
        .map(|f| f.function_name.as_str())
        .collect();
    jaccard(&set_a, &set_b)
}

fn pattern_overlap(a: &BaseMemory, b: &BaseMemory) -> f64 {
    if a.linked_patterns.is_empty() && b.linked_patterns.is_empty() {
        return 0.0;
    }
    let set_a: std::collections::HashSet<&str> = a
        .linked_patterns
        .iter()
        .map(|p| p.pattern_name.as_str())
        .collect();
    let set_b: std::collections::HashSet<&str> = b
        .linked_patterns
        .iter()
        .map(|p| p.pattern_name.as_str())
        .collect();
    jaccard(&set_a, &set_b)
}

fn jaccard(a: &std::collections::HashSet<&str>, b: &std::collections::HashSet<&str>) -> f64 {
    let intersection = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

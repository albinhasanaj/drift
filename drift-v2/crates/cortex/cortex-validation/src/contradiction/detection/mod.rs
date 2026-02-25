//! Contradiction detection strategy registry.
//!
//! 5 detection strategies that can be run against pairs of memories
//! to identify contradictions.

pub mod absolute_statement;
pub mod cross_pattern;
pub mod feedback;
pub mod semantic;
pub mod temporal_supersession;

use cortex_core::memory::BaseMemory;
use cortex_core::models::Contradiction;

/// Run all detection strategies against a pair of memories.
///
/// `embedding_similarity`: optional cosine similarity between the two memories'
/// embeddings. Pass `None` if embeddings are unavailable.
///
/// Returns the first (strongest) contradiction found, or `None`.
pub fn detect_all(
    a: &BaseMemory,
    b: &BaseMemory,
    embedding_similarity: Option<f64>,
) -> Option<Contradiction> {
    // Run strategies in order of specificity (most specific first).

    // 1. Absolute statement conflicts ("always X" vs "never X").
    if let Some(c) = absolute_statement::detect(a, b) {
        return Some(c);
    }

    // 2. Cross-pattern contradictions (same pattern, opposing content).
    if let Some(c) = cross_pattern::detect(a, b) {
        return Some(c);
    }

    // 3. Feedback contradictions.
    if let Some(c) = feedback::detect(a, b) {
        return Some(c);
    }

    // 4. Temporal supersession (newer replaces older on same topic).
    if let Some(c) = temporal_supersession::detect(a, b, embedding_similarity, 0.3) {
        return Some(c);
    }

    // 5. Semantic contradictions (embedding similarity + negation).
    if let Some(c) = semantic::detect(a, b, embedding_similarity) {
        return Some(c);
    }

    None
}

/// Run all detection strategies and collect ALL contradictions found.
pub fn detect_all_exhaustive(
    a: &BaseMemory,
    b: &BaseMemory,
    embedding_similarity: Option<f64>,
) -> Vec<Contradiction> {
    let mut results = Vec::new();

    if let Some(c) = absolute_statement::detect(a, b) {
        results.push(c);
    }
    if let Some(c) = cross_pattern::detect(a, b) {
        results.push(c);
    }
    if let Some(c) = feedback::detect(a, b) {
        results.push(c);
    }
    if let Some(c) = temporal_supersession::detect(a, b, embedding_similarity, 0.3) {
        results.push(c);
    }
    if let Some(c) = semantic::detect(a, b, embedding_similarity) {
        results.push(c);
    }

    results
}

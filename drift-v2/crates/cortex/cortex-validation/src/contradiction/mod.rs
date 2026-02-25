//! Contradiction detection, confidence propagation, and consensus.
//!
//! Multi-strategy contradiction detection with graph-based propagation
//! and consensus resistance.

pub mod consensus;
pub mod detection;
pub mod propagation;

use cortex_core::memory::{BaseMemory, RelationshipEdge};
use cortex_core::models::Contradiction;

/// Type alias for the embedding similarity lookup function.
pub type SimilarityFn<'a> = dyn Fn(&str, &str) -> Option<f64> + 'a;

/// The contradiction detector orchestrates all detection strategies,
/// propagation, and consensus checks.
pub struct ContradictionDetector;

impl ContradictionDetector {
    pub fn new() -> Self {
        Self
    }

    /// Detect contradictions among a set of memories.
    ///
    /// Runs all 5 detection strategies pairwise. For large sets, callers
    /// should pre-filter to related memories (same type, shared tags, etc.).
    ///
    /// `similarity_fn`: optional function that returns embedding cosine similarity
    /// between two memory IDs. Pass `None` to skip embedding-based detection.
    pub fn detect(
        &self,
        memories: &[BaseMemory],
        similarity_fn: Option<&SimilarityFn<'_>>,
    ) -> Vec<Contradiction> {
        let mut contradictions = Vec::new();

        for i in 0..memories.len() {
            for j in (i + 1)..memories.len() {
                let a = &memories[i];
                let b = &memories[j];

                let sim = similarity_fn.and_then(|f| f(&a.id, &b.id));

                if let Some(c) = detection::detect_all(a, b, sim) {
                    contradictions.push(c);
                }
            }
        }

        contradictions
    }

    /// Detect contradictions and compute confidence propagation.
    ///
    /// Returns contradictions and the resulting confidence adjustments
    /// that should be applied to the relationship graph.
    pub fn detect_and_propagate(
        &self,
        memories: &[BaseMemory],
        edges: &[RelationshipEdge],
        similarity_fn: Option<&SimilarityFn<'_>>,
    ) -> (Vec<Contradiction>, Vec<propagation::ConfidenceAdjustment>) {
        let contradictions = self.detect(memories, similarity_fn);

        let mut all_adjustments = Vec::new();
        for c in &contradictions {
            let adjustments =
                propagation::propagate(&c.memory_ids, c.contradiction_type, edges, None);
            all_adjustments.extend(adjustments);
        }

        (contradictions, all_adjustments)
    }
}

impl Default for ContradictionDetector {
    fn default() -> Self {
        Self::new()
    }
}

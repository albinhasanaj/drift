//! Causal inference engine: evaluates pairs of memories and infers causal relationships.

pub mod scorer;
pub mod strategies;

use cortex_core::memory::BaseMemory;

use crate::relations::CausalRelation;

/// Result of inference between two memories.
#[derive(Debug, Clone)]
pub struct InferenceResult {
    pub source_id: String,
    pub target_id: String,
    pub strength: f64,
    pub suggested_relation: CausalRelation,
    pub above_threshold: bool,
}

/// The inference engine evaluates memory pairs for causal relationships.
pub struct InferenceEngine {
    /// Minimum score to create an edge.
    threshold: f64,
}

impl InferenceEngine {
    pub fn new() -> Self {
        Self {
            threshold: scorer::DEFAULT_EDGE_THRESHOLD,
        }
    }

    pub fn with_threshold(threshold: f64) -> Self {
        Self { threshold }
    }

    /// Infer the causal relationship between two memories.
    pub fn infer(&self, source: &BaseMemory, target: &BaseMemory) -> InferenceResult {
        let strength = scorer::compute_composite(source, target);
        let suggested_relation = suggest_relation(source, target);

        InferenceResult {
            source_id: source.id.clone(),
            target_id: target.id.clone(),
            strength,
            suggested_relation,
            above_threshold: strength >= self.threshold,
        }
    }

    /// Infer relationships for a memory against a set of candidates.
    pub fn infer_batch(
        &self,
        source: &BaseMemory,
        candidates: &[BaseMemory],
    ) -> Vec<InferenceResult> {
        candidates
            .iter()
            .filter(|c| c.id != source.id)
            .map(|c| self.infer(source, c))
            .filter(|r| r.above_threshold)
            .collect()
    }

    /// Get the current threshold.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }
}

impl Default for InferenceEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Suggest the most likely relation type based on memory properties.
fn suggest_relation(source: &BaseMemory, target: &BaseMemory) -> CausalRelation {
    // Explicit supersession.
    if source.supersedes.as_deref() == Some(&target.id) {
        return CausalRelation::Supersedes;
    }

    // If source was created after target and references it, likely "derived_from".
    if source.transaction_time > target.transaction_time {
        // Same type suggests derivation.
        if source.memory_type == target.memory_type {
            return CausalRelation::DerivedFrom;
        }
        // Different type but close in time suggests "triggered_by".
        let delta = (source.transaction_time - target.transaction_time).num_seconds();
        if delta < 300 {
            return CausalRelation::TriggeredBy;
        }
    }

    // Default to "supports" as the weakest causal claim.
    CausalRelation::Supports
}

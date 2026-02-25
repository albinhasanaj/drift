//! IntentEngine: classify intent and apply memory type boosts.

pub mod classifier;
pub mod weight_matrix;

use cortex_core::intent::Intent;
use cortex_core::memory::MemoryType;
use cortex_core::models::RetrievalContext;

use weight_matrix::WeightMatrix;

/// Intent classification and weight boosting engine.
pub struct IntentEngine {
    matrix: WeightMatrix,
}

impl IntentEngine {
    pub fn new() -> Self {
        Self {
            matrix: WeightMatrix::default_weights(),
        }
    }

    /// Classify the intent from a retrieval context.
    pub fn classify(&self, context: &RetrievalContext) -> Intent {
        classifier::classify(context)
    }

    /// Get the boost multiplier for a memory type given the detected intent.
    pub fn boost(&self, intent: Intent, memory_type: MemoryType) -> f64 {
        self.matrix.boost(intent, memory_type)
    }
}

impl Default for IntentEngine {
    fn default() -> Self {
        Self::new()
    }
}

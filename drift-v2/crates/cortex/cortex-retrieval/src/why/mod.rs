//! WhySynthesizer: answers "why is it this way?" questions.

pub mod aggregator;
pub mod synthesizer;

use cortex_core::errors::CortexResult;
use cortex_core::models::WhyContext;
use cortex_core::traits::{ICausalStorage, IMemoryStorage};

/// Synthesizes WhyContext from storage and causal graph.
pub struct WhySynthesizer<'a> {
    storage: &'a dyn IMemoryStorage,
    causal: &'a dyn ICausalStorage,
}

impl<'a> WhySynthesizer<'a> {
    pub fn new(storage: &'a dyn IMemoryStorage, causal: &'a dyn ICausalStorage) -> Self {
        Self { storage, causal }
    }

    /// Synthesize a WhyContext for the given focus area.
    pub fn synthesize(&self, focus: &str, budget: usize) -> CortexResult<WhyContext> {
        synthesizer::synthesize(self.storage, self.causal, focus, budget)
    }
}

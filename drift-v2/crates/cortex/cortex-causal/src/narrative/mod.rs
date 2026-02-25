//! Narrative generation: template-based causal narratives with confidence scoring.

pub mod builder;
pub mod confidence;
pub mod templates;

use crate::graph::stable_graph::IndexedGraph;

pub use builder::{CausalNarrative, NarrativeSection};
pub use confidence::{chain_confidence, ConfidenceLevel};

/// Narrative generator wrapping the builder.
pub struct NarrativeGenerator;

impl NarrativeGenerator {
    /// Generate a causal narrative for a memory.
    pub fn generate(graph: &IndexedGraph, memory_id: &str) -> CausalNarrative {
        builder::build_narrative(graph, memory_id)
    }
}

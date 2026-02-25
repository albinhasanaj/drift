//! DecompositionPriorProvider trait — D1 compliant.
//!
//! No-op default returns empty vec (same pattern as DriftEventHandler).
//! In standalone mode, priors are empty and the algorithm falls back
//! to standard decomposition. The bridge (Phase 9) retrieves priors
//! from Cortex and passes them in.

/// Provider of decomposition priors from external sources.
///
/// Default implementation returns empty vec (no priors).
/// The Cortex bridge (Phase 9) implements this trait to provide
/// priors from similar projects.
pub trait DecompositionPriorProvider: Send + Sync {
    /// Get decomposition priors for the current project.
    /// Returns an empty vec by default (D1 compliance).
    fn get_priors(&self) -> Result<Vec<DecompositionPriorData>, String> {
        Ok(Vec::new())
    }
}

/// Prior data from an external source (Cortex bridge or other).
/// This is a drift-core type — no Cortex imports.
#[derive(Debug, Clone)]
pub struct DecompositionPriorData {
    /// The type of boundary adjustment.
    pub adjustment_type: PriorAdjustmentType,
    /// Confidence in this prior (0.0-1.0).
    pub confidence: f64,
    /// DNA similarity between source and target (0.0-1.0).
    pub dna_similarity: f64,
    /// Human-readable narrative.
    pub narrative: String,
    /// Source project DNA hash.
    pub source_dna_hash: String,
}

/// Type of boundary adjustment in a prior.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PriorAdjustmentType {
    Split { module: String, into: Vec<String> },
    Merge { modules: Vec<String>, into: String },
    Reclassify { module: String, new_category: String },
}

/// No-op implementation for standalone mode.
pub struct NoOpPriorProvider;

impl DecompositionPriorProvider for NoOpPriorProvider {}

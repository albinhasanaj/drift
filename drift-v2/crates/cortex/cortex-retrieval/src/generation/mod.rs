//! GenerationOrchestrator: context building, provenance, feedback, validation.

pub mod context_builder;
pub mod feedback;
pub mod gatherers;
pub mod provenance;
pub mod validation;

use cortex_core::errors::CortexResult;
use cortex_core::models::GenerationContext;
use cortex_core::traits::{ICompressor, IMemoryStorage};

use self::feedback::GenerationOutcome;
use self::provenance::ProvenanceRecord;
use self::validation::ValidationReport;

/// Orchestrates the full generation context pipeline:
/// 1. Pre-generation validation
/// 2. Context building with budget allocation
/// 3. Provenance tracking
/// 4. Feedback application
pub struct GenerationOrchestrator<'a> {
    storage: &'a dyn IMemoryStorage,
    compressor: &'a dyn ICompressor,
}

impl<'a> GenerationOrchestrator<'a> {
    pub fn new(storage: &'a dyn IMemoryStorage, compressor: &'a dyn ICompressor) -> Self {
        Self {
            storage,
            compressor,
        }
    }

    /// Validate, build context, and generate provenance in one call.
    pub fn build(
        &self,
        focus: &str,
        active_files: &[String],
        budget: usize,
    ) -> CortexResult<GenerationOutput> {
        // Step 1: Pre-generation validation.
        let validation = validation::validate_pre_generation(self.storage, focus)?;

        // Step 2: Build generation context.
        let context = context_builder::build_context(
            self.storage,
            self.compressor,
            focus,
            active_files,
            budget,
        )?;

        // Step 3: Generate provenance records.
        let provenance = provenance::generate_provenance(&context);

        // Step 4: Generate inline comments.
        let inline_comments = provenance::generate_inline_comments(&context);

        Ok(GenerationOutput {
            context,
            validation,
            provenance,
            inline_comments,
        })
    }

    /// Apply feedback from a generation outcome.
    pub fn apply_feedback(
        &self,
        memory_ids: &[String],
        outcome: GenerationOutcome,
    ) -> CortexResult<usize> {
        feedback::apply_feedback(self.storage, memory_ids, outcome)
    }
}

/// Complete output from the generation orchestrator.
#[derive(Debug)]
pub struct GenerationOutput {
    pub context: GenerationContext,
    pub validation: ValidationReport,
    pub provenance: Vec<ProvenanceRecord>,
    pub inline_comments: String,
}

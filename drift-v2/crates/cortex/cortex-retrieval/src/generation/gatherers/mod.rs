//! Gatherer trait + registry.
//!
//! Each gatherer specializes in collecting a specific category of memories
//! for generation context.

pub mod antipattern_gatherer;
pub mod constraint_gatherer;
pub mod pattern_gatherer;
pub mod tribal_gatherer;

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::traits::IMemoryStorage;

/// A gatherer collects memories of a specific category for generation context.
pub trait Gatherer: Send + Sync {
    /// The category name (e.g., "patterns", "tribal", "constraints", "antipatterns").
    fn category(&self) -> &'static str;

    /// Default budget allocation percentage for this category.
    fn default_percentage(&self) -> f64;

    /// Gather relevant memories for the given focus area.
    fn gather(
        &self,
        storage: &dyn IMemoryStorage,
        focus: &str,
        active_files: &[String],
        limit: usize,
    ) -> CortexResult<Vec<BaseMemory>>;
}

/// All registered gatherers in priority order.
pub fn all_gatherers() -> Vec<Box<dyn Gatherer>> {
    vec![
        Box::new(pattern_gatherer::PatternGatherer),
        Box::new(tribal_gatherer::TribalGatherer),
        Box::new(constraint_gatherer::ConstraintGatherer),
        Box::new(antipattern_gatherer::AntipatternGatherer),
    ]
}

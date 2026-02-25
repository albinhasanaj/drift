//! Grounding logic: compare Cortex memories against Drift scan results.
//! The killer feature (D7) — first AI memory system with empirically validated memory.

pub mod classification;
pub mod contradiction;
pub mod evidence;
pub mod loop_runner;
pub mod scheduler;
pub mod scorer;

pub use classification::{classify_groundability, Groundability};
pub use evidence::{EvidenceType, GroundingEvidence};
pub use loop_runner::GroundingLoopRunner;
pub use scheduler::{GroundingScheduler, TriggerType};
pub use scorer::GroundingScorer;

// Re-export GroundingConfig from config module for backward compatibility.
pub use crate::config::GroundingConfig;

// Re-export types from types module for backward compatibility.
// All existing `crate::grounding::GroundingResult` etc. imports work unchanged.
pub use crate::types::{
    AdjustmentMode, ConfidenceAdjustment, GroundingResult, GroundingSnapshot, GroundingVerdict,
};

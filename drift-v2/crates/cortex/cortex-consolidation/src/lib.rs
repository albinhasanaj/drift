//! # cortex-consolidation
//!
//! 6-phase consolidation pipeline: selection → clustering (HDBSCAN) → recall gate → abstraction → integration → pruning.
//! Quality monitoring with 5 core metrics and auto-tuning feedback loop.

pub mod algorithms;
pub mod engine;
pub mod llm_polish;
pub mod monitoring;
pub mod pipeline;
pub mod scheduling;

pub use engine::ConsolidationEngine;
pub use monitoring::{ConsolidationDashboard, QualityAssessment, TunableThresholds};
pub use scheduling::{evaluate_triggers, TriggerReason, TriggerSignals};

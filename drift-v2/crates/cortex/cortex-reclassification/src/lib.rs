//! # cortex-reclassification
//!
//! Monthly background task evaluating all memories for importance reclassification.
//! 5 signals: access frequency, retrieval rank, linked entities, contradictions, user feedback.
//! Safeguards: never auto-downgrade user-set critical, max 1 change/month, full audit trail.

pub mod engine;
pub mod rules;
pub mod safeguards;
pub mod signals;

pub use engine::{ReclassificationDecision, ReclassificationEngine, ReclassificationEvaluation};
pub use rules::{Direction, ReclassificationRule};
pub use safeguards::{ReclassificationRecord, SafeguardResult};
pub use signals::ReclassificationSignals;

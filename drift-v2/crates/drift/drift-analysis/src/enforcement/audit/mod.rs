//! Audit system — 5-factor health scoring, degradation detection, trend prediction.

pub mod types;
pub mod health_scorer;
pub mod degradation;
pub mod trends;
pub mod deduplication;
pub mod auto_approve;

pub use types::*;
pub use health_scorer::HealthScorer;
pub use degradation::DegradationDetector;
pub use trends::TrendAnalyzer;
pub use deduplication::DuplicateDetector;
pub use auto_approve::AutoApprover;

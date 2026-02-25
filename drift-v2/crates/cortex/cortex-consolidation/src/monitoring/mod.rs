//! Consolidation monitoring: quality metrics, auto-tuning, and dashboard.

pub mod auto_tuning;
pub mod dashboard;
pub mod metrics;

pub use auto_tuning::{TunableThresholds, TuningAdjustment};
pub use dashboard::ConsolidationDashboard;
pub use metrics::{assess_quality, QualityAssessment};

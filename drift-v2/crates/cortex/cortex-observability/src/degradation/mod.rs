//! Degradation tracking and alerting subsystem.

pub mod alerting;
pub mod tracker;

pub use alerting::{evaluate_alerts, AlertLevel, DegradationAlert};
pub use tracker::{DegradationTracker, RecoveryStatus, TrackedDegradation};

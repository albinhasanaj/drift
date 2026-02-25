//! Violation feedback loop — Tricorder-style FP tracking, auto-disable.

pub mod types;
pub mod tracker;
pub mod confidence_feedback;
pub mod stats_provider;

pub use types::*;
pub use tracker::FeedbackTracker;
pub use confidence_feedback::ConfidenceFeedback;
pub use stats_provider::FeedbackStatsProvider;

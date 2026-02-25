//! Bayesian Confidence Scoring — Beta distribution posteriors with 5-factor model.
//!
//! AD8: Beta(1+k, 1+n-k) posterior replaces static scoring.
//! Every confidence score in Drift flows through this system.

pub mod types;
pub mod beta;
pub mod factors;
pub mod momentum;
pub mod scorer;

pub use types::{ConfidenceScore, ConfidenceTier, MomentumDirection};
pub use scorer::{
    ConfidenceScorer, ScorerConfig, FeedbackStore, InMemoryFeedbackStore,
    ConfidenceDiagnostics, CategoryConfidenceSummary,
};
pub use beta::BetaPosterior;

//! Learning System — Bayesian convention discovery, 5 categories, auto-promotion.
//!
//! Discovers conventions from aggregated + scored patterns without configuration.
//! minOccurrences=3, dominance=0.60, minFiles=2.

pub mod types;
pub mod discovery;
pub mod promotion;
pub mod relearning;
pub mod dirichlet;
pub mod expiry;

pub use types::{
    Convention, ConventionCategory, ConventionScope, PromotionStatus, LearningConfig,
    ConventionStore, InMemoryConventionStore, LearningDiagnostics,
};
pub use discovery::ConventionDiscoverer;

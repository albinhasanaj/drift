//! Simulation Engine — Monte Carlo effort estimation.
//!
//! 13 task categories, 4 scorers, P10/P50/P90 confidence intervals,
//! 15 strategy recommendations.

pub mod types;
pub mod scorers;
pub mod monte_carlo;
pub mod strategies;

pub use types::*;
pub use scorers::{ComplexityScorer, RiskScorer, EffortScorer, ConfidenceScorer, Scorer};
pub use monte_carlo::MonteCarloSimulator;
pub use strategies::StrategyRecommender;

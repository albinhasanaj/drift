//! Adaptive weight system: decay, bounds enforcement, persistence.

pub mod bounds;
pub mod decay;

pub use bounds::{clamp_weight, normalize_weights, MAX_WEIGHT, MIN_WEIGHT};
pub use decay::decay_weight;

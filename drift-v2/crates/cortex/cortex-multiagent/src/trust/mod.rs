//! Trust scoring for multi-agent memory.
//!
//! Computes and manages trust scores between agents based on accumulated
//! evidence (validations, contradictions, usage). Supports trust decay
//! toward neutral and bootstrap for new/spawned agents.
//!
//! ## Modules
//!
//! - [`scorer`] — Compute and manage trust scores
//! - [`evidence`] — Accumulate trust evidence from interactions
//! - [`decay`] — Trust decay toward neutral (0.5)
//! - [`bootstrap`] — Initial trust for new and spawned agents

pub mod bootstrap;
pub mod decay;
pub mod evidence;
pub mod scorer;

pub use bootstrap::{bootstrap_from_parent, bootstrap_trust};
pub use decay::apply_trust_decay;
pub use evidence::TrustEvidenceTracker;
pub use scorer::TrustScorer;

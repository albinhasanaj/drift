//! # cortex-causal
//!
//! The "why" engine. Maintains an in-memory DAG (`petgraph`) synced with `SQLite`.
//! Causal inference, traversal, counterfactual queries, and narrative generation.

pub mod engine;
pub mod graph;
pub mod inference;
pub mod narrative;
pub mod relations;
pub mod traversal;

pub use engine::CausalEngine;
pub use graph::GraphManager;
pub use inference::InferenceEngine;
pub use narrative::{CausalNarrative, NarrativeGenerator};
pub use relations::CausalRelation;
pub use traversal::{TraversalConfig, TraversalEngine, TraversalResult};

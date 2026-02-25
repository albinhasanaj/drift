//! Reachability analysis — forward/inverse BFS with auto-select engine.
//!
//! Auto-selects petgraph (in-memory) for <10K nodes, SQLite CTE for ≥10K nodes.
//! Includes sensitivity classification, LRU caching, cross-service reachability,
//! and field-level data flow tracking.

pub mod types;
pub mod bfs;
pub mod sensitivity;
pub mod cache;
pub mod cross_service;
pub mod field_flow;

pub use types::*;
pub use bfs::{reachability_forward, reachability_inverse, auto_select_engine};
pub use sensitivity::classify_sensitivity;
pub use cache::ReachabilityCache;

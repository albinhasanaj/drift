//! Cross-namespace consolidation and consensus detection for multi-agent memory.
//!
//! ## Modules
//!
//! - [`consensus`] — Detect independently corroborated knowledge across agents
//! - [`cross_namespace`] — Extend consolidation pipeline across namespaces

pub mod consensus;
pub mod cross_namespace;

pub use consensus::{ConsensusCandidate, ConsensusDetector};
pub use cross_namespace::CrossNamespaceConsolidator;

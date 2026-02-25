//! Pattern Aggregation & Deduplication — 7-phase pipeline.
//!
//! Transforms per-file pattern matches into project-level aggregated patterns
//! with deduplication, Jaccard similarity, MinHash LSH, hierarchy building,
//! counter reconciliation, and gold layer refresh.

pub mod types;
pub mod grouper;
pub mod similarity;
pub mod hierarchy;
pub mod reconciliation;
pub mod gold_layer;
pub mod incremental;
pub mod pipeline;

pub use types::{AggregatedPattern, PatternLocation, MergeCandidate, MergeDecision, PatternHierarchy};
pub use pipeline::{AggregationPipeline, AggregationResult, AggregationDiagnostics};
pub use similarity::{jaccard_similarity, MinHashIndex};
pub use grouper::PatternGrouper;

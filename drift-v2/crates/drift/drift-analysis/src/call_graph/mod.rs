//! Call Graph Builder — petgraph StableGraph, 6 resolution strategies, SQLite CTE fallback.
//!
//! Performance targets: Build <5s for 10K files, BFS <5ms, SQLite CTE <50ms.

pub mod types;
pub mod builder;
pub mod resolution;
pub mod traversal;
pub mod cte_fallback;
pub mod incremental;
pub mod di_support;
pub mod tsconfig;
pub mod framework_detection;

pub use types::{CallGraph, FunctionNode, CallEdge, Resolution, CallGraphStats};
pub use builder::CallGraphBuilder;
pub use resolution::{ResolutionDiagnostics, is_fuzzy_blocked, resolve_call, resolve_constructor};
pub use traversal::{bfs_forward, bfs_inverse, detect_entry_points, mark_entry_points_with_root};
pub use incremental::IncrementalCallGraph;
pub use tsconfig::{TsConfigPaths, AliasRule, resolve_alias};
pub use framework_detection::{
    detect_framework_patterns, DetectedRoute, DetectedEvent, EventKind, FrameworkDetectionResult,
};

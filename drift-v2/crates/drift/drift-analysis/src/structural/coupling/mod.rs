//! Coupling Analysis (System 19) — Robert C. Martin metrics, Tarjan's SCC, zone classification.
//!
//! Computes Ce (efferent), Ca (afferent), I (instability), A (abstractness),
//! D (distance from main sequence) per module. Detects dependency cycles via
//! Tarjan's SCC and suggests cycle-breaking edges.

pub mod types;
pub mod import_graph;
pub mod martin_metrics;
pub mod cycle_detection;
pub mod zones;

pub use types::*;
pub use import_graph::ImportGraphBuilder;
pub use martin_metrics::compute_martin_metrics;
pub use cycle_detection::detect_cycles;
pub use zones::classify_zone;

//! Graph intelligence systems — Level 2B analysis consuming the call graph.
//!
//! Five independent subsystems:
//! - **Reachability** — Forward/inverse BFS, auto-select engine, sensitivity classification
//! - **Taint** — Source/sink/sanitizer model, 17 CWE categories, SARIF output
//! - **Error Handling** — 8-phase topology engine, 20+ framework support
//! - **Impact** — Blast radius, dead code detection, path finding
//! - **Test Topology** — Coverage mapping, 24 smell detectors, quality scoring

pub mod reachability;
pub mod taint;
pub mod error_handling;
pub mod impact;
pub mod test_topology;

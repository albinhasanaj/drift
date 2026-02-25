//! NAPI-exported binding modules.
//!
//! Phase 1 exposes lifecycle and scanner bindings.
//! Phase 2 adds analysis, call graph, and boundary bindings.

pub mod lifecycle;
pub mod scanner;
pub mod analysis;
pub mod patterns;
pub mod graph;
pub mod structural;
pub mod enforcement;
pub mod feedback;
pub mod advanced;
pub mod bridge;
pub mod cloud;

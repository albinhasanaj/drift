//! Provenance tracking for multi-agent memory.
//!
//! Records the origin and chain of custody for every memory as it flows
//! between agents. Supports correction propagation with exponential dampening
//! and cross-agent tracing.
//!
//! ## Modules
//!
//! - [`tracker`] — Record and query provenance chains
//! - [`correction`] — Propagate corrections through provenance chains
//! - [`cross_agent`] — Trace knowledge across agent boundaries

pub mod correction;
pub mod cross_agent;
pub mod tracker;

pub use correction::CorrectionPropagator;
pub use cross_agent::CrossAgentTracer;
pub use tracker::ProvenanceTracker;

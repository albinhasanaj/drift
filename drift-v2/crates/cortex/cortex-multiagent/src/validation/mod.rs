//! Cross-agent validation for multi-agent memory.
//!
//! ## Modules
//!
//! - [`cross_agent`] — Detect and resolve contradictions between agents

pub mod cross_agent;

pub use cross_agent::CrossAgentValidator;

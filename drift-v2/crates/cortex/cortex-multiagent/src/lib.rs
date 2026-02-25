//! # cortex-multiagent
//!
//! Multi-agent memory orchestration for the Cortex memory system.
//! Provides agent registration, namespace isolation, memory projections with
//! filtering, share/promote/retract operations, provenance tracking, trust
//! scoring, and delta sync.
//!
//! ## Modules
//!
//! - [`engine`] — `MultiAgentEngine` implementing `IMultiAgentEngine`
//! - [`registry`] — Agent lifecycle management
//! - [`namespace`] — Namespace CRUD, permissions, URI addressing
//! - [`projection`] — Filtered views between namespaces
//! - [`share`] — Share, promote, retract operations
//! - [`provenance`] — Provenance tracking, correction propagation, cross-agent tracing
//! - [`trust`] — Trust scoring, evidence tracking, decay, bootstrap
//! - [`sync`] — Delta sync protocol, causal delivery, cloud integration

pub mod consolidation;
pub mod engine;
pub mod namespace;
pub mod projection;
pub mod provenance;
pub mod registry;
pub mod share;
pub mod sync;
pub mod trust;
pub mod validation;

pub use engine::MultiAgentEngine;

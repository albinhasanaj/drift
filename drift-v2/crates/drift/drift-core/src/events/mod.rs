//! Event system for Drift.
//! Trait with no-op defaults, synchronous dispatch, zero overhead when empty.

pub mod dispatcher;
pub mod handler;
pub mod types;

pub use dispatcher::EventDispatcher;
pub use handler::DriftEventHandler;

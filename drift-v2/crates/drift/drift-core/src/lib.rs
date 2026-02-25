//! # drift-core
//!
//! Foundation crate for the Drift analysis engine.
//! Defines all types, traits, errors, config, events, tracing, and constants.
//! Every other crate in the workspace depends on this.

// PH4-03: Blanket dead_code/unused suppression removed. Add targeted #[allow] on specific items if needed.

pub mod config;
pub mod constants;
pub mod errors;
pub mod events;
pub mod licensing;
pub mod telemetry;
pub mod tracing;
pub mod traits;
pub mod types;
pub mod workspace;

// Re-export the most commonly used types at the crate root.
pub use config::DriftConfig;
pub use errors::error_code::DriftErrorCode;
pub use events::dispatcher::EventDispatcher;
pub use events::handler::DriftEventHandler;
pub use types::collections::{FxHashMap, FxHashSet};
pub use types::identifiers::{ClassId, DetectorId, FileId, FunctionId, ModuleId, PatternId};
pub use types::interning::{FunctionInterner, PathInterner};

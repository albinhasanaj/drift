//! Error handling for Drift.
//! One error enum per subsystem, `thiserror` only, zero `anyhow`.

pub mod boundary_error;
pub mod call_graph_error;
pub mod config_error;
pub mod constraint_error;
pub mod context_error;
pub mod detection_error;
pub mod error_code;
pub mod gate_error;
pub mod napi_error;
pub mod parse_error;
pub mod pipeline_error;
pub mod scan_error;
pub mod storage_error;
pub mod taint_error;

pub use boundary_error::BoundaryError;
pub use call_graph_error::CallGraphError;
pub use config_error::ConfigError;
pub use constraint_error::ConstraintError;
pub use context_error::ContextError;
pub use detection_error::DetectionError;
pub use error_code::DriftErrorCode;
pub use gate_error::GateError;
pub use napi_error::NapiError;
pub use parse_error::ParseError;
pub use pipeline_error::{PipelineError, PipelineResult};
pub use scan_error::ScanError;
pub use storage_error::StorageError;
pub use taint_error::TaintError;

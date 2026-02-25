//! DriftError → napi::Error conversion with structured `[ERROR_CODE] message` strings.
//!
//! Every Drift error enum converts to a NAPI error with a code prefix.
//! The TS client parses the code from the message format: `[ERROR_CODE] Human-readable message`.
//!
//! Pattern reference: `cortex-napi/src/conversions/error_types.rs`

use drift_core::errors::error_code::DriftErrorCode;
use napi::Status;

// ---- Error code constants ----

// Lifecycle
pub const INIT_ERROR: &str = "INIT_ERROR";
pub const ALREADY_INITIALIZED: &str = "ALREADY_INITIALIZED";
pub const RUNTIME_NOT_INITIALIZED: &str = "RUNTIME_NOT_INITIALIZED";
pub const CONFIG_ERROR: &str = "CONFIG_ERROR";

// Scanner
pub const SCAN_ERROR: &str = "SCAN_ERROR";
pub const SCAN_CANCELLED: &str = "SCAN_CANCELLED";
pub const FILE_TOO_LARGE: &str = "FILE_TOO_LARGE";
pub const PERMISSION_DENIED: &str = "PERMISSION_DENIED";

// Parser
pub const PARSE_ERROR: &str = "PARSE_ERROR";
pub const UNSUPPORTED_LANGUAGE: &str = "UNSUPPORTED_LANGUAGE";
pub const QUERY_COMPILATION: &str = "QUERY_COMPILATION";

// Storage
pub const STORAGE_ERROR: &str = "STORAGE_ERROR";
pub const DB_BUSY: &str = "DB_BUSY";
pub const DB_CORRUPT: &str = "DB_CORRUPT";
pub const DB_DISK_FULL: &str = "DB_DISK_FULL";
pub const MIGRATION_FAILED: &str = "MIGRATION_FAILED";
pub const LOCK_POISONED: &str = "LOCK_POISONED";

// Analysis
pub const ANALYSIS_ERROR: &str = "ANALYSIS_ERROR";
pub const CALL_GRAPH_ERROR: &str = "CALL_GRAPH_ERROR";
pub const DETECTION_ERROR: &str = "DETECTION_ERROR";
pub const BOUNDARY_ERROR: &str = "BOUNDARY_ERROR";
pub const TAINT_ERROR: &str = "TAINT_ERROR";
pub const CONSTRAINT_ERROR: &str = "CONSTRAINT_ERROR";

// Query
pub const NOT_FOUND: &str = "NOT_FOUND";
pub const INVALID_CURSOR: &str = "INVALID_CURSOR";
pub const INVALID_FILTER: &str = "INVALID_FILTER";

// General
pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
pub const CANCELLED: &str = "CANCELLED";
pub const INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";

/// Convert any Drift error implementing `DriftErrorCode + Display` to a structured NAPI error.
///
/// Output format: `[ERROR_CODE] Human-readable message`
pub fn to_napi_error(err: impl std::fmt::Display + DriftErrorCode) -> napi::Error {
    let code = err.error_code();
    napi::Error::new(Status::GenericFailure, format!("[{code}] {err}"))
}

/// Convert a `drift_core::errors::ScanError` to a NAPI error.
pub fn scan_error(err: drift_core::errors::ScanError) -> napi::Error {
    to_napi_error(err)
}

/// Convert a `drift_core::errors::ParseError` to a NAPI error.
pub fn parse_error(err: drift_core::errors::ParseError) -> napi::Error {
    to_napi_error(err)
}

/// Convert a `drift_core::errors::StorageError` to a NAPI error.
pub fn storage_error(err: drift_core::errors::StorageError) -> napi::Error {
    to_napi_error(err)
}

/// Convert a `drift_core::errors::ConfigError` to a NAPI error.
pub fn config_error(err: drift_core::errors::ConfigError) -> napi::Error {
    to_napi_error(err)
}

/// Create a "runtime not initialized" error.
pub fn runtime_not_initialized() -> napi::Error {
    napi::Error::new(
        Status::GenericFailure,
        format!(
            "[{RUNTIME_NOT_INITIALIZED}] DriftRuntime not initialized. Call driftInitialize() first."
        ),
    )
}

/// Create an internal error with a custom message.
pub fn internal_error(msg: impl std::fmt::Display) -> napi::Error {
    napi::Error::new(
        Status::GenericFailure,
        format!("[{INTERNAL_ERROR}] {msg}"),
    )
}

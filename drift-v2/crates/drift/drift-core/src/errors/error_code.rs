//! DriftErrorCode trait for NAPI conversion.

/// Trait for converting Drift errors to NAPI error codes.
/// Every error enum must implement this to provide a structured
/// error code string for TypeScript consumption.
pub trait DriftErrorCode {
    /// Returns the NAPI error code string (e.g., "SCAN_ERROR").
    fn error_code(&self) -> &'static str;

    /// Returns the formatted NAPI error string: `[ERROR_CODE] message`.
    fn napi_string(&self) -> String
    where
        Self: std::fmt::Display,
    {
        format!("[{}] {}", self.error_code(), self)
    }
}

// Error code constants for NAPI boundary.
pub const SCAN_ERROR: &str = "SCAN_ERROR";
pub const PARSE_ERROR: &str = "PARSE_ERROR";
pub const DB_BUSY: &str = "DB_BUSY";
pub const DB_CORRUPT: &str = "DB_CORRUPT";
pub const CANCELLED: &str = "CANCELLED";
pub const UNSUPPORTED_LANGUAGE: &str = "UNSUPPORTED_LANGUAGE";
pub const DETECTION_ERROR: &str = "DETECTION_ERROR";
pub const CALL_GRAPH_ERROR: &str = "CALL_GRAPH_ERROR";
pub const CONFIG_ERROR: &str = "CONFIG_ERROR";
pub const LICENSE_ERROR: &str = "LICENSE_ERROR";
pub const GATE_FAILED: &str = "GATE_FAILED";
pub const STORAGE_ERROR: &str = "STORAGE_ERROR";
pub const DISK_FULL: &str = "DISK_FULL";
pub const MIGRATION_FAILED: &str = "MIGRATION_FAILED";
pub const TAINT_ERROR: &str = "TAINT_ERROR";
pub const CONSTRAINT_ERROR: &str = "CONSTRAINT_ERROR";
pub const BOUNDARY_ERROR: &str = "BOUNDARY_ERROR";
pub const PIPELINE_ERROR: &str = "PIPELINE_ERROR";

//! Structured span field definitions for Drift metrics.
//!
//! These constants define the standard field names used in tracing spans
//! across all Drift subsystems. Using consistent field names enables
//! structured log queries and dashboard construction.

/// Scanner: files processed per second.
pub const SCAN_FILES_PER_SECOND: &str = "scan_files_per_second";

/// Scanner/Parser: cache hit rate (0.0 - 1.0).
pub const CACHE_HIT_RATE: &str = "cache_hit_rate";

/// Parser: parse time per language in milliseconds.
pub const PARSE_TIME_PER_LANGUAGE: &str = "parse_time_per_language";

/// NAPI Bridge: serialization time in milliseconds.
pub const NAPI_SERIALIZATION_TIME: &str = "napi_serialization_time";

/// Detectors: detection time per category in milliseconds.
pub const DETECTION_TIME_PER_CATEGORY: &str = "detection_time_per_category";

/// Storage: batch write time in milliseconds.
pub const BATCH_WRITE_TIME: &str = "batch_write_time";

/// Call Graph: graph construction time in milliseconds.
pub const CALL_GRAPH_BUILD_TIME: &str = "call_graph_build_time";

/// Confidence: Bayesian scoring computation time in milliseconds.
pub const CONFIDENCE_COMPUTE_TIME: &str = "confidence_compute_time";

/// Quality Gates: gate evaluation time in milliseconds.
pub const GATE_EVALUATION_TIME: &str = "gate_evaluation_time";

/// MCP: response time in milliseconds.
pub const MCP_RESPONSE_TIME: &str = "mcp_response_time";

/// Scanner: file discovery phase duration in milliseconds.
pub const DISCOVERY_DURATION: &str = "discovery_duration";

/// Scanner: content hashing phase duration in milliseconds.
pub const HASHING_DURATION: &str = "hashing_duration";

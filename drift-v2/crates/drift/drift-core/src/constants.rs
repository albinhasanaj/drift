//! Shared constants for the Drift analysis engine.

/// Drift version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum file size in bytes for scanning (default: 1MB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1_048_576;

/// Default number of threads (0 = auto-detect).
pub const DEFAULT_THREADS: usize = 0;

/// Default minimum occurrences for pattern discovery.
pub const DEFAULT_MIN_OCCURRENCES: u32 = 3;

/// Default dominance threshold for convention detection.
pub const DEFAULT_DOMINANCE_THRESHOLD: f64 = 0.60;

/// Default minimum files for pattern consideration.
pub const DEFAULT_MIN_FILES: u32 = 2;

/// Default re-learning threshold (% files changed).
pub const DEFAULT_RELEARN_THRESHOLD: f64 = 0.10;

/// Default quality gate minimum score (0-100).
pub const DEFAULT_MIN_SCORE: u32 = 70;

/// Default MCP max response tokens.
pub const DEFAULT_MAX_RESPONSE_TOKENS: u32 = 8000;

/// Default MCP cache TTL in seconds.
pub const DEFAULT_CACHE_TTL_SECONDS: u64 = 300;

/// Default max operational backups.
pub const DEFAULT_MAX_OPERATIONAL_BACKUPS: u32 = 5;

/// Default max daily backups.
pub const DEFAULT_MAX_DAILY_BACKUPS: u32 = 7;

/// Default quality gate fail level.
pub const DEFAULT_FAIL_ON: &str = "error";

/// Default hash algorithm.
pub const DEFAULT_HASH_ALGORITHM: &str = "xxh3";

// ---- Performance Targets ----

/// Target: scan 10K files in <300ms on Linux.
pub const PERF_SCAN_10K_LINUX_MS: u64 = 300;

/// Target: scan 10K files in <500ms on macOS.
pub const PERF_SCAN_10K_MACOS_MS: u64 = 500;

/// Target: scan 100K files in <3s cold.
pub const PERF_SCAN_100K_COLD_MS: u64 = 3000;

/// Target: scan 100K files in <1.5s incremental.
pub const PERF_SCAN_100K_INCREMENTAL_MS: u64 = 1500;

/// Target: parse 10K files in <5s.
pub const PERF_PARSE_10K_MS: u64 = 5000;

/// Batch writer batch size.
pub const BATCH_WRITE_SIZE: usize = 500;

/// Batch writer channel capacity.
pub const BATCH_CHANNEL_CAPACITY: usize = 1024;

/// Batch writer recv timeout in milliseconds.
pub const BATCH_RECV_TIMEOUT_MS: u64 = 100;

// ---- Feature Flags ----

/// Feature flag: OpenTelemetry support.
pub const FEATURE_OTEL: &str = "otel";

/// Feature flag: Cortex bridge integration.
pub const FEATURE_CORTEX: &str = "cortex";

/// Feature flag: MCP server support.
pub const FEATURE_MCP: &str = "mcp";

/// Feature flag: WASM target support.
pub const FEATURE_WASM: &str = "wasm";

// ---- Supported Languages ----

/// Number of supported languages.
pub const SUPPORTED_LANGUAGE_COUNT: usize = 10;

/// Supported language names.
pub const SUPPORTED_LANGUAGES: [&str; SUPPORTED_LANGUAGE_COUNT] = [
    "typescript",
    "javascript",
    "python",
    "java",
    "csharp",
    "go",
    "rust",
    "ruby",
    "php",
    "kotlin",
];

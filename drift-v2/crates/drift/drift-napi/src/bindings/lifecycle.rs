//! Lifecycle bindings: `drift_initialize()` and `drift_shutdown()`.
//!
//! `drift_initialize()` creates drift.db, sets PRAGMAs, runs migrations,
//! and initializes the DriftRuntime singleton.
//!
//! `drift_shutdown()` cleanly closes all connections and flushes caches.

use std::path::PathBuf;

use napi_derive::napi;

use crate::conversions::error_codes;
use crate::runtime::{self, RuntimeOptions};

/// Initialize the Drift analysis engine.
///
/// Creates the database (drift.db), applies SQLite PRAGMAs (WAL mode,
/// synchronous=NORMAL, 64MB page cache), runs schema migrations, and
/// initializes the global DriftRuntime singleton.
///
/// Must be called exactly once before any other drift_* function.
/// Subsequent calls return an ALREADY_INITIALIZED error.
///
/// @param db_path - Optional path to drift.db. Defaults to `.drift/drift.db`.
/// @param project_root - Optional project root for scanning and config resolution.
/// @param config_toml - Optional TOML configuration string. Overrides file-based config.
/// @param cortex_db_path - Optional path to cortex.db. When provided and the file
///   exists, bridge memories are dual-written to cortex.db for Cortex retrieval.
#[napi(js_name = "driftInitialize")]
pub fn drift_initialize(
    db_path: Option<String>,
    project_root: Option<String>,
    config_toml: Option<String>,
    cortex_db_path: Option<String>,
) -> napi::Result<()> {
    let opts = RuntimeOptions {
        db_path: db_path.map(PathBuf::from),
        project_root: project_root.map(PathBuf::from),
        config_toml,
        bridge_db_path: None,
        cortex_db_path: cortex_db_path.map(PathBuf::from),
    };

    runtime::initialize(opts)
}

/// Shut down the Drift analysis engine.
///
/// Performs a WAL checkpoint (TRUNCATE mode) to consolidate the write-ahead log,
/// then drops the runtime. After this call, all drift_* functions will return
/// RUNTIME_NOT_INITIALIZED until `driftInitialize()` is called again.
///
/// Note: Because `OnceLock` cannot be reset, shutdown performs cleanup but the
/// runtime reference remains. In practice, shutdown is called once at process exit.
#[napi(js_name = "driftShutdown")]
pub fn drift_shutdown() -> napi::Result<()> {
    let rt = runtime::get()?;

    // Checkpoint WAL to consolidate the write-ahead log
    rt.storage.checkpoint().map_err(|e| {
        napi::Error::from_reason(format!("[{}] WAL checkpoint failed: {e}", error_codes::STORAGE_ERROR))
    })?;

    Ok(())
}

/// Check if the Drift runtime is initialized.
///
/// Returns true if `driftInitialize()` has been called successfully.
#[napi(js_name = "driftIsInitialized")]
pub fn drift_is_initialized() -> bool {
    runtime::is_initialized()
}

/// Run garbage collection and data retention on drift.db.
///
/// Applies tiered retention policy:
/// - **Orphan cleanup**: removes data for files no longer tracked
/// - **Short (30d)**: detections, violations, findings
/// - **Medium (90d)**: trends, feedback, history
/// - **Long (365d)**: caches, decisions
///
/// Follows with incremental vacuum to reclaim disk space.
///
/// @param short_days - Override short retention period (default 30).
/// @param medium_days - Override medium retention period (default 90).
/// @param long_days - Override long retention period (default 365).
#[napi(js_name = "driftGC")]
pub fn drift_gc(
    short_days: Option<u32>,
    medium_days: Option<u32>,
    long_days: Option<u32>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;

    let policy = drift_storage::retention::RetentionPolicy {
        short_days: short_days.unwrap_or(30),
        medium_days: medium_days.unwrap_or(90),
        long_days: long_days.unwrap_or(365),
    };

    let retention_report = rt.storage.with_writer(|conn| {
        drift_storage::retention::apply_retention(conn, &policy)
    }).map_err(|e| {
        napi::Error::from_reason(format!(
            "[{}] Retention cleanup failed: {e}",
            error_codes::STORAGE_ERROR
        ))
    })?;

    // Incremental vacuum to reclaim space
    let _ = rt.storage.with_writer(|conn| -> Result<(), drift_core::errors::StorageError> {
        conn.execute_batch("PRAGMA incremental_vacuum")
            .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
        Ok(())
    });

    Ok(serde_json::json!({
        "total_deleted": retention_report.total_deleted,
        "duration_ms": retention_report.duration_ms,
        "per_table": retention_report.per_table.iter().map(|t| {
            serde_json::json!({ "table": t.table, "deleted": t.deleted })
        }).collect::<Vec<_>>(),
    }))
}

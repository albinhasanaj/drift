//! Lifecycle bindings: initialize, shutdown, configure.

use napi_derive::napi;
use std::path::PathBuf;

use crate::runtime::{self, RuntimeOptions};

/// Initialize the Cortex runtime.
///
/// Must be called before any other Cortex function.
/// `db_path`: optional path to SQLite database (null for in-memory).
/// `config_toml`: optional TOML configuration string.
/// `cloud_enabled`: whether to enable cloud sync.
#[napi]
pub fn cortex_initialize(
    db_path: Option<String>,
    config_toml: Option<String>,
    cloud_enabled: Option<bool>,
) -> napi::Result<()> {
    runtime::initialize(RuntimeOptions {
        db_path: db_path.map(PathBuf::from),
        config_toml,
        cloud_enabled: cloud_enabled.unwrap_or(false),
    })
}

/// Graceful shutdown of the Cortex runtime.
///
/// C-13: Flushes WAL to the main database file (TRUNCATE checkpoint),
/// ensuring all data is durable before process exit.
#[napi]
pub fn cortex_shutdown() -> napi::Result<()> {
    let rt = runtime::get()?;

    // F-01/F-02/F-03: Persist observability metrics snapshot before shutdown.
    if let Ok(mut obs) = rt.observability.lock() {
        if let Ok(snapshot) = obs.metrics_snapshot() {
            let _ = rt.storage.pool().writer.with_conn_sync(|conn| {
                cortex_storage::temporal_events::emit_event(
                    conn,
                    "system",
                    "metrics_snapshot",
                    &snapshot,
                    "system",
                    "shutdown",
                )
            });
        }
        obs.reset_metrics();
    }

    // Checkpoint WAL if file-backed (no-op for in-memory).
    if rt.storage.pool().db_path.is_some() {
        rt.storage.pool().writer.with_conn_sync(|conn| {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|e| {
                    cortex_core::errors::CortexError::StorageError(
                        cortex_core::errors::StorageError::SqliteError {
                            message: format!("WAL checkpoint failed: {e}"),
                        },
                    )
                })
        }).map_err(|e| napi::Error::from_reason(format!("Shutdown checkpoint failed: {e}")))?;
    }

    Ok(())
}

/// Update runtime configuration.
///
/// Returns the current configuration as JSON.
#[napi]
pub fn cortex_configure(config_toml: Option<String>) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    // If a new config is provided, we can't hot-swap engines, but we return
    // the current config for inspection. Hot-reload would require re-init.
    if config_toml.is_some() {
        return Err(napi::Error::from_reason(
            "Hot configuration reload not supported. Call shutdown() then initialize() with new config.",
        ));
    }
    serde_json::to_value(&rt.config)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize config: {e}")))
}

//! Destructive operation safety — auto-backup + confirmation token.
//! V1 pattern preserved exactly.

use std::path::Path;

use rusqlite::Connection;

use super::backup::{BackupConfig, BackupManager, BackupReason};
use super::errors::{WorkspaceError, WorkspaceResult};

/// Execute a destructive operation with safety guards.
/// 1. Validates confirmation token ("DELETE")
/// 2. Creates auto-backup before operation
/// 3. Executes the operation
/// 4. Logs the event
pub fn perform_destructive_operation<F, T>(
    conn: &Connection,
    drift_path: &Path,
    operation_name: &str,
    confirmation: &str,
    drift_version: &str,
    operation: F,
) -> WorkspaceResult<T>
where
    F: FnOnce() -> WorkspaceResult<T>,
{
    if confirmation != "DELETE" {
        return Err(WorkspaceError::ConfirmationRequired {
            operation: operation_name.to_string(),
        });
    }

    // Auto-backup before destructive operation
    let backup_mgr = BackupManager::new(drift_path, BackupConfig::default());
    let backup = backup_mgr.create_backup(BackupReason::PreDestructiveOperation, drift_version)?;

    // Log the operation start
    let start_details = serde_json::json!({
        "operation": operation_name,
        "backup_id": backup.id,
    })
    .to_string();
    conn.execute(
        "INSERT INTO workspace_events (event_type, details) VALUES ('destructive_op_start', ?1)",
        [&start_details],
    )?;

    // Execute the operation
    let result = operation()?;

    // Log completion
    let complete_details = serde_json::json!({
        "operation": operation_name,
    })
    .to_string();
    conn.execute(
        "INSERT INTO workspace_events (event_type, details) VALUES ('destructive_op_complete', ?1)",
        [&complete_details],
    )?;

    Ok(result)
}

/// Delete the entire .drift/ directory. Requires "DELETE" confirmation.
pub fn workspace_delete(
    drift_path: &Path,
    confirmation: &str,
    drift_version: &str,
) -> WorkspaceResult<()> {
    if confirmation != "DELETE" {
        return Err(WorkspaceError::ConfirmationRequired {
            operation: "workspace_delete".to_string(),
        });
    }

    // Create final backup before deletion
    let backup_mgr = BackupManager::new(drift_path, BackupConfig::default());
    let _ = backup_mgr.create_backup(BackupReason::PreDestructiveOperation, drift_version);

    // Delete .drift/ directory
    if drift_path.exists() {
        std::fs::remove_dir_all(drift_path)?;
    }

    Ok(())
}

/// Reset workspace: delete everything except backups. Requires "DELETE" confirmation.
pub fn workspace_reset(
    drift_path: &Path,
    confirmation: &str,
    drift_version: &str,
) -> WorkspaceResult<()> {
    if confirmation != "DELETE" {
        return Err(WorkspaceError::ConfirmationRequired {
            operation: "workspace_reset".to_string(),
        });
    }

    // Create backup before reset
    let backup_mgr = BackupManager::new(drift_path, BackupConfig::default());
    let _ = backup_mgr.create_backup(BackupReason::PreDestructiveOperation, drift_version);

    // Delete drift.db (will be recreated on next init)
    let db_path = drift_path.join("drift.db");
    if db_path.exists() {
        std::fs::remove_file(&db_path)?;
    }

    // Delete WAL and SHM files
    let _ = std::fs::remove_file(drift_path.join("drift.db-wal"));
    let _ = std::fs::remove_file(drift_path.join("drift.db-shm"));

    // Delete cache directory
    let cache_path = drift_path.join("cache");
    if cache_path.exists() {
        std::fs::remove_dir_all(&cache_path)?;
    }

    // Keep: .drift-backups/, drift.toml, license.key
    Ok(())
}

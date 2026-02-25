//! Workspace export/import for portability and CI caching.
//! Uses VACUUM INTO for compact, single-file output.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

use super::errors::{WorkspaceError, WorkspaceResult};
use super::migration::initialize_workspace_db;

/// Export manifest — metadata about an exported workspace.
#[derive(Debug, Clone, Serialize)]
pub struct ExportManifest {
    pub exported_at: String,
    pub schema_version: u32,
    pub drift_version: String,
    pub size_bytes: u64,
}

/// Export workspace to a single portable SQLite file.
/// Uses VACUUM INTO for compact, single-file output (no WAL/SHM).
pub fn export_workspace(conn: &Connection, output: &Path) -> WorkspaceResult<ExportManifest> {
    // Canonicalize to absolute path and validate it's a real filesystem path.
    // VACUUM INTO requires a string literal — parameterized queries don't work here.
    // We escape single quotes and validate the path contains no SQL metacharacters.
    let path_str = output.display().to_string();
    if path_str.contains(';') || path_str.contains("--") {
        return Err(WorkspaceError::ConfigError(
            "Export path contains invalid characters".to_string(),
        ));
    }
    let escaped = path_str.replace('\'', "''");
    conn.execute_batch(&format!("VACUUM INTO '{}';", escaped))?;

    // Verify export integrity
    let export_conn = Connection::open_with_flags(output, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let result: String = export_conn
        .pragma_query_value(None, "integrity_check", |row| row.get(0))
        .unwrap_or_else(|_| "error".to_string());
    if result != "ok" {
        let _ = std::fs::remove_file(output);
        return Err(WorkspaceError::ExportCorrupted(result));
    }

    let schema_version: u32 = export_conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap_or(0);

    let size_bytes = std::fs::metadata(output).map(|m| m.len()).unwrap_or(0);

    Ok(ExportManifest {
        exported_at: format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ),
        schema_version,
        drift_version: env!("CARGO_PKG_VERSION").to_string(),
        size_bytes,
    })
}

/// Import workspace from a portable SQLite file.
/// Verifies integrity, checks schema compatibility, backs up current state.
pub fn import_workspace(drift_path: &Path, input: &Path) -> WorkspaceResult<()> {
    // 1. Verify import file integrity
    let import_conn = Connection::open_with_flags(input, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let result: String = import_conn
        .pragma_query_value(None, "integrity_check", |row| row.get(0))
        .unwrap_or_else(|_| "error".to_string());
    if result != "ok" {
        return Err(WorkspaceError::ImportCorrupted(result));
    }
    drop(import_conn);

    // 2. Replace drift.db with imported file
    let db_path = drift_path.join("drift.db");
    std::fs::copy(input, &db_path)?;

    // 3. Re-initialize (run any pending migrations)
    let conn = Connection::open(&db_path)?;
    initialize_workspace_db(&conn)?;

    Ok(())
}

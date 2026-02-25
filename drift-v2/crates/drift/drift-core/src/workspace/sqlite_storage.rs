//! `SqliteWorkspaceStorage` — concrete `IWorkspaceStorage` implementation
//! backed by SQLite. Encapsulates all `Connection::open()` calls for
//! workspace operations.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use crate::errors::StorageError;
use crate::traits::storage::workspace::IWorkspaceStorage;
use crate::traits::storage::workspace_types::{
    BackupResult, GcStats, IntegrityResult, ProjectInfo, WorkspaceContext, WorkspaceStatus,
};

use super::errors::WorkspaceError;
use super::migration::{get_schema_version, initialize_workspace_db};

/// Concrete SQLite-backed workspace storage.
///
/// Holds the path to the `.drift/` directory and opens connections
/// on demand for each operation. Workspace operations are infrequent,
/// so connection-per-call is acceptable.
pub struct SqliteWorkspaceStorage {
    /// Path to the `.drift/` directory.
    drift_path: PathBuf,
}

impl SqliteWorkspaceStorage {
    /// Create a new `SqliteWorkspaceStorage` for the given `.drift/` directory.
    /// Does NOT open or create any database — call `initialize()` for that.
    pub fn new(drift_path: &Path) -> Self {
        Self {
            drift_path: drift_path.to_path_buf(),
        }
    }

    /// Path to drift.db inside the drift directory.
    fn db_path(&self) -> PathBuf {
        self.drift_path.join("drift.db")
    }

    /// Open a read-only connection to drift.db.
    fn open_readonly(&self) -> Result<Connection, StorageError> {
        let db_path = self.db_path();
        if !db_path.exists() {
            return Err(StorageError::NotSupported {
                operation: "open_readonly".to_string(),
                reason: "drift.db does not exist".to_string(),
            });
        }
        Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| StorageError::SqliteError {
                message: e.to_string(),
            })
    }

    /// Open a read-write connection to drift.db.
    fn open_readwrite(&self) -> Result<Connection, StorageError> {
        let db_path = self.db_path();
        Connection::open(&db_path).map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })
    }

    /// Convert a WorkspaceError to StorageError.
    fn ws_err(e: WorkspaceError) -> StorageError {
        StorageError::SqliteError {
            message: e.to_string(),
        }
    }
}

impl IWorkspaceStorage for SqliteWorkspaceStorage {
    fn initialize(&self, _path: &str) -> Result<(), StorageError> {
        // Create .drift/ directory if it doesn't exist
        std::fs::create_dir_all(&self.drift_path).map_err(|e| StorageError::SqliteError {
            message: format!("Failed to create drift directory: {e}"),
        })?;

        let conn = self.open_readwrite()?;
        initialize_workspace_db(&conn).map_err(Self::ws_err)?;
        Ok(())
    }

    fn status(&self) -> Result<WorkspaceStatus, StorageError> {
        let conn = self.open_readonly()?;
        let schema_version = get_schema_version(&conn).map_err(Self::ws_err)?;

        let file_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_metadata",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let page_count: u64 = conn
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap_or(0);
        let page_size: u64 = conn
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .unwrap_or(4096);
        let db_size_bytes = page_count * page_size;

        let wal_path = self.db_path().with_extension("db-wal");
        let wal_size_bytes = if wal_path.exists() {
            std::fs::metadata(&wal_path)
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };

        Ok(WorkspaceStatus {
            initialized: true,
            db_path: Some(self.db_path().display().to_string()),
            schema_version,
            file_count,
            db_size_bytes,
            wal_size_bytes,
        })
    }

    fn project_info(&self) -> Result<ProjectInfo, StorageError> {
        let conn = self.open_readonly()?;

        let get_config = |key: &str| -> String {
            conn.query_row(
                "SELECT value FROM workspace_config WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .unwrap_or_default()
        };

        let root_path = get_config("root_path");
        let name = get_config("project_name");

        let total_files: i64 = conn
            .query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
            .unwrap_or(0);

        let total_functions: i64 = conn
            .query_row("SELECT COUNT(*) FROM functions", [], |row| row.get(0))
            .unwrap_or(0);

        let total_patterns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pattern_confidence",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let last_scan_at: Option<i64> = conn
            .query_row(
                "SELECT MAX(started_at) FROM scan_history",
                [],
                |row| row.get(0),
            )
            .unwrap_or(None);

        let languages_json = get_config("detected_languages");
        let language_breakdown: Vec<(String, u64)> =
            serde_json::from_str::<Vec<String>>(&languages_json)
                .unwrap_or_default()
                .into_iter()
                .map(|l| (l, 0))
                .collect();

        Ok(ProjectInfo {
            root_path,
            name,
            language_breakdown,
            total_files,
            total_functions,
            total_patterns,
            last_scan_at,
        })
    }

    fn workspace_context(&self) -> Result<WorkspaceContext, StorageError> {
        let conn = self.open_readonly()?;

        let get_config = |key: &str| -> String {
            conn.query_row(
                "SELECT value FROM workspace_config WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .unwrap_or_default()
        };

        let root_path = get_config("root_path");
        let languages: Vec<String> =
            serde_json::from_str(&get_config("detected_languages")).unwrap_or_default();
        let frameworks: Vec<String> =
            serde_json::from_str(&get_config("detected_frameworks")).unwrap_or_default();

        let file_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
            .unwrap_or(0);
        let function_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM functions", [], |row| row.get(0))
            .unwrap_or(0);
        let pattern_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pattern_confidence",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let boundary_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM boundaries", [], |row| row.get(0))
            .unwrap_or(0);
        let detection_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM detections", [], |row| row.get(0))
            .unwrap_or(0);

        Ok(WorkspaceContext {
            root_path,
            languages,
            frameworks,
            file_count,
            function_count,
            pattern_count,
            boundary_count,
            detection_count,
        })
    }

    fn gc(&self) -> Result<GcStats, StorageError> {
        let conn = self.open_readwrite()?;

        let page_size: u64 = conn
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .unwrap_or(4096);
        let freelist_before: u64 = conn
            .pragma_query_value(None, "freelist_count", |row| row.get(0))
            .unwrap_or(0);

        let _ = conn.execute_batch("PRAGMA incremental_vacuum;");

        let freelist_after: u64 = conn
            .pragma_query_value(None, "freelist_count", |row| row.get(0))
            .unwrap_or(0);
        let pages_freed = freelist_before.saturating_sub(freelist_after);

        // WAL checkpoint
        let wal_checkpointed = conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .is_ok();

        // Clean old events (90-day retention)
        let stale = conn
            .execute(
                "DELETE FROM workspace_events WHERE created_at < datetime('now', '-90 days')",
                [],
            )
            .unwrap_or(0) as u64;

        Ok(GcStats {
            orphan_files_removed: 0,
            stale_cache_entries_removed: stale,
            wal_checkpointed,
            freed_bytes: pages_freed * page_size,
        })
    }

    fn backup(&self, destination: &str) -> Result<BackupResult, StorageError> {
        use rusqlite::backup::Backup;

        let start = std::time::Instant::now();
        let db_path = self.db_path();
        if !db_path.exists() {
            return Err(StorageError::NotSupported {
                operation: "backup".to_string(),
                reason: "drift.db does not exist".to_string(),
            });
        }

        let dest_path = Path::new(destination);
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StorageError::SqliteError {
                message: format!("Failed to create backup directory: {e}"),
            })?;
        }

        let src_conn =
            Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| StorageError::SqliteError {
                    message: e.to_string(),
                })?;
        let mut dst_conn =
            Connection::open(dest_path).map_err(|e| StorageError::SqliteError {
                message: e.to_string(),
            })?;

        {
            let backup = Backup::new(&src_conn, &mut dst_conn).map_err(|e| {
                StorageError::SqliteError {
                    message: e.to_string(),
                }
            })?;
            backup
                .run_to_completion(1000, std::time::Duration::from_millis(10), None)
                .map_err(|e| StorageError::SqliteError {
                    message: e.to_string(),
                })?;
        }

        let size_bytes = std::fs::metadata(dest_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(BackupResult {
            destination: destination.to_string(),
            size_bytes,
            duration_ms,
        })
    }

    fn export(&self, destination: &str) -> Result<(), StorageError> {
        let conn = self.open_readonly()?;
        let path_str = destination.to_string();
        if path_str.contains(';') || path_str.contains("--") {
            return Err(StorageError::SqliteError {
                message: "Export path contains invalid characters".to_string(),
            });
        }
        let escaped = path_str.replace('\'', "''");
        conn.execute_batch(&format!("VACUUM INTO '{}';", escaped))
            .map_err(|e| StorageError::SqliteError {
                message: e.to_string(),
            })?;
        Ok(())
    }

    fn import(&self, source: &str) -> Result<(), StorageError> {
        let input = Path::new(source);
        let import_conn =
            Connection::open_with_flags(input, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| StorageError::SqliteError {
                    message: e.to_string(),
                })?;
        let result: String = import_conn
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .unwrap_or_else(|_| "error".to_string());
        if result != "ok" {
            return Err(StorageError::SqliteError {
                message: format!("Import file corrupted: {result}"),
            });
        }
        drop(import_conn);

        let db_path = self.db_path();
        std::fs::copy(input, &db_path).map_err(|e| StorageError::SqliteError {
            message: format!("Failed to copy import file: {e}"),
        })?;

        let conn = self.open_readwrite()?;
        initialize_workspace_db(&conn).map_err(Self::ws_err)?;
        Ok(())
    }

    fn integrity_check(&self) -> Result<IntegrityResult, StorageError> {
        let db_path = self.db_path();
        if !db_path.exists() {
            return Ok(IntegrityResult {
                ok: false,
                issues: vec!["drift.db does not exist".to_string()],
            });
        }

        let conn = self.open_readonly()?;
        let result: String = conn
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .unwrap_or_else(|_| "error".to_string());

        if result == "ok" {
            Ok(IntegrityResult {
                ok: true,
                issues: vec![],
            })
        } else {
            Ok(IntegrityResult {
                ok: false,
                issues: vec![result],
            })
        }
    }

    fn schema_version(&self) -> Result<u32, StorageError> {
        let conn = self.open_readonly()?;
        get_schema_version(&conn).map_err(Self::ws_err)
    }
}

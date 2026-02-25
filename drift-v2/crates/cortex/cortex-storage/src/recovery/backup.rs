//! Periodic backup creation + restore from backup.

use std::path::Path;

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

/// Create a backup of the database to the given path.
pub fn create_backup(conn: &Connection, backup_path: &Path) -> CortexResult<()> {
    let mut dst = Connection::open(backup_path)
        .map_err(|e| to_storage_err(format!("open backup dest: {e}")))?;

    let backup = rusqlite::backup::Backup::new(conn, &mut dst)
        .map_err(|e| to_storage_err(format!("init backup: {e}")))?;

    backup
        .run_to_completion(100, std::time::Duration::from_millis(10), None)
        .map_err(|e| to_storage_err(format!("run backup: {e}")))?;

    Ok(())
}

/// Restore a database from a backup file.
pub fn restore_from_backup(conn: &mut Connection, backup_path: &Path) -> CortexResult<()> {
    let src = Connection::open(backup_path)
        .map_err(|e| to_storage_err(format!("open backup source: {e}")))?;

    let backup = rusqlite::backup::Backup::new(&src, conn)
        .map_err(|e| to_storage_err(format!("init restore: {e}")))?;

    backup
        .run_to_completion(100, std::time::Duration::from_millis(10), None)
        .map_err(|e| to_storage_err(format!("run restore: {e}")))?;

    Ok(())
}

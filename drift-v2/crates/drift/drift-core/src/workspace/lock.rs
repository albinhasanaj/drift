//! Workspace locking via fd-lock for concurrent access safety.
//! Shared read locks allow concurrent MCP queries.
//! Exclusive write locks prevent concurrent mutations.

use std::fs::File;
use std::path::{Path, PathBuf};

use fd_lock::RwLock;

use super::errors::WorkspaceError;

/// Cross-platform workspace lock using advisory file locks.
/// Shared read locks allow concurrent MCP queries.
/// Exclusive write locks prevent concurrent mutations.
pub struct WorkspaceLock {
    lock_file: RwLock<File>,
    lock_path: PathBuf,
}

impl WorkspaceLock {
    /// Create a new workspace lock at `.drift/workspace.lock`.
    pub fn new(drift_path: &Path) -> Result<Self, WorkspaceError> {
        let lock_path = drift_path.join("workspace.lock");
        let file = File::create(&lock_path)?;
        Ok(Self {
            lock_file: RwLock::new(file),
            lock_path,
        })
    }

    /// Acquire shared read lock (non-blocking).
    /// Used by: MCP tool queries, CLI read commands, backup creation.
    /// Multiple readers can hold this simultaneously.
    pub fn read(&mut self) -> Result<fd_lock::RwLockReadGuard<'_, File>, WorkspaceError> {
        self.lock_file.try_read().map_err(|_| WorkspaceError::Locked {
            operation: "read".to_string(),
            message: "A write operation is in progress. Try again shortly.".to_string(),
        })
    }

    /// Acquire exclusive write lock (non-blocking).
    /// Used by: drift scan, drift migrate, drift reset.
    /// Fails immediately if any other lock is held.
    pub fn write(&mut self) -> Result<fd_lock::RwLockWriteGuard<'_, File>, WorkspaceError> {
        self.lock_file.try_write().map_err(|_| WorkspaceError::Locked {
            operation: "write".to_string(),
            message: "Another operation is in progress. Wait for it to complete.".to_string(),
        })
    }

    /// Get the lock file path.
    pub fn path(&self) -> &Path {
        &self.lock_path
    }
}

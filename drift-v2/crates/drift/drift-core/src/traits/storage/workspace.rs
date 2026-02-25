//! `IWorkspaceStorage` trait — workspace lifecycle operations.
//!
//! Abstracts the 12 workspace files in `drift-core/src/workspace/` behind a
//! trait. SQLite-specific operations (backup, VACUUM INTO, integrity_check)
//! return `Err(StorageError::NotSupported)` for non-SQLite backends.

use crate::errors::StorageError;
use std::sync::Arc;

use super::workspace_types::{
    BackupResult, GcStats, IntegrityResult, ProjectInfo, WorkspaceContext, WorkspaceStatus,
};

/// Workspace lifecycle storage operations.
///
/// Covers: initialization, status, project info, context, GC, backup,
/// export/import, integrity check, schema version.
pub trait IWorkspaceStorage: Send + Sync {
    /// Initialize a workspace at the given path (create DB, run migrations).
    fn initialize(&self, path: &str) -> Result<(), StorageError>;

    /// Get workspace status.
    fn status(&self) -> Result<WorkspaceStatus, StorageError>;

    /// Get project information.
    fn project_info(&self) -> Result<ProjectInfo, StorageError>;

    /// Get workspace context for AI/MCP consumption.
    fn workspace_context(&self) -> Result<WorkspaceContext, StorageError>;

    /// Run garbage collection.
    fn gc(&self) -> Result<GcStats, StorageError>;

    /// Create a backup of the workspace database.
    /// Returns `Err(StorageError::NotSupported)` for non-SQLite backends.
    fn backup(&self, destination: &str) -> Result<BackupResult, StorageError>;

    /// Export workspace data to a file.
    /// Returns `Err(StorageError::NotSupported)` for non-SQLite backends.
    fn export(&self, destination: &str) -> Result<(), StorageError>;

    /// Import workspace data from a file.
    /// Returns `Err(StorageError::NotSupported)` for non-SQLite backends.
    fn import(&self, source: &str) -> Result<(), StorageError>;

    /// Run integrity check on the database.
    fn integrity_check(&self) -> Result<IntegrityResult, StorageError>;

    /// Get the current schema version.
    fn schema_version(&self) -> Result<u32, StorageError>;
}

// ─── Arc blanket impl ───────────────────────────────────────────────

impl<T: IWorkspaceStorage + ?Sized> IWorkspaceStorage for Arc<T> {
    fn initialize(&self, path: &str) -> Result<(), StorageError> {
        (**self).initialize(path)
    }
    fn status(&self) -> Result<WorkspaceStatus, StorageError> {
        (**self).status()
    }
    fn project_info(&self) -> Result<ProjectInfo, StorageError> {
        (**self).project_info()
    }
    fn workspace_context(&self) -> Result<WorkspaceContext, StorageError> {
        (**self).workspace_context()
    }
    fn gc(&self) -> Result<GcStats, StorageError> {
        (**self).gc()
    }
    fn backup(&self, dest: &str) -> Result<BackupResult, StorageError> {
        (**self).backup(dest)
    }
    fn export(&self, dest: &str) -> Result<(), StorageError> {
        (**self).export(dest)
    }
    fn import(&self, src: &str) -> Result<(), StorageError> {
        (**self).import(src)
    }
    fn integrity_check(&self) -> Result<IntegrityResult, StorageError> {
        (**self).integrity_check()
    }
    fn schema_version(&self) -> Result<u32, StorageError> {
        (**self).schema_version()
    }
}

//! Connection management: write-serialized + read-pooled.

pub mod pragmas;
pub mod writer;
pub mod pool;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use drift_core::errors::StorageError;
use rusqlite::Connection;

use self::pool::ReadPool;
use self::pragmas::apply_pragmas;
use crate::migrations;

/// Manages the single write connection and the read connection pool.
pub struct DatabaseManager {
    writer: Mutex<Connection>,
    readers: ReadPool,
    path: Option<PathBuf>,
}

impl DatabaseManager {
    /// Open a database at the given path, apply pragmas, run migrations.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let writer = Connection::open(path).map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;
        apply_pragmas(&writer)?;
        migrations::run_migrations(&writer)?;

        let readers = ReadPool::open(path, ReadPool::default_size())?;

        Ok(Self {
            writer: Mutex::new(writer),
            readers,
            path: Some(path.to_path_buf()),
        })
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let writer =
            Connection::open_in_memory().map_err(|e| StorageError::SqliteError {
                message: e.to_string(),
            })?;
        apply_pragmas(&writer)?;
        migrations::run_migrations(&writer)?;

        // In-memory: readers can't share the same DB, so use a minimal pool
        let readers = ReadPool::open_in_memory(1)?;

        Ok(Self {
            writer: Mutex::new(writer),
            readers,
            path: None,
        })
    }

    /// Execute a write operation with the serialized writer connection.
    pub fn with_writer<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce(&Connection) -> Result<T, StorageError>,
    {
        let guard = self.writer.lock().map_err(|_| StorageError::SqliteError {
            message: "write lock poisoned".to_string(),
        })?;
        f(&guard)
    }

    /// Execute a read operation with a pooled read connection.
    pub fn with_reader<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce(&Connection) -> Result<T, StorageError>,
    {
        self.readers.with_conn(f)
    }

    /// Run a WAL checkpoint (TRUNCATE mode) after scan completion.
    pub fn checkpoint(&self) -> Result<(), StorageError> {
        self.with_writer(|conn| {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|e| StorageError::SqliteError {
                    message: e.to_string(),
                })
        })
    }

    /// Get the database file path (None for in-memory).
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Open a dedicated connection for the BatchWriter.
    /// Returns a fresh Connection to the same database with pragmas applied.
    /// For in-memory databases, returns an in-memory connection (batch writes
    /// won't be visible to the main writer — use only for testing).
    pub fn open_batch_connection(&self) -> Result<Connection, StorageError> {
        let conn = match &self.path {
            Some(path) => Connection::open(path).map_err(|e| StorageError::SqliteError {
                message: format!("open batch connection: {e}"),
            })?,
            None => Connection::open_in_memory().map_err(|e| StorageError::SqliteError {
                message: format!("open in-memory batch connection: {e}"),
            })?,
        };
        apply_pragmas(&conn)?;
        Ok(conn)
    }
}

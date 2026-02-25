//! ReadPool — round-robin read-only connections.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use drift_core::errors::StorageError;
use rusqlite::Connection;

use super::pragmas::apply_read_pragmas;

const DEFAULT_POOL_SIZE: usize = 4;
const MAX_POOL_SIZE: usize = 8;

/// A pool of read-only SQLite connections with round-robin selection.
pub struct ReadPool {
    connections: Vec<Mutex<Connection>>,
    next: AtomicUsize,
}

impl ReadPool {
    /// Open a pool of read-only connections to the given database path.
    pub fn open(path: &Path, pool_size: usize) -> Result<Self, StorageError> {
        let size = pool_size.clamp(1, MAX_POOL_SIZE);
        let mut connections = Vec::with_capacity(size);
        for _ in 0..size {
            let conn = Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|e| StorageError::SqliteError {
                message: e.to_string(),
            })?;
            apply_read_pragmas(&conn)?;
            connections.push(Mutex::new(conn));
        }
        Ok(Self {
            connections,
            next: AtomicUsize::new(0),
        })
    }

    /// Open an in-memory pool (for testing).
    pub fn open_in_memory(pool_size: usize) -> Result<Self, StorageError> {
        let size = pool_size.clamp(1, MAX_POOL_SIZE);
        let mut connections = Vec::with_capacity(size);
        for _ in 0..size {
            let conn = Connection::open_in_memory().map_err(|e| StorageError::SqliteError {
                message: e.to_string(),
            })?;
            connections.push(Mutex::new(conn));
        }
        Ok(Self {
            connections,
            next: AtomicUsize::new(0),
        })
    }

    /// Execute a closure with a read connection (round-robin).
    pub fn with_conn<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce(&Connection) -> Result<T, StorageError>,
    {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.connections.len();
        let guard = self.connections[idx]
            .lock()
            .map_err(|_| StorageError::SqliteError {
                message: "read pool lock poisoned".to_string(),
            })?;
        f(&guard)
    }

    /// Number of connections in the pool.
    pub fn size(&self) -> usize {
        self.connections.len()
    }

    /// Default pool size.
    pub fn default_size() -> usize {
        DEFAULT_POOL_SIZE
    }
}

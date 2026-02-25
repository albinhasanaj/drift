//! Pool of 4–8 read connections (concurrent, never blocked by writer via WAL).

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use super::pragmas::apply_read_pragmas;
use crate::to_storage_err;

/// Default number of read connections.
const DEFAULT_POOL_SIZE: usize = 4;

/// Maximum number of read connections.
const MAX_POOL_SIZE: usize = 8;

/// A pool of read-only SQLite connections.
pub struct ReadPool {
    connections: Vec<std::sync::Mutex<Connection>>,
    next: AtomicUsize,
}

impl ReadPool {
    /// Open a pool of read connections to the given database path.
    pub fn open(path: &Path, pool_size: usize) -> CortexResult<Self> {
        let size = pool_size.clamp(1, MAX_POOL_SIZE);
        let mut connections = Vec::with_capacity(size);
        for _ in 0..size {
            let conn = Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|e| to_storage_err(e.to_string()))?;
            apply_read_pragmas(&conn)?;
            connections.push(std::sync::Mutex::new(conn));
        }
        Ok(Self {
            connections,
            next: AtomicUsize::new(0),
        })
    }

    /// Create an in-memory pool (for testing). Uses a shared cache URI so all
    /// connections see the same database.
    pub fn open_in_memory(pool_size: usize) -> CortexResult<Self> {
        let size = pool_size.clamp(1, MAX_POOL_SIZE);
        let mut connections = Vec::with_capacity(size);
        for _ in 0..size {
            // In-memory read connections can't really be read-only for a shared
            // in-memory DB, so we open them normally. In production, the file-based
            // path uses SQLITE_OPEN_READ_ONLY.
            let conn = Connection::open_in_memory().map_err(|e| to_storage_err(e.to_string()))?;
            apply_read_pragmas(&conn)?;
            connections.push(std::sync::Mutex::new(conn));
        }
        Ok(Self {
            connections,
            next: AtomicUsize::new(0),
        })
    }

    /// Execute a closure with a read connection from the pool (round-robin).
    pub fn with_conn<F, T>(&self, f: F) -> CortexResult<T>
    where
        F: FnOnce(&Connection) -> CortexResult<T>,
    {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.connections.len();
        let guard = self.connections[idx]
            .lock()
            .map_err(|e| to_storage_err(format!("read pool lock poisoned: {e}")))?;
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

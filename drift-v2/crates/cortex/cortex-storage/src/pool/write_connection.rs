//! Single write connection behind `tokio::sync::Mutex`.
//! Serialized writes — no contention.

use std::path::Path;

use rusqlite::Connection;
use tokio::sync::Mutex;

use cortex_core::errors::CortexResult;

use super::pragmas::apply_pragmas;
use crate::to_storage_err;

/// A single write connection protected by an async mutex.
pub struct WriteConnection {
    conn: Mutex<Connection>,
}

impl WriteConnection {
    /// Open a new write connection to the given database path.
    pub fn open(path: &Path) -> CortexResult<Self> {
        let conn = Connection::open(path).map_err(|e| to_storage_err(e.to_string()))?;
        apply_pragmas(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> CortexResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| to_storage_err(e.to_string()))?;
        apply_pragmas(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Acquire the write lock and execute a closure with the connection.
    pub async fn with_conn<F, T>(&self, f: F) -> CortexResult<T>
    where
        F: FnOnce(&Connection) -> CortexResult<T>,
    {
        let guard = self.conn.lock().await;
        f(&guard)
    }

    /// Synchronous access for non-async contexts (e.g., migrations at startup).
    pub fn with_conn_sync<F, T>(&self, f: F) -> CortexResult<T>
    where
        F: FnOnce(&Connection) -> CortexResult<T>,
    {
        let guard = self.conn.blocking_lock();
        f(&guard)
    }
}

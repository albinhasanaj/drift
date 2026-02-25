//! ConnectionPool — writer + read pool with round-robin selection.
//!
//! The only place in the bridge crate that holds `Mutex<Connection>`.
//! All other code accesses storage through `IBridgeStorage` trait methods.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use rusqlite::Connection;

use crate::errors::{BridgeError, BridgeResult};
use crate::storage;

/// Default number of reader connections.
const DEFAULT_READ_POOL_SIZE: usize = 2;

/// Connection pool for bridge.db: 1 writer + N readers.
///
/// WAL mode is enabled on all connections.
/// Round-robin reader selection via atomic counter.
pub struct ConnectionPool {
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    read_index: AtomicUsize,
}

impl ConnectionPool {
    /// Open a file-backed connection pool.
    ///
    /// Creates `read_pool_size` reader connections + 1 writer connection.
    /// WAL mode is enabled on all connections.
    pub fn open(path: &Path, read_pool_size: usize) -> BridgeResult<Self> {
        let pool_size = if read_pool_size == 0 { DEFAULT_READ_POOL_SIZE } else { read_pool_size };

        // Writer connection (read-write)
        let writer = Connection::open(path).map_err(|e| {
            BridgeError::Config(format!("Failed to open bridge.db writer: {}", e))
        })?;
        storage::configure_connection(&writer)?;

        // Reader connections (read-only)
        let mut readers = Vec::with_capacity(pool_size);
        for i in 0..pool_size {
            let reader = Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|e| {
                BridgeError::Config(format!("Failed to open bridge.db reader {}: {}", i, e))
            })?;
            storage::configure_readonly_connection(&reader)?;
            readers.push(Mutex::new(reader));
        }

        Ok(Self {
            writer: Mutex::new(writer),
            readers,
            read_index: AtomicUsize::new(0),
        })
    }

    /// Open an in-memory connection pool.
    ///
    /// Uses a single shared in-memory database via URI filename.
    /// SQLite in-memory DBs are not shared across separate `Connection::open_in_memory()` calls,
    /// so we use `file::memdb1?mode=memory&cache=shared` for readers to see writer's data.
    pub fn open_in_memory() -> BridgeResult<Self> {
        // Use a plain in-memory connection. Shared cache mode causes table-level
        // locking issues ("database table is locked") even on single-threaded access.
        // Since readers is empty, with_reader falls back to the writer, so all
        // operations share the single connection — no shared cache needed.
        let writer = Connection::open_in_memory().map_err(|e| {
            BridgeError::Config(format!("Failed to open in-memory writer: {}", e))
        })?;
        storage::configure_connection(&writer)?;

        Ok(Self {
            writer: Mutex::new(writer),
            readers: Vec::new(),
            read_index: AtomicUsize::new(0),
        })
    }

    /// Execute a closure with the writer connection.
    pub fn with_writer<F, T>(&self, f: F) -> BridgeResult<T>
    where
        F: FnOnce(&Connection) -> BridgeResult<T>,
    {
        let conn = self.writer.lock().map_err(|e| {
            BridgeError::Config(format!("Writer lock poisoned: {}", e))
        })?;
        f(&conn)
    }

    /// Execute a closure with a reader connection (round-robin).
    ///
    /// Falls back to writer if no readers are available (in-memory mode).
    pub fn with_reader<F, T>(&self, f: F) -> BridgeResult<T>
    where
        F: FnOnce(&Connection) -> BridgeResult<T>,
    {
        if self.readers.is_empty() {
            // In-memory mode: use writer for reads
            return self.with_writer(f);
        }

        let index = self.read_index.fetch_add(1, Ordering::Relaxed) % self.readers.len();
        let conn = self.readers[index].lock().map_err(|e| {
            BridgeError::Config(format!("Reader lock poisoned: {}", e))
        })?;
        f(&conn)
    }

    /// Check WAL mode on the writer connection.
    pub fn is_wal_mode(&self) -> bool {
        self.with_writer(|conn| {
            let mode: String = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                .unwrap_or_default();
            Ok(mode.to_lowercase() == "wal")
        })
        .unwrap_or(false)
    }
}

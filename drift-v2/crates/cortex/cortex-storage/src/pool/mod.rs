//! Connection pool managing read/write connections.

pub mod pragmas;
pub mod read_pool;
pub mod write_connection;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cortex_core::errors::CortexResult;

pub use read_pool::ReadPool;
pub use write_connection::WriteConnection;

/// Manages the single write connection and the read connection pool.
///
/// Writer and readers are wrapped in `Arc` so they can be shared with
/// engines like `TemporalEngine` and `MultiAgentEngine` without opening
/// duplicate connections.
pub struct ConnectionPool {
    pub writer: Arc<WriteConnection>,
    pub readers: Arc<ReadPool>,
    pub db_path: Option<PathBuf>,
}

impl ConnectionPool {
    /// Open a connection pool for the given database file.
    pub fn open(path: &Path, read_pool_size: usize) -> CortexResult<Self> {
        let writer = Arc::new(WriteConnection::open(path)?);
        let readers = Arc::new(ReadPool::open(path, read_pool_size)?);
        Ok(Self {
            writer,
            readers,
            db_path: Some(path.to_path_buf()),
        })
    }

    /// Open an in-memory connection pool (for testing).
    /// Note: In-memory mode uses separate databases for writer and readers,
    /// so readers won't see writer's changes. For integration tests, use a
    /// temp file instead.
    pub fn open_in_memory(read_pool_size: usize) -> CortexResult<Self> {
        let writer = Arc::new(WriteConnection::open_in_memory()?);
        let readers = Arc::new(ReadPool::open_in_memory(read_pool_size)?);
        Ok(Self {
            writer,
            readers,
            db_path: None,
        })
    }
}

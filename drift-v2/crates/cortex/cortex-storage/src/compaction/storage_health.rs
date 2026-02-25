//! DB file size, active vs archived count, embedding storage size,
//! FTS5 index size, fragmentation %, projected growth rate, time-to-threshold.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::queries::aggregation;
use crate::to_storage_err;

/// Storage health report.
#[derive(Debug, Clone)]
pub struct StorageHealthReport {
    pub active_memories: usize,
    pub archived_memories: usize,
    pub total_embeddings: usize,
    pub total_relationships: usize,
    pub total_audit_entries: usize,
    pub page_count: u64,
    pub page_size: u64,
    pub freelist_count: u64,
}

impl StorageHealthReport {
    /// Estimated database size in bytes.
    pub fn estimated_db_size(&self) -> u64 {
        self.page_count * self.page_size
    }

    /// Fragmentation percentage.
    pub fn fragmentation_pct(&self) -> f64 {
        if self.page_count == 0 {
            return 0.0;
        }
        (self.freelist_count as f64 / self.page_count as f64) * 100.0
    }
}

/// Generate a storage health report.
pub fn report(conn: &Connection) -> CortexResult<StorageHealthReport> {
    let stats = aggregation::storage_stats(conn)?;

    let page_count: u64 = conn
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .map_err(|e| to_storage_err(e.to_string()))?;
    let page_size: u64 = conn
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .map_err(|e| to_storage_err(e.to_string()))?;
    let freelist_count: u64 = conn
        .pragma_query_value(None, "freelist_count", |row| row.get(0))
        .map_err(|e| to_storage_err(e.to_string()))?;

    Ok(StorageHealthReport {
        active_memories: stats.active_memories,
        archived_memories: stats.archived_memories,
        total_embeddings: stats.total_embeddings,
        total_relationships: stats.total_relationships,
        total_audit_entries: stats.total_audit_entries,
        page_count,
        page_size,
        freelist_count,
    })
}

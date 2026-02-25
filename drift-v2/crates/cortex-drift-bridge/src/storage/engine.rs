//! BridgeStorageEngine — concrete `IBridgeStorage` implementation wrapping `ConnectionPool`.
//!
//! Each trait method delegates to existing free functions in `storage/tables.rs` (writes)
//! or `query/cortex_queries.rs` (reads), routed through the pool.

use std::path::Path;

use crate::errors::BridgeResult;
use crate::grounding::{GroundingResult, GroundingSnapshot};
use crate::traits::{
    BridgeEventRow, BridgeHealthStatus, BridgeMemoryRow, BridgeMetricRow, BridgeStorageStats,
    GroundingSnapshotRow, IBridgeStorage,
};

use super::pool::ConnectionPool;

/// Concrete bridge storage engine backed by SQLite via `ConnectionPool`.
pub struct BridgeStorageEngine {
    pool: ConnectionPool,
}

impl BridgeStorageEngine {
    /// Open a file-backed engine.
    pub fn open(path: &Path) -> BridgeResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                crate::errors::BridgeError::Config(format!(
                    "Failed to create bridge.db directory: {}",
                    e
                ))
            })?;
        }
        let pool = ConnectionPool::open(path, 2)?;
        let engine = Self { pool };
        engine.initialize()?;
        Ok(engine)
    }

    /// Open an in-memory engine (for testing).
    pub fn open_in_memory() -> BridgeResult<Self> {
        let pool = ConnectionPool::open_in_memory()?;
        let engine = Self { pool };
        engine.initialize()?;
        Ok(engine)
    }

    /// Execute a closure with the writer connection (for tests and advanced use cases).
    ///
    /// Prefer trait methods (`IBridgeStorage`) for normal usage.
    pub fn with_writer<F, T>(&self, f: F) -> BridgeResult<T>
    where
        F: FnOnce(&rusqlite::Connection) -> BridgeResult<T>,
    {
        self.pool.with_writer(f)
    }

    /// Execute a closure with a reader connection (for tests and advanced use cases).
    pub fn with_reader<F, T>(&self, f: F) -> BridgeResult<T>
    where
        F: FnOnce(&rusqlite::Connection) -> BridgeResult<T>,
    {
        self.pool.with_reader(f)
    }

    // ── Convenience SQL methods (mirrors rusqlite::Connection API) ──
    // These delegate to the pool so tests and callers can use the engine
    // like a raw Connection without needing explicit with_reader/with_writer.

    /// Execute a SQL query returning a single row (uses reader).
    pub fn query_row<T, P, F>(&self, sql: &str, params: P, f: F) -> BridgeResult<T>
    where
        P: rusqlite::Params,
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        self.pool
            .with_reader(|conn| conn.query_row(sql, params, f).map_err(Into::into))
    }

    /// Execute a SQL statement (uses writer).
    pub fn execute<P: rusqlite::Params>(&self, sql: &str, params: P) -> BridgeResult<usize> {
        self.pool
            .with_writer(|conn| conn.execute(sql, params).map_err(Into::into))
    }

    /// Execute a batch of SQL statements (uses writer).
    pub fn execute_batch(&self, sql: &str) -> BridgeResult<()> {
        self.pool
            .with_writer(|conn| conn.execute_batch(sql).map_err(Into::into))
    }

    /// Prepare and execute a statement, returning mapped rows (uses reader).
    pub fn prepare_and_query<T, F>(&self, sql: &str, f: F) -> BridgeResult<Vec<T>>
    where
        F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        self.pool.with_reader(|conn| {
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map([], f)?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
    }
}

impl IBridgeStorage for BridgeStorageEngine {
    // ── 7 Writes ──

    fn insert_memory(&self, memory: &cortex_core::memory::BaseMemory) -> BridgeResult<()> {
        self.pool
            .with_writer(|conn| super::tables::store_memory(conn, memory))
    }

    fn insert_grounding_result(&self, result: &GroundingResult) -> BridgeResult<()> {
        self.pool
            .with_writer(|conn| super::tables::record_grounding_result(conn, result))
    }

    fn insert_snapshot(&self, snapshot: &GroundingSnapshot) -> BridgeResult<()> {
        self.pool
            .with_writer(|conn| super::tables::record_grounding_snapshot(conn, snapshot))
    }

    fn insert_event(
        &self,
        event_type: &str,
        memory_type: Option<&str>,
        memory_id: Option<&str>,
        confidence: Option<f64>,
    ) -> BridgeResult<()> {
        self.pool.with_writer(|conn| {
            super::tables::log_event(conn, event_type, memory_type, memory_id, confidence)
        })
    }

    fn insert_metric(&self, key: &str, value: f64) -> BridgeResult<()> {
        self.pool
            .with_writer(|conn| super::tables::record_metric(conn, key, value))
    }

    fn update_memory_confidence(&self, memory_id: &str, delta: f64) -> BridgeResult<()> {
        self.pool
            .with_writer(|conn| super::tables::update_memory_confidence(conn, memory_id, delta))
    }

    fn upsert_weight(&self, section: &str, weight: f64) -> BridgeResult<()> {
        self.pool.with_writer(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO bridge_metrics (metric_name, metric_value) VALUES (?1, ?2)",
                rusqlite::params![format!("weight:{}", section), weight],
            )?;
            Ok(())
        })
    }

    // ── 7 Reads ──

    fn get_memory(&self, id: &str) -> BridgeResult<Option<BridgeMemoryRow>> {
        self.pool.with_reader(|conn| {
            crate::query::cortex_queries::get_memory_by_id(conn, id).map(|opt| {
                opt.map(|r| BridgeMemoryRow {
                    id: r.id,
                    memory_type: r.memory_type,
                    content: r.content,
                    summary: r.summary,
                    confidence: r.confidence,
                    importance: r.importance,
                    tags: r.tags,
                    linked_patterns: r.linked_patterns,
                    created_at: r.created_at,
                })
            })
        })
    }

    fn query_memories_by_type(
        &self,
        memory_type: &str,
        limit: usize,
    ) -> BridgeResult<Vec<BridgeMemoryRow>> {
        self.pool.with_reader(|conn| {
            crate::query::cortex_queries::get_memories_by_type(conn, memory_type, limit).map(
                |rows| {
                    rows.into_iter()
                        .map(|r| BridgeMemoryRow {
                            id: r.id,
                            memory_type: r.memory_type,
                            content: r.content,
                            summary: r.summary,
                            confidence: r.confidence,
                            importance: r.importance,
                            tags: r.tags,
                            linked_patterns: r.linked_patterns,
                            created_at: r.created_at,
                        })
                        .collect()
                },
            )
        })
    }

    fn get_grounding_history(
        &self,
        memory_id: &str,
        limit: usize,
    ) -> BridgeResult<Vec<(f64, String, i64)>> {
        self.pool.with_reader(|conn| {
            super::tables::get_grounding_history(conn, memory_id, limit)
        })
    }

    fn get_snapshots(&self, limit: usize) -> BridgeResult<Vec<GroundingSnapshotRow>> {
        self.pool.with_reader(|conn| {
            let mut stmt = conn.prepare(
                "SELECT total_memories, grounded_count, validated_count, partial_count, weak_count, \
                 invalidated_count, avg_score, error_count, trigger_type, created_at \
                 FROM bridge_grounding_snapshots ORDER BY created_at DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
                Ok(GroundingSnapshotRow {
                    total_memories: row.get(0)?,
                    grounded_count: row.get(1)?,
                    validated_count: row.get(2)?,
                    partial_count: row.get(3)?,
                    weak_count: row.get(4)?,
                    invalidated_count: row.get(5)?,
                    avg_score: row.get(6)?,
                    error_count: row.get(7)?,
                    trigger_type: row.get(8)?,
                    created_at: row.get(9)?,
                })
            })?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
    }

    fn get_events(&self, limit: usize) -> BridgeResult<Vec<BridgeEventRow>> {
        self.pool.with_reader(|conn| {
            let mut stmt = conn.prepare(
                "SELECT event_type, memory_type, memory_id, confidence, created_at \
                 FROM bridge_event_log ORDER BY created_at DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
                Ok(BridgeEventRow {
                    event_type: row.get(0)?,
                    memory_type: row.get(1)?,
                    memory_id: row.get(2)?,
                    confidence: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
    }

    fn get_metrics(&self, key: &str) -> BridgeResult<Vec<BridgeMetricRow>> {
        self.pool.with_reader(|conn| {
            let mut stmt = conn.prepare(
                "SELECT metric_name, metric_value, recorded_at FROM bridge_metrics \
                 WHERE metric_name = ?1 ORDER BY recorded_at DESC",
            )?;
            let rows = stmt.query_map(rusqlite::params![key], |row| {
                Ok(BridgeMetricRow {
                    metric_name: row.get(0)?,
                    metric_value: row.get(1)?,
                    created_at: row.get(2)?,
                })
            })?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
    }

    fn get_schema_version(&self) -> BridgeResult<u32> {
        self.pool.with_reader(|conn| {
            crate::storage::migrations::get_schema_version(conn)
        })
    }

    // ── 3 Formalized ad-hoc queries ──

    fn query_all_memories_for_grounding(&self) -> BridgeResult<Vec<BridgeMemoryRow>> {
        self.pool.with_reader(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, memory_type, content, summary, confidence, importance, tags, linked_patterns, created_at \
                 FROM bridge_memories ORDER BY created_at DESC LIMIT 500",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(BridgeMemoryRow {
                    id: row.get(0)?,
                    memory_type: row.get(1)?,
                    content: row.get(2)?,
                    summary: row.get(3)?,
                    confidence: row.get(4)?,
                    importance: row.get(5)?,
                    tags: row.get(6)?,
                    linked_patterns: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row?);
            }
            Ok(results)
        })
    }

    fn search_memories_by_tag(
        &self,
        tag: &str,
        limit: usize,
    ) -> BridgeResult<Vec<BridgeMemoryRow>> {
        self.pool.with_reader(|conn| {
            crate::query::cortex_queries::get_memories_by_tag(conn, tag, limit).map(|rows| {
                rows.into_iter()
                    .map(|r| BridgeMemoryRow {
                        id: r.id,
                        memory_type: r.memory_type,
                        content: r.content,
                        summary: r.summary,
                        confidence: r.confidence,
                        importance: r.importance,
                        tags: r.tags,
                        linked_patterns: r.linked_patterns,
                        created_at: r.created_at,
                    })
                    .collect()
            })
        })
    }

    fn get_previous_grounding_score(&self, memory_id: &str) -> BridgeResult<Option<f64>> {
        self.pool.with_reader(|conn| {
            super::tables::get_previous_grounding_score(conn, memory_id)
        })
    }

    // ── 4 Lifecycle ──

    fn initialize(&self) -> BridgeResult<()> {
        self.pool.with_writer(|conn| {
            crate::storage::migrate(conn)?;
            Ok(())
        })
    }

    fn migrate(&self) -> BridgeResult<()> {
        self.pool.with_writer(|conn| {
            crate::storage::migrate(conn)?;
            Ok(())
        })
    }

    fn health_check(&self) -> BridgeResult<BridgeHealthStatus> {
        self.pool.with_reader(|conn| {
            let connected = conn.execute_batch("SELECT 1").is_ok();
            let wal_mode = conn
                .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .map(|m| m.to_lowercase() == "wal")
                .unwrap_or(false);
            Ok(BridgeHealthStatus {
                connected,
                wal_mode,
            })
        })
    }

    fn shutdown(&self) -> BridgeResult<()> {
        // No-op for SQLite — connections close on drop.
        Ok(())
    }

    // ── 2 Usage ──

    fn count_memories(&self) -> BridgeResult<u64> {
        self.pool.with_reader(|conn| {
            crate::query::cortex_queries::count_memories(conn)
        })
    }

    fn storage_stats(&self) -> BridgeResult<BridgeStorageStats> {
        self.pool.with_reader(|conn| {
            let memory_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM bridge_memories", [], |row| row.get(0))
                .unwrap_or(0);
            let event_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM bridge_event_log", [], |row| row.get(0))
                .unwrap_or(0);
            let grounding_result_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM bridge_grounding_results",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let snapshot_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM bridge_grounding_snapshots",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let metric_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM bridge_metrics", [], |row| row.get(0))
                .unwrap_or(0);
            Ok(BridgeStorageStats {
                memory_count: memory_count as u64,
                event_count: event_count as u64,
                grounding_result_count: grounding_result_count as u64,
                snapshot_count: snapshot_count as u64,
                metric_count: metric_count as u64,
            })
        })
    }
}

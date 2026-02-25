//! `IBridgeStorage` trait — abstraction over bridge.db storage operations.
//!
//! This trait replaces raw `Mutex<Connection>` access with a clean interface
//! that works for both SQLite (local) and Postgres (cloud).
//!
//! Row types are intentionally NOT `BaseMemory` — the bridge stores a simplified
//! view (JSON strings for content/tags/patterns). Writes accept `BaseMemory`
//! (serializing internally) and reads return `BridgeMemoryRow`.

use std::sync::Arc;

use crate::errors::BridgeResult;
use crate::grounding::{GroundingResult, GroundingSnapshot};

// ── Row types (aligned with storage/tables.rs + query/cortex_queries.rs) ──

/// Raw row from bridge_memories table.
#[derive(Debug, Clone)]
pub struct BridgeMemoryRow {
    pub id: String,
    pub memory_type: String,
    pub content: String,
    pub summary: String,
    pub confidence: f64,
    pub importance: String,
    pub tags: String,
    pub linked_patterns: String,
    pub created_at: i64,
}

/// Row from bridge_grounding_results table.
#[derive(Debug, Clone)]
pub struct GroundingResultRow {
    pub memory_id: String,
    pub grounding_score: f64,
    pub classification: String,
    pub evidence: String,
    pub created_at: i64,
}

/// Row from bridge_grounding_snapshots table.
#[derive(Debug, Clone)]
pub struct GroundingSnapshotRow {
    pub total_memories: u32,
    pub grounded_count: u32,
    pub validated_count: u32,
    pub partial_count: u32,
    pub weak_count: u32,
    pub invalidated_count: u32,
    pub avg_score: f64,
    pub error_count: u32,
    pub trigger_type: Option<String>,
    pub created_at: i64,
}

/// Row from bridge_event_log table.
#[derive(Debug, Clone)]
pub struct BridgeEventRow {
    pub event_type: String,
    pub memory_type: Option<String>,
    pub memory_id: Option<String>,
    pub confidence: Option<f64>,
    pub created_at: i64,
}

/// Row from bridge_metrics table.
#[derive(Debug, Clone)]
pub struct BridgeMetricRow {
    pub metric_name: String,
    pub metric_value: f64,
    pub created_at: i64,
}

/// Storage statistics.
#[derive(Debug, Clone, Default)]
pub struct BridgeStorageStats {
    pub memory_count: u64,
    pub event_count: u64,
    pub grounding_result_count: u64,
    pub snapshot_count: u64,
    pub metric_count: u64,
}

/// Health status of bridge storage.
#[derive(Debug, Clone)]
pub struct BridgeHealthStatus {
    pub connected: bool,
    pub wal_mode: bool,
}

// ── CortexMemoryWriter trait ──

/// Optional writer for dual-writing memories to cortex.db (P0-3).
///
/// Implemented in drift-napi when cortex.db is available. The bridge crate
/// does not depend on cortex-storage — this trait decouples the two. When
/// provided to `BridgeEventHandler`, every memory created by the event mapper
/// is also written to cortex.db so it is visible to Cortex retrieval.
///
/// Failures are non-fatal: bridge storage is the source of truth. Cortex
/// write failures are logged but do not fail the event processing pipeline.
pub trait CortexMemoryWriter: Send + Sync {
    /// Write a memory to cortex.db. Returns Ok(()) on success.
    fn write_memory(&self, memory: &cortex_core::memory::BaseMemory) -> BridgeResult<()>;
}

// ── IBridgeStorage trait ──

/// Abstraction over bridge.db storage operations.
///
/// 23 methods: 7 writes + 7 reads + 3 ad-hoc queries + 4 lifecycle + 2 usage.
pub trait IBridgeStorage: Send + Sync {
    // ── 7 Writes ──

    /// Store a memory in bridge_memories (deduplicates by summary+type).
    fn insert_memory(&self, memory: &cortex_core::memory::BaseMemory) -> BridgeResult<()>;

    /// Record a grounding result.
    fn insert_grounding_result(&self, result: &GroundingResult) -> BridgeResult<()>;

    /// Record a grounding snapshot.
    fn insert_snapshot(&self, snapshot: &GroundingSnapshot) -> BridgeResult<()>;

    /// Log an event in bridge_event_log.
    fn insert_event(
        &self,
        event_type: &str,
        memory_type: Option<&str>,
        memory_id: Option<&str>,
        confidence: Option<f64>,
    ) -> BridgeResult<()>;

    /// Record a metric in bridge_metrics.
    fn insert_metric(&self, key: &str, value: f64) -> BridgeResult<()>;

    /// Update a memory's confidence after grounding adjustment.
    fn update_memory_confidence(&self, memory_id: &str, delta: f64) -> BridgeResult<()>;

    /// Upsert adaptive weight for a spec section.
    fn upsert_weight(&self, section: &str, weight: f64) -> BridgeResult<()>;

    // ── 7 Reads ──

    /// Get a memory by ID.
    fn get_memory(&self, id: &str) -> BridgeResult<Option<BridgeMemoryRow>>;

    /// Query memories by type (newest first).
    fn query_memories_by_type(
        &self,
        memory_type: &str,
        limit: usize,
    ) -> BridgeResult<Vec<BridgeMemoryRow>>;

    /// Get grounding history for a memory.
    fn get_grounding_history(
        &self,
        memory_id: &str,
        limit: usize,
    ) -> BridgeResult<Vec<(f64, String, i64)>>;

    /// Get recent snapshots.
    fn get_snapshots(&self, limit: usize) -> BridgeResult<Vec<GroundingSnapshotRow>>;

    /// Get recent events.
    fn get_events(&self, limit: usize) -> BridgeResult<Vec<BridgeEventRow>>;

    /// Get metrics by key.
    fn get_metrics(&self, key: &str) -> BridgeResult<Vec<BridgeMetricRow>>;

    /// Get the current schema version.
    fn get_schema_version(&self) -> BridgeResult<u32>;

    // ── 3 Formalized ad-hoc queries ──

    /// Query all memories suitable for grounding (max 500, newest first).
    fn query_all_memories_for_grounding(&self) -> BridgeResult<Vec<BridgeMemoryRow>>;

    /// Search memories by tag (exact JSON match).
    fn search_memories_by_tag(
        &self,
        tag: &str,
        limit: usize,
    ) -> BridgeResult<Vec<BridgeMemoryRow>>;

    /// Get the previous grounding score for a memory.
    fn get_previous_grounding_score(&self, memory_id: &str) -> BridgeResult<Option<f64>>;

    // ── 4 Lifecycle ──

    /// Initialize storage (create tables, run migrations).
    fn initialize(&self) -> BridgeResult<()>;

    /// Run schema migrations.
    fn migrate(&self) -> BridgeResult<()>;

    /// Health check.
    fn health_check(&self) -> BridgeResult<BridgeHealthStatus>;

    /// Shutdown (no-op for SQLite, close pools for cloud).
    fn shutdown(&self) -> BridgeResult<()>;

    // ── 2 Usage ──

    /// Count total memories.
    fn count_memories(&self) -> BridgeResult<u64>;

    /// Get storage statistics.
    fn storage_stats(&self) -> BridgeResult<BridgeStorageStats>;
}

// ── Arc<T> blanket impl ──

impl<T: IBridgeStorage + ?Sized> IBridgeStorage for Arc<T> {
    fn insert_memory(&self, memory: &cortex_core::memory::BaseMemory) -> BridgeResult<()> {
        (**self).insert_memory(memory)
    }
    fn insert_grounding_result(&self, result: &GroundingResult) -> BridgeResult<()> {
        (**self).insert_grounding_result(result)
    }
    fn insert_snapshot(&self, snapshot: &GroundingSnapshot) -> BridgeResult<()> {
        (**self).insert_snapshot(snapshot)
    }
    fn insert_event(
        &self,
        event_type: &str,
        memory_type: Option<&str>,
        memory_id: Option<&str>,
        confidence: Option<f64>,
    ) -> BridgeResult<()> {
        (**self).insert_event(event_type, memory_type, memory_id, confidence)
    }
    fn insert_metric(&self, key: &str, value: f64) -> BridgeResult<()> {
        (**self).insert_metric(key, value)
    }
    fn update_memory_confidence(&self, memory_id: &str, delta: f64) -> BridgeResult<()> {
        (**self).update_memory_confidence(memory_id, delta)
    }
    fn upsert_weight(&self, section: &str, weight: f64) -> BridgeResult<()> {
        (**self).upsert_weight(section, weight)
    }
    fn get_memory(&self, id: &str) -> BridgeResult<Option<BridgeMemoryRow>> {
        (**self).get_memory(id)
    }
    fn query_memories_by_type(
        &self,
        memory_type: &str,
        limit: usize,
    ) -> BridgeResult<Vec<BridgeMemoryRow>> {
        (**self).query_memories_by_type(memory_type, limit)
    }
    fn get_grounding_history(
        &self,
        memory_id: &str,
        limit: usize,
    ) -> BridgeResult<Vec<(f64, String, i64)>> {
        (**self).get_grounding_history(memory_id, limit)
    }
    fn get_snapshots(&self, limit: usize) -> BridgeResult<Vec<GroundingSnapshotRow>> {
        (**self).get_snapshots(limit)
    }
    fn get_events(&self, limit: usize) -> BridgeResult<Vec<BridgeEventRow>> {
        (**self).get_events(limit)
    }
    fn get_metrics(&self, key: &str) -> BridgeResult<Vec<BridgeMetricRow>> {
        (**self).get_metrics(key)
    }
    fn get_schema_version(&self) -> BridgeResult<u32> {
        (**self).get_schema_version()
    }
    fn query_all_memories_for_grounding(&self) -> BridgeResult<Vec<BridgeMemoryRow>> {
        (**self).query_all_memories_for_grounding()
    }
    fn search_memories_by_tag(
        &self,
        tag: &str,
        limit: usize,
    ) -> BridgeResult<Vec<BridgeMemoryRow>> {
        (**self).search_memories_by_tag(tag, limit)
    }
    fn get_previous_grounding_score(&self, memory_id: &str) -> BridgeResult<Option<f64>> {
        (**self).get_previous_grounding_score(memory_id)
    }
    fn initialize(&self) -> BridgeResult<()> {
        (**self).initialize()
    }
    fn migrate(&self) -> BridgeResult<()> {
        (**self).migrate()
    }
    fn health_check(&self) -> BridgeResult<BridgeHealthStatus> {
        (**self).health_check()
    }
    fn shutdown(&self) -> BridgeResult<()> {
        (**self).shutdown()
    }
    fn count_memories(&self) -> BridgeResult<u64> {
        (**self).count_memories()
    }
    fn storage_stats(&self) -> BridgeResult<BridgeStorageStats> {
        (**self).storage_stats()
    }
}

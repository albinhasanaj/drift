//! CP0-G-03: Cloud-swap simulation — Bridge.
//!
//! MockBridgeStorage + MockDriftReader: In-memory implementations proving
//! the bridge trait boundary is sufficient for a Postgres backend.

use std::sync::{Arc, Mutex};

use cortex_drift_bridge::errors::BridgeResult;
use cortex_drift_bridge::grounding::{GroundingResult, GroundingSnapshot};
use cortex_drift_bridge::traits::{
    BridgeEventRow, BridgeHealthStatus, BridgeMemoryRow, BridgeMetricRow,
    BridgeStorageStats, GroundingSnapshotRow, IBridgeStorage,
};
use drift_core::errors::StorageError;
use drift_core::traits::storage::drift_reader::IDriftReader;

/// In-memory mock implementing IBridgeStorage.
struct MockBridgeStorage {
    memories: Mutex<Vec<BridgeMemoryRow>>,
    events: Mutex<Vec<BridgeEventRow>>,
    metrics: Mutex<Vec<BridgeMetricRow>>,
    version: u32,
}

impl MockBridgeStorage {
    fn new() -> Self {
        Self {
            memories: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            metrics: Mutex::new(Vec::new()),
            version: 1,
        }
    }
}

impl IBridgeStorage for MockBridgeStorage {
    fn insert_memory(&self, memory: &cortex_core::memory::BaseMemory) -> BridgeResult<()> {
        self.memories.lock().unwrap().push(BridgeMemoryRow {
            id: memory.id.clone(),
            memory_type: format!("{:?}", memory.memory_type),
            content: memory.content.clone(),
            summary: memory.summary.clone().unwrap_or_default(),
            confidence: memory.confidence,
            importance: memory.importance,
            tags: serde_json::to_string(&memory.tags).unwrap_or_default(),
            linked_patterns: String::new(),
            created_at: String::new(),
        });
        Ok(())
    }
    fn insert_grounding_result(&self, _result: &GroundingResult) -> BridgeResult<()> { Ok(()) }
    fn insert_snapshot(&self, _snapshot: &GroundingSnapshot) -> BridgeResult<()> { Ok(()) }
    fn insert_event(&self, event_type: &str, memory_type: Option<&str>, memory_id: Option<&str>, confidence: Option<f64>) -> BridgeResult<()> {
        self.events.lock().unwrap().push(BridgeEventRow {
            event_type: event_type.to_string(),
            memory_type: memory_type.map(String::from),
            memory_id: memory_id.map(String::from),
            confidence,
            created_at: String::new(),
        });
        Ok(())
    }
    fn insert_metric(&self, key: &str, value: f64) -> BridgeResult<()> {
        self.metrics.lock().unwrap().push(BridgeMetricRow {
            metric_name: key.to_string(),
            metric_value: value,
            created_at: String::new(),
        });
        Ok(())
    }
    fn update_memory_confidence(&self, _memory_id: &str, _delta: f64) -> BridgeResult<()> { Ok(()) }
    fn upsert_weight(&self, _section: &str, _weight: f64) -> BridgeResult<()> { Ok(()) }
    fn get_memory(&self, id: &str) -> BridgeResult<Option<BridgeMemoryRow>> {
        Ok(self.memories.lock().unwrap().iter().find(|m| m.id == id).cloned())
    }
    fn query_memories_by_type(&self, memory_type: &str, limit: usize) -> BridgeResult<Vec<BridgeMemoryRow>> {
        Ok(self.memories.lock().unwrap().iter().filter(|m| m.memory_type == memory_type).take(limit).cloned().collect())
    }
    fn get_grounding_history(&self, _memory_id: &str, _limit: usize) -> BridgeResult<Vec<(f64, String, i64)>> { Ok(vec![]) }
    fn get_snapshots(&self, _limit: usize) -> BridgeResult<Vec<GroundingSnapshotRow>> { Ok(vec![]) }
    fn get_events(&self, limit: usize) -> BridgeResult<Vec<BridgeEventRow>> {
        Ok(self.events.lock().unwrap().iter().rev().take(limit).cloned().collect())
    }
    fn get_metrics(&self, key: &str) -> BridgeResult<Vec<BridgeMetricRow>> {
        Ok(self.metrics.lock().unwrap().iter().filter(|m| m.metric_name == key).cloned().collect())
    }
    fn get_schema_version(&self) -> BridgeResult<u32> { Ok(self.version) }
    fn query_all_memories_for_grounding(&self) -> BridgeResult<Vec<BridgeMemoryRow>> {
        Ok(self.memories.lock().unwrap().clone())
    }
    fn search_memories_by_tag(&self, _tag: &str, _limit: usize) -> BridgeResult<Vec<BridgeMemoryRow>> { Ok(vec![]) }
    fn get_previous_grounding_score(&self, _memory_id: &str) -> BridgeResult<Option<f64>> { Ok(None) }
    fn initialize(&self) -> BridgeResult<()> { Ok(()) }
    fn migrate(&self) -> BridgeResult<()> { Ok(()) }
    fn health_check(&self) -> BridgeResult<BridgeHealthStatus> {
        Ok(BridgeHealthStatus { connected: true, wal_mode: false })
    }
    fn shutdown(&self) -> BridgeResult<()> { Ok(()) }
    fn count_memories(&self) -> BridgeResult<u64> {
        Ok(self.memories.lock().unwrap().len() as u64)
    }
    fn storage_stats(&self) -> BridgeResult<BridgeStorageStats> {
        Ok(BridgeStorageStats {
            memory_count: self.memories.lock().unwrap().len() as u64,
            event_count: self.events.lock().unwrap().len() as u64,
            grounding_result_count: 0,
            snapshot_count: 0,
            metric_count: self.metrics.lock().unwrap().len() as u64,
        })
    }
}

/// In-memory mock implementing IDriftReader.
struct MockDriftReader {
    pattern_scores: Mutex<std::collections::HashMap<String, f64>>,
}

impl MockDriftReader {
    fn new() -> Self {
        Self { pattern_scores: Mutex::new(std::collections::HashMap::new()) }
    }
    fn set_pattern_confidence(&self, pid: &str, score: f64) {
        self.pattern_scores.lock().unwrap().insert(pid.to_string(), score);
    }
}

impl IDriftReader for MockDriftReader {
    fn pattern_confidence(&self, pid: &str) -> Result<Option<f64>, StorageError> {
        Ok(self.pattern_scores.lock().unwrap().get(pid).copied())
    }
    fn pattern_occurrence_rate(&self, _pid: &str) -> Result<Option<f64>, StorageError> { Ok(Some(0.5)) }
    fn false_positive_rate(&self, _pid: &str) -> Result<Option<f64>, StorageError> { Ok(Some(0.1)) }
    fn constraint_verified(&self, _cid: &str) -> Result<Option<bool>, StorageError> { Ok(Some(true)) }
    fn coupling_metric(&self, _module: &str) -> Result<Option<f64>, StorageError> { Ok(Some(0.3)) }
    fn dna_health(&self) -> Result<Option<f64>, StorageError> { Ok(Some(0.85)) }
    fn test_coverage(&self, _fid: &str) -> Result<Option<f64>, StorageError> { Ok(Some(0.7)) }
    fn error_handling_gaps(&self, _fp: &str) -> Result<Option<u32>, StorageError> { Ok(Some(2)) }
    fn decision_evidence(&self, _did: &str) -> Result<Option<f64>, StorageError> { Ok(Some(0.6)) }
    fn boundary_data(&self, _bid: &str) -> Result<Option<f64>, StorageError> { Ok(Some(0.9)) }
    fn taint_flow_risk(&self, _file: &str) -> Result<Option<u32>, StorageError> { Ok(Some(1)) }
    fn call_graph_coverage(&self, _fid: &str) -> Result<Option<f64>, StorageError> { Ok(Some(0.4)) }
    fn count_matching_patterns(&self, pids: &[String]) -> Result<u32, StorageError> {
        let store = self.pattern_scores.lock().unwrap();
        Ok(pids.iter().filter(|p| store.contains_key(*p)).count() as u32)
    }
    fn latest_scan_timestamp(&self) -> Result<Option<String>, StorageError> {
        Ok(Some("2026-02-11T00:00:00Z".to_string()))
    }
}

#[test]
fn ct0_g03_bridge_mock_storage_works() {
    let bridge = MockBridgeStorage::new();
    let storage: &dyn IBridgeStorage = &bridge;

    // Initialize
    storage.initialize().unwrap();

    // Insert event
    storage.insert_event("test.mock", Some("pattern"), None, Some(0.8)).unwrap();
    let events = storage.get_events(10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "test.mock");

    // Insert metric
    storage.insert_metric("mock_metric", 99.0).unwrap();
    let metrics = storage.get_metrics("mock_metric").unwrap();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].metric_value, 99.0);

    // Health check
    let health = storage.health_check().unwrap();
    assert!(health.connected);

    // Storage stats
    let stats = storage.storage_stats().unwrap();
    assert_eq!(stats.event_count, 1);
    assert_eq!(stats.metric_count, 1);
}

#[test]
fn ct0_g03_drift_reader_mock_provides_evidence() {
    let reader = MockDriftReader::new();
    reader.set_pattern_confidence("pattern-123", 0.85);

    let reader_trait: &dyn IDriftReader = &reader;
    assert_eq!(reader_trait.pattern_confidence("pattern-123").unwrap(), Some(0.85));
    assert_eq!(reader_trait.pattern_confidence("nonexistent").unwrap(), None);
    assert_eq!(reader_trait.dna_health().unwrap(), Some(0.85));
    assert_eq!(reader_trait.latest_scan_timestamp().unwrap(), Some("2026-02-11T00:00:00Z".to_string()));

    let count = reader_trait.count_matching_patterns(&["pattern-123".into(), "unknown".into()]).unwrap();
    assert_eq!(count, 1);
}

#[test]
fn ct0_g03_mock_works_behind_arc() {
    let bridge = Arc::new(MockBridgeStorage::new());
    let storage: Arc<dyn IBridgeStorage> = bridge.clone();
    storage.insert_metric("arc_test", 1.0).unwrap();
    assert_eq!(storage.count_memories().unwrap(), 0);

    let reader = Arc::new(MockDriftReader::new());
    let reader_trait: Arc<dyn IDriftReader> = reader.clone();
    assert!(reader_trait.dna_health().unwrap().is_some());
}

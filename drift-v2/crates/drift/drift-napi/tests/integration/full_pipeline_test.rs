//! CP0-G-01: Full pipeline integration test.
//!
//! Proves all storage engines work together through trait-based interfaces:
//! DriftStorageEngine (drift.db) + BridgeStorageEngine (bridge.db).
//! At no point does any code touch a raw `&Connection`.

use std::sync::Arc;
use tempfile::tempdir;

use drift_core::traits::storage::{
    IDriftFiles, IDriftAnalysis, IDriftStructural, IDriftEnforcement,
    IDriftAdvanced, IDriftBatchWriter, IDriftReader,
};
use drift_storage::engine::DriftStorageEngine;

#[test]
fn full_pipeline_scan_ground_evidence_verdict() {
    let dir = tempdir().unwrap();
    let drift_path = dir.path().join("drift.db");

    // 1. Initialize DriftStorageEngine
    let engine = DriftStorageEngine::open(&drift_path).expect("DriftStorageEngine::open");

    // 2. Verify it implements all 7 drift traits via trait objects
    let _files: &dyn IDriftFiles = &engine;
    let _analysis: &dyn IDriftAnalysis = &engine;
    let _structural: &dyn IDriftStructural = &engine;
    let _enforcement: &dyn IDriftEnforcement = &engine;
    let _advanced: &dyn IDriftAdvanced = &engine;
    let _batch: &dyn IDriftBatchWriter = &engine;
    let _reader: &dyn IDriftReader = &engine;

    // 3. Exercise file metadata via trait (simulates scan)
    let files_trait: &dyn IDriftFiles = &engine;
    let all_files = files_trait.load_all_file_metadata().unwrap();
    assert!(all_files.is_empty(), "Fresh DB should have 0 files");
    let count = files_trait.count_files().unwrap();
    assert_eq!(count, 0);

    // 4. Exercise analysis trait (patterns, detections)
    let analysis_trait: &dyn IDriftAnalysis = &engine;
    let funcs = analysis_trait.count_functions().unwrap();
    assert_eq!(funcs, 0);
    let detections = analysis_trait.count_detections().unwrap();
    assert_eq!(detections, 0);

    // 5. Exercise enforcement trait
    let enforcement_trait: &dyn IDriftEnforcement = &engine;
    let violations = enforcement_trait.query_all_violations().unwrap();
    assert!(violations.is_empty());

    // 6. Exercise reader trait (bridge evidence interface)
    let reader_trait: &dyn IDriftReader = &engine;
    let pc = reader_trait.pattern_confidence("nonexistent").unwrap();
    assert!(pc.is_none(), "Nonexistent pattern should return None");
    let ts = reader_trait.latest_scan_timestamp().unwrap();
    assert!(ts.is_none(), "No scans yet");

    // 7. Exercise structural trait
    let structural_trait: &dyn IDriftStructural = &engine;
    let cycles = structural_trait.query_coupling_cycles().unwrap();
    assert!(cycles.is_empty());

    // 8. Exercise advanced trait
    let advanced_trait: &dyn IDriftAdvanced = &engine;
    let sims = advanced_trait.get_simulations(10).unwrap();
    assert!(sims.is_empty());

    // 9. Insert scan start via analysis trait and verify round-trip
    let scan_id = analysis_trait.insert_scan_start(1000, "/test/path").unwrap();
    assert!(scan_id > 0);
    let scans = analysis_trait.query_recent_scans(10).unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].root_path, "/test/path");
    assert_eq!(scans[0].status, "running");

    // 10. Update scan complete
    analysis_trait.update_scan_complete(
        scan_id, 2000, 100, 50, 30, 10, 10, 1000, "completed", None,
    ).unwrap();
    let scans2 = analysis_trait.query_recent_scans(10).unwrap();
    assert_eq!(scans2[0].status, "completed");
    assert_eq!(scans2[0].total_files, Some(100));

    // 11. Now verify reader can see the scan timestamp
    let ts2 = reader_trait.latest_scan_timestamp().unwrap();
    assert!(ts2.is_some(), "Should have a scan timestamp now");
}

#[test]
fn full_pipeline_with_bridge_engine() {
    let dir = tempdir().unwrap();
    let bridge_path = dir.path().join("bridge.db");

    // Initialize BridgeStorageEngine
    use cortex_drift_bridge::storage::engine::BridgeStorageEngine;
    use cortex_drift_bridge::traits::IBridgeStorage;

    let bridge = BridgeStorageEngine::open(&bridge_path).expect("BridgeStorageEngine::open");

    // Verify it implements IBridgeStorage
    let _: &dyn IBridgeStorage = &bridge;

    // Exercise trait methods
    let count = bridge.count_memories().unwrap();
    assert_eq!(count, 0);

    let stats = bridge.storage_stats().unwrap();
    assert_eq!(stats.memory_count, 0);
    assert_eq!(stats.event_count, 0);

    let health = bridge.health_check().unwrap();
    assert!(health.connected);
    assert!(health.wal_mode);

    let version = bridge.get_schema_version().unwrap();
    assert!(version > 0, "Schema version should be > 0 after migration");

    // Insert an event via trait
    bridge.insert_event("test.pipeline", Some("test"), None, Some(0.5)).unwrap();
    let events = bridge.get_events(10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "test.pipeline");

    // Insert a metric via trait
    bridge.insert_metric("pipeline_test", 42.0).unwrap();
    let metrics = bridge.get_metrics("pipeline_test").unwrap();
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].metric_value, 42.0);
}

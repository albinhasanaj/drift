//! CT0-G-07: All engines Send + Sync (compile-time verified)
//! CT0-G-08: All engines work behind Arc (compile-time verified)

use std::sync::Arc;
use tempfile::tempdir;

use drift_core::traits::storage::{
    IDriftFiles, IDriftAnalysis, IDriftStructural, IDriftEnforcement,
    IDriftAdvanced, IDriftBatchWriter, IDriftReader,
};
use drift_storage::engine::DriftStorageEngine;

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn ct0_g07_drift_storage_engine_is_send_sync() {
    assert_send_sync::<DriftStorageEngine>();
}

#[test]
fn ct0_g07_bridge_storage_engine_is_send_sync() {
    use cortex_drift_bridge::storage::engine::BridgeStorageEngine;
    assert_send_sync::<BridgeStorageEngine>();
}

#[test]
fn ct0_g08_drift_engine_works_behind_arc() {
    let dir = tempdir().unwrap();
    let engine = Arc::new(
        DriftStorageEngine::open(&dir.path().join("drift.db")).unwrap()
    );

    // Verify trait methods callable through Arc
    let files: Arc<dyn IDriftFiles> = engine.clone();
    let _ = files.count_files().unwrap();

    let analysis: Arc<dyn IDriftAnalysis> = engine.clone();
    let _ = analysis.count_functions().unwrap();

    let structural: Arc<dyn IDriftStructural> = engine.clone();
    let _ = structural.query_coupling_cycles().unwrap();

    let enforcement: Arc<dyn IDriftEnforcement> = engine.clone();
    let _ = enforcement.query_all_violations().unwrap();

    let advanced: Arc<dyn IDriftAdvanced> = engine.clone();
    let _ = advanced.get_simulations(1).unwrap();

    let reader: Arc<dyn IDriftReader> = engine.clone();
    let _ = reader.pattern_confidence("test").unwrap();
}

#[test]
fn ct0_g08_bridge_engine_works_behind_arc() {
    use cortex_drift_bridge::storage::engine::BridgeStorageEngine;
    use cortex_drift_bridge::traits::IBridgeStorage;

    let dir = tempdir().unwrap();
    let engine = Arc::new(
        BridgeStorageEngine::open(&dir.path().join("bridge.db")).unwrap()
    );

    let storage: Arc<dyn IBridgeStorage> = engine.clone();
    let _ = storage.count_memories().unwrap();
    let _ = storage.health_check().unwrap();
    let _ = storage.get_schema_version().unwrap();
}

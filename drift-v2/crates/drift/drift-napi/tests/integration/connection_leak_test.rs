//! CP0-G-05 / CT0-G-09: Connection leak test.
//! Runs 1000 mixed operations, drops engine, verifies no file locks remain.

use tempfile::tempdir;
use drift_core::traits::storage::{IDriftFiles, IDriftAnalysis, IDriftReader, IDriftEnforcement};
use drift_storage::engine::DriftStorageEngine;

#[test]
fn ct0_g09_no_connection_leaks_after_1000_operations() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");

    {
        let engine = DriftStorageEngine::open(&db_path).unwrap();

        // Run 1000 mixed read operations through trait interfaces
        let files: &dyn IDriftFiles = &engine;
        let analysis: &dyn IDriftAnalysis = &engine;
        let reader: &dyn IDriftReader = &engine;
        let enforcement: &dyn IDriftEnforcement = &engine;

        for i in 0..250 {
            let _ = files.get_file_metadata(&format!("file_{}.ts", i));
            let _ = analysis.count_functions();
            let _ = reader.pattern_confidence(&format!("pattern_{}", i));
            let _ = enforcement.query_all_violations();
        }

        // Engine drops here
    }

    // Verify: database file can be opened by another process (not locked)
    let verify = rusqlite::Connection::open(&db_path);
    assert!(verify.is_ok(), "Database should not be locked after engine drop");

    // Verify: can run queries on the re-opened connection
    let conn = verify.unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0, "Should have 0 files (we only did reads)");
}

#[test]
fn ct0_g09_bridge_no_leaks_after_1000_ops() {
    use cortex_drift_bridge::storage::engine::BridgeStorageEngine;
    use cortex_drift_bridge::traits::IBridgeStorage;

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("bridge.db");

    {
        let engine = BridgeStorageEngine::open(&db_path).unwrap();
        let storage: &dyn IBridgeStorage = &engine;

        for i in 0..500 {
            let _ = storage.count_memories();
            let _ = storage.get_events(1);
        }
    }

    // Verify no file lock
    let verify = rusqlite::Connection::open(&db_path);
    assert!(verify.is_ok(), "Bridge DB should not be locked after engine drop");
}

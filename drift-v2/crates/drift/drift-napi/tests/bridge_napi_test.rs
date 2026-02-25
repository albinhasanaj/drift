//! Bridge NAPI tests — BT-NAPI-16 through BT-NAPI-18.
//!
//! Tests the bridge runtime lifecycle: bridge.db creation alongside drift.db,
//! non-fatal failure when bridge init fails, and table verification.

use std::path::Path;

use cortex_drift_bridge::storage;
use cortex_drift_bridge::storage::schema::BRIDGE_TABLE_NAMES;
use tempfile::TempDir;

/// Helper: open bridge.db the same way DriftRuntime does.
fn open_bridge_db(path: &Path) -> rusqlite::Connection {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let conn = rusqlite::Connection::open(path).unwrap();
    storage::configure_connection(&conn).unwrap();
    storage::migrate(&conn).unwrap();
    conn
}

// ---- BT-NAPI-16: DriftRuntime opens bridge.db alongside drift.db during init ----

#[test]
fn bt_napi_16_bridge_db_created_alongside_drift_db() {
    let dir = TempDir::new().unwrap();
    let drift_dir = dir.path().join(".drift");
    std::fs::create_dir_all(&drift_dir).unwrap();

    // Open drift.db (simulating DriftRuntime)
    let drift_db_path = drift_dir.join("drift.db");
    let _drift_db = drift_storage::DatabaseManager::open(&drift_db_path).unwrap();
    assert!(drift_db_path.exists(), "drift.db should exist");

    // Open bridge.db as sibling (what DriftRuntime::new does)
    let bridge_db_path = drift_dir.join("bridge.db");
    let _bridge_conn = open_bridge_db(&bridge_db_path);

    assert!(bridge_db_path.exists(), "bridge.db should exist alongside drift.db");

    // Both should be in the same directory
    assert_eq!(
        drift_db_path.parent().unwrap(),
        bridge_db_path.parent().unwrap(),
        "drift.db and bridge.db should be siblings in .drift/"
    );
}

// ---- BT-NAPI-17: Bridge init failure → DriftRuntime still works, bridge_initialized = false ----

#[test]
fn bt_napi_17_bridge_init_failure_is_non_fatal() {
    // Simulate what DriftRuntime::new does when bridge init fails:
    // 1. Open drift.db successfully
    // 2. Attempt bridge.db at a bad path → fails
    // 3. DriftRuntime continues with bridge_initialized = false

    let dir = TempDir::new().unwrap();
    let drift_dir = dir.path().join(".drift");
    std::fs::create_dir_all(&drift_dir).unwrap();

    // drift.db works fine
    let drift_db_path = drift_dir.join("drift.db");
    let drift_db = drift_storage::DatabaseManager::open(&drift_db_path).unwrap();
    assert!(drift_db_path.exists());

    // Bridge init at an invalid path should fail
    let bad_bridge_path = Path::new("/nonexistent/deeply/nested/readonly/bridge.db");
    let bridge_result = rusqlite::Connection::open(bad_bridge_path);

    // Simulate the non-fatal pattern from runtime.rs
    let bridge_initialized;
    let mut bridge_db: Option<std::sync::Mutex<rusqlite::Connection>> = None;

    match bridge_result {
        Ok(conn) => {
            // This branch shouldn't be taken for an invalid path on most systems
            bridge_db = Some(std::sync::Mutex::new(conn));
            bridge_initialized = true;
        }
        Err(_e) => {
            // Non-fatal — bridge features unavailable
            bridge_initialized = false;
        }
    }

    // Key assertions: DriftRuntime (drift.db) still works
    drift_db
        .with_reader(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
                .map_err(|e| drift_core::errors::StorageError::SqliteError {
                    message: e.to_string(),
                })?;
            assert_eq!(count, 0, "drift.db should be functional");
            Ok(())
        })
        .unwrap();

    // Bridge should be unavailable
    assert!(!bridge_initialized, "bridge_initialized should be false after failure");
    assert!(bridge_db.is_none(), "bridge_db should be None after failure");
}

// ---- BT-NAPI-18: bridge.db has all 5 bridge tables after init ----

#[test]
fn bt_napi_18_bridge_db_has_all_five_tables() {
    let dir = TempDir::new().unwrap();
    let bridge_db_path = dir.path().join("bridge.db");
    let conn = open_bridge_db(&bridge_db_path);

    // Query sqlite_master for all bridge tables
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'bridge_%' ORDER BY name")
        .unwrap();
    let table_names: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Verify all 5 data tables exist
    for expected in &BRIDGE_TABLE_NAMES {
        assert!(
            table_names.contains(&expected.to_string()),
            "Missing bridge table: {expected}. Found: {table_names:?}"
        );
    }

    // Verify we have at least 5 bridge tables (may also have bridge_schema_version)
    assert!(
        table_names.len() >= 5,
        "Expected at least 5 bridge tables, found {}: {:?}",
        table_names.len(),
        table_names
    );

    // Verify each table is queryable (not just present)
    for table in &BRIDGE_TABLE_NAMES {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
            .unwrap_or_else(|e| panic!("Failed to query {table}: {e}"));
        // bridge_event_log may have 1 row from migration logging
        if *table == "bridge_event_log" {
            assert!(count <= 1, "{table} should have at most 1 migration event, found {count}");
        } else {
            assert_eq!(count, 0, "{table} should be empty after fresh init");
        }
    }

    // Verify indexes exist
    let index_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        index_count >= 4,
        "Expected at least 4 bridge indexes, found {index_count}"
    );
}

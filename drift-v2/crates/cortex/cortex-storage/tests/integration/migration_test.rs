//! Integration test: all migrations run cleanly on fresh DB.

use cortex_storage::StorageEngine;

#[test]
fn test_all_migrations_run_on_fresh_db() {
    let engine = StorageEngine::open_in_memory().unwrap();

    // Verify schema version is 12 by checking we can query the version table.
    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let version: u32 = conn
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(version, 15, "schema should be at version 15");
            Ok(())
        })
        .unwrap();
}

#[test]
fn test_migrations_are_idempotent() {
    // Running open twice on the same DB should not fail.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let _engine1 = StorageEngine::open(&db_path).unwrap();
    drop(_engine1);

    let _engine2 = StorageEngine::open(&db_path).unwrap();
    // If we get here, migrations didn't fail on re-run.
}

#[test]
fn test_all_tables_exist() {
    let engine = StorageEngine::open_in_memory().unwrap();

    let expected_tables = vec![
        "schema_version",
        "memories",
        "memory_relationships",
        "memory_patterns",
        "memory_constraints",
        "memory_files",
        "memory_functions",
        "memory_embeddings",
        "memory_embedding_link",
        "causal_edges",
        "causal_evidence",
        "session_contexts",
        "session_analytics",
        "memory_audit_log",
        "consolidation_metrics",
        "degradation_log",
        "memory_validation_history",
        "memory_contradictions",
        "memory_versions",
        "embedding_model_info",
        "sync_state",
        "sync_log",
        "conflict_log",
        "reclassification_history",
        "reclassification_signals",
        "metric_snapshots",
        "query_performance_log",
        "memory_events",
        "memory_events_archive",
        "memory_snapshots",
        "drift_snapshots",
        "materialized_views",
        // v015: multi-agent tables
        "agent_registry",
        "memory_namespaces",
        "namespace_permissions",
        "memory_projections",
        "provenance_log",
        "agent_trust",
        "delta_queue",
    ];

    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            for table in &expected_tables {
                let exists: bool = conn
                    .prepare(&format!(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='{table}'"
                    ))
                    .unwrap()
                    .exists([])
                    .unwrap();
                assert!(exists, "table '{table}' should exist");
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn test_wal_mode_active() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("wal_test.db");
    let engine = StorageEngine::open(&db_path).unwrap();

    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let mode: String = conn
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .unwrap();
            assert_eq!(mode.to_lowercase(), "wal", "WAL mode should be active");
            Ok(())
        })
        .unwrap();
}

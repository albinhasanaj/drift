//! Integration test: WAL recovery, backup restore.

use chrono::Utc;
use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

fn make_memory(id: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(CoreContent {
            project_name: "backup test".to_string(),
            description: "testing".to_string(),
            metadata: serde_json::json!({}),
        }),
        summary: "backup test".to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: "backup_hash".to_string(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

#[test]
fn test_backup_and_restore() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("original.db");
    let backup_path = dir.path().join("backup.db");

    // Create and populate.
    let engine = StorageEngine::open(&db_path).unwrap();
    engine.create(&make_memory("backup-1")).unwrap();
    engine.create(&make_memory("backup-2")).unwrap();

    // Create backup.
    engine
        .pool()
        .writer
        .with_conn_sync(|conn| cortex_storage::recovery::backup::create_backup(conn, &backup_path))
        .unwrap();

    // Verify backup exists and is valid.
    let backup_engine = StorageEngine::open(&backup_path).unwrap();
    assert!(backup_engine.get("backup-1").unwrap().is_some());
    assert!(backup_engine.get("backup-2").unwrap().is_some());
}

#[test]
fn test_integrity_check() {
    let engine = StorageEngine::open_in_memory().unwrap();

    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let ok = cortex_storage::recovery::integrity_check::check_integrity(conn)?;
            assert!(ok, "integrity check should pass on fresh DB");
            Ok(())
        })
        .unwrap();
}

#[test]
fn test_wal_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("wal_recovery.db");
    let engine = StorageEngine::open(&db_path).unwrap();

    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let recovered = cortex_storage::recovery::wal_recovery::attempt_wal_recovery(conn)?;
            assert!(recovered, "WAL recovery should succeed on healthy DB");
            Ok(())
        })
        .unwrap();
}

//! Cat 15: Compaction, Recovery & Vacuum (MN-01 through MN-08)

use rusqlite::Connection;

use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::pool::pragmas;
use cortex_storage::queries::maintenance;
use cortex_storage::StorageEngine;

fn raw_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    pragmas::apply_pragmas(&conn).unwrap();
    cortex_storage::migrations::run_migrations(&conn).unwrap();
    conn
}

fn make_memory(id: &str) -> BaseMemory {
    let now = chrono::Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: format!("obs {id}"),
        evidence: vec![],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Insight,
        content: tc.clone(),
        summary: format!("summary {id}"),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: now,
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&tc).unwrap(),
    }
}

#[test]
fn mn_01_full_vacuum_succeeds() {
    let conn = raw_conn();
    let result = maintenance::full_vacuum(&conn);
    assert!(result.is_ok(), "VACUUM should succeed on clean DB");
}

#[test]
fn mn_02_incremental_vacuum_succeeds() {
    let conn = raw_conn();
    let result = maintenance::incremental_vacuum(&conn, 100);
    assert!(result.is_ok(), "incremental vacuum should succeed");
}

#[test]
fn mn_03_wal_checkpoint_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mn03.db");
    let engine = StorageEngine::open(&path).unwrap();
    engine.create(&make_memory("mn03")).unwrap();

    let result = engine.pool().writer.with_conn_sync(|conn| {
        maintenance::wal_checkpoint(conn)
    });
    assert!(result.is_ok(), "WAL checkpoint should succeed");
}

#[test]
fn mn_04_integrity_check_passes() {
    let conn = raw_conn();
    let ok = maintenance::integrity_check(&conn).unwrap();
    assert!(ok, "integrity check should pass on clean DB");
}

#[test]
fn mn_05_archived_cleanup_removes_old_low_confidence() {
    let conn = raw_conn();

    // Insert an old, archived, zero-access, low-confidence memory.
    conn.execute(
        "INSERT INTO memories (id, memory_type, content, summary, transaction_time, valid_time,
         confidence, importance, last_accessed, access_count, tags, archived, content_hash)
         VALUES ('old-1', 'insight', '{\"type\":\"insight\",\"data\":{\"observation\":\"x\",\"evidence\":[]}}', 's',
         datetime('now', '-100 days'), datetime('now', '-100 days'),
         0.1, 'low', datetime('now', '-100 days'), 0, '[]', 1, 'h1')",
        [],
    ).unwrap();

    // Insert a recent archived memory that should NOT be cleaned up.
    conn.execute(
        "INSERT INTO memories (id, memory_type, content, summary, transaction_time, valid_time,
         confidence, importance, last_accessed, access_count, tags, archived, content_hash)
         VALUES ('new-1', 'insight', '{\"type\":\"insight\",\"data\":{\"observation\":\"y\",\"evidence\":[]}}', 's',
         datetime('now'), datetime('now'),
         0.1, 'low', datetime('now'), 0, '[]', 1, 'h2')",
        [],
    ).unwrap();

    let deleted = maintenance::archived_cleanup(&conn, 30, 0.3).unwrap();
    assert_eq!(deleted, 1, "should clean up 1 old archived memory");
}

#[test]
fn mn_06_vacuum_after_bulk_delete() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Create and delete 100 memories.
    let batch: Vec<BaseMemory> = (0..100)
        .map(|i| make_memory(&format!("mn06-{i}")))
        .collect();
    storage.create_bulk(&batch).unwrap();

    for i in 0..100 {
        storage.delete(&format!("mn06-{i}")).unwrap();
    }

    // Vacuum should succeed and reclaim space.
    storage.vacuum().unwrap();
}

#[test]
fn mn_07_integrity_check_after_operations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mn07.db");
    let engine = StorageEngine::open(&path).unwrap();

    // Perform various operations.
    for i in 0..20 {
        engine.create(&make_memory(&format!("mn07-{i}"))).unwrap();
    }
    for i in 0..10 {
        engine.delete(&format!("mn07-{i}")).unwrap();
    }

    let ok = engine.pool().writer.with_conn_sync(|conn| {
        maintenance::integrity_check(conn)
    }).unwrap();
    assert!(ok, "integrity check should pass after mixed operations");
}

#[test]
fn mn_08_audit_rotation_preserves_recent() {
    let conn = raw_conn();

    // Insert old entries.
    for i in 0..5 {
        conn.execute(
            "INSERT INTO memory_audit_log (memory_id, operation, actor, details, timestamp)
             VALUES (?1, 'create', 'system', '{}', datetime('now', '-200 days'))",
            rusqlite::params![format!("old-{i}")],
        ).unwrap();
    }
    // Insert recent entries.
    for i in 0..3 {
        conn.execute(
            "INSERT INTO memory_audit_log (memory_id, operation, actor, details, timestamp)
             VALUES (?1, 'create', 'system', '{}', datetime('now'))",
            rusqlite::params![format!("recent-{i}")],
        ).unwrap();
    }

    maintenance::audit_rotation(&conn, 3).unwrap();

    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM memory_audit_log", [], |row| row.get(0))
        .unwrap();
    assert_eq!(total, 3, "recent entries should be preserved");
}

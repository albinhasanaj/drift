//! Cat 14: Observability & Metrics Storage (OB-01 through OB-08)

use rusqlite::Connection;
use cortex_storage::pool::pragmas;

fn raw_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    pragmas::apply_pragmas(&conn).unwrap();
    cortex_storage::migrations::run_migrations(&conn).unwrap();
    conn
}

#[test]
fn ob_01_memory_validation_history_roundtrip() {
    let storage = cortex_storage::StorageEngine::open_in_memory().unwrap();
    // Create a memory first (FK constraint).
    let now = chrono::Utc::now();
    let tc = cortex_core::memory::TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "test".into(), evidence: vec![],
    });
    let mem = cortex_core::memory::BaseMemory {
        id: "m1".into(), memory_type: cortex_core::memory::MemoryType::Insight,
        content: tc.clone(), summary: "s".into(),
        transaction_time: now, valid_time: now, valid_until: None,
        confidence: cortex_core::memory::Confidence::new(0.8),
        importance: cortex_core::memory::Importance::Normal,
        last_accessed: now, access_count: 0,
        linked_patterns: vec![], linked_constraints: vec![],
        linked_files: vec![], linked_functions: vec![],
        tags: vec![], archived: false, superseded_by: None, supersedes: None,
        namespace: Default::default(), source_agent: Default::default(),
        content_hash: cortex_core::memory::BaseMemory::compute_content_hash(&tc).unwrap(),
    };
    cortex_core::traits::IMemoryStorage::create(&storage, &mem).unwrap();

    storage.pool().writer.with_conn_sync(|conn| {
        conn.execute(
            "INSERT INTO memory_validation_history (memory_id, dimension, score, healing_action)
             VALUES ('m1', 'temporal_consistency', 0.95, 'none')",
            [],
        ).unwrap();

        let (dim, score, healing): (String, f64, Option<String>) = conn
            .query_row(
                "SELECT dimension, score, healing_action FROM memory_validation_history WHERE memory_id = 'm1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(dim, "temporal_consistency");
        assert!((score - 0.95).abs() < 1e-10);
        assert_eq!(healing, Some("none".to_string()));
        Ok(())
    }).unwrap();
}

#[test]
fn ob_02_memory_snapshots_roundtrip() {
    let conn = raw_conn();
    let state_blob = b"{\"summary\": \"test\"}";
    conn.execute(
        "INSERT INTO memory_snapshots (memory_id, snapshot_at, state, event_id, reason)
         VALUES ('m2', strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, 1, 'test_snapshot')",
        rusqlite::params![state_blob.as_slice()],
    ).unwrap();

    let (reason, event_id): (String, i64) = conn
        .query_row(
            "SELECT reason, event_id FROM memory_snapshots WHERE memory_id = 'm2'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(reason, "test_snapshot");
    assert_eq!(event_id, 1);
}

#[test]
fn ob_03_memory_events_archive_roundtrip() {
    let conn = raw_conn();
    conn.execute(
        "INSERT INTO memory_events_archive (event_id, memory_id, recorded_at, event_type, delta, actor_type, actor_id, schema_version)
         VALUES (1, 'm3', '2025-01-01T00:00:00.000Z', 'created', '{}', 'system', 'test', 1)",
        [],
    ).unwrap();

    let event_type: String = conn
        .query_row(
            "SELECT event_type FROM memory_events_archive WHERE memory_id = 'm3'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(event_type, "created");
}

#[test]
fn ob_04_event_archival_moves_events() {
    let conn = raw_conn();

    // Insert events.
    for i in 0..5 {
        conn.execute(
            "INSERT INTO memory_events (memory_id, recorded_at, event_type, delta, actor_type, actor_id, schema_version)
             VALUES ('m4', ?1, 'test', '{}', 'system', 'test', 1)",
            rusqlite::params![format!("2024-01-0{i}T00:00:00.000Z", i = i + 1)],
        ).unwrap();
    }

    let max_id: i64 = conn
        .query_row("SELECT MAX(event_id) FROM memory_events WHERE memory_id = 'm4'", [], |row| row.get(0))
        .unwrap();

    let moved = cortex_storage::queries::event_ops::move_events_to_archive(
        &conn, "2024-01-04T00:00:00.000Z", max_id as u64,
    ).unwrap();
    assert!(moved >= 3, "should archive old events. Moved: {moved}");

    let archive_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM memory_events_archive WHERE memory_id = 'm4'", [], |row| row.get(0))
        .unwrap();
    assert!(archive_count >= 3);
}

#[test]
fn ob_05_event_count_query() {
    let conn = raw_conn();
    for i in 0..7 {
        conn.execute(
            "INSERT INTO memory_events (memory_id, recorded_at, event_type, delta, actor_type, actor_id, schema_version)
             VALUES ('m5', strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, '{}', 'system', 'test', 1)",
            rusqlite::params![format!("event_{i}")],
        ).unwrap();
    }

    let count = cortex_storage::queries::event_ops::get_event_count(&conn, "m5").unwrap();
    assert_eq!(count, 7);
}

#[test]
fn ob_06_events_by_type_filter() {
    let conn = raw_conn();
    for etype in &["created", "updated", "created", "archived"] {
        conn.execute(
            "INSERT INTO memory_events (memory_id, recorded_at, event_type, delta, actor_type, actor_id, schema_version)
             VALUES ('m6', strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, '{}', 'system', 'test', 1)",
            rusqlite::params![etype],
        ).unwrap();
    }

    let created = cortex_storage::queries::event_ops::get_events_by_type(&conn, "created", None).unwrap();
    assert_eq!(created.len(), 2, "should find 2 'created' events");
}

#[test]
fn ob_07_events_after_id() {
    let conn = raw_conn();
    let mut ids = Vec::new();
    for i in 0..5 {
        conn.execute(
            "INSERT INTO memory_events (memory_id, recorded_at, event_type, delta, actor_type, actor_id, schema_version)
             VALUES ('m7', strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?1, '{}', 'system', 'test', 1)",
            rusqlite::params![format!("ev_{i}")],
        ).unwrap();
        ids.push(conn.last_insert_rowid() as u64);
    }

    let after = cortex_storage::queries::event_ops::get_events_after_id(&conn, "m7", ids[2], None).unwrap();
    assert_eq!(after.len(), 2, "should get 2 events after id[2]");
}

#[test]
fn ob_08_degradation_log_components() {
    let conn = raw_conn();
    for comp in &["storage", "embeddings", "retrieval", "consolidation"] {
        conn.execute(
            "INSERT INTO degradation_log (component, failure, fallback) VALUES (?1, 'timeout', 'retry')",
            rusqlite::params![comp],
        ).unwrap();
    }

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM degradation_log WHERE component IN ('storage','embeddings','retrieval')", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 3);
}

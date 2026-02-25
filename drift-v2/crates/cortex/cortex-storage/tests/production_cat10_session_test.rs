//! Cat 10: Session & Audit Subsystem (SA-01 through SA-10)

use rusqlite::Connection;

use cortex_storage::pool::pragmas;

fn raw_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    pragmas::apply_pragmas(&conn).unwrap();
    cortex_storage::migrations::run_migrations(&conn).unwrap();
    conn
}

// ═══════════════════════════════════════════════════════════════════════════════
// SA-01: Session create and get roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn sa_01_session_create_roundtrip() {
    let conn = raw_conn();
    cortex_storage::queries::session_ops::create_session(&conn, "s1", 4096).unwrap();
    let exists: bool = conn
        .prepare("SELECT 1 FROM session_contexts WHERE id = 's1'")
        .unwrap()
        .exists([])
        .unwrap();
    assert!(exists, "session should exist after create");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SA-02: Session end sets ended_at
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn sa_02_session_end_sets_ended_at() {
    let conn = raw_conn();
    cortex_storage::queries::session_ops::create_session(&conn, "s2", 4096).unwrap();
    cortex_storage::queries::session_ops::end_session(&conn, "s2").unwrap();

    let ended: Option<String> = conn
        .query_row(
            "SELECT ended_at FROM session_contexts WHERE id = 's2'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(ended.is_some(), "ended_at should be set");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SA-05: Audit log records create/update/delete
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn sa_05_audit_log_crud() {
    use cortex_core::memory::*;
    use cortex_core::traits::IMemoryStorage;

    let storage = cortex_storage::StorageEngine::open_in_memory().unwrap();

    let now = chrono::Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "audit test".into(),
        evidence: vec![],
    });
    let mem = BaseMemory {
        id: "sa05".into(),
        memory_type: MemoryType::Insight,
        content: tc.clone(),
        summary: "s".into(),
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
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&tc).unwrap(),
    };

    storage.create(&mem).unwrap();
    storage.update(&mem).unwrap();
    storage.delete("sa05").unwrap();

    let count: i64 = storage.pool().writer.with_conn_sync(|conn| {
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM memory_audit_log WHERE memory_id = 'sa05'",
            [],
            |row| row.get(0),
        ).unwrap())
    }).unwrap();
    assert!(count >= 3, "should have at least 3 audit entries (create, update, delete). Got {count}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SA-06: Audit log rotation removes old entries
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn sa_06_audit_rotation() {
    let conn = raw_conn();

    // Insert old audit entries.
    for i in 0..10 {
        conn.execute(
            "INSERT INTO memory_audit_log (memory_id, operation, actor, details, timestamp)
             VALUES (?1, 'create', 'system', '{}', datetime('now', ?2))",
            rusqlite::params![format!("rot-{i}"), format!("-{} days", 100 + i)],
        ).unwrap();
    }
    // Insert fresh entries.
    for i in 0..5 {
        conn.execute(
            "INSERT INTO memory_audit_log (memory_id, operation, actor, details, timestamp)
             VALUES (?1, 'create', 'system', '{}', datetime('now'))",
            rusqlite::params![format!("fresh-{i}")],
        ).unwrap();
    }

    let deleted = cortex_storage::queries::maintenance::audit_rotation(&conn, 2).unwrap();
    assert!(deleted >= 10, "should rotate old entries. Deleted: {deleted}");

    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM memory_audit_log", [], |row| row.get(0))
        .unwrap();
    assert_eq!(remaining, 5, "fresh entries should remain");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SA-07: Consolidation metrics roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn sa_07_consolidation_metrics_roundtrip() {
    let conn = raw_conn();
    conn.execute(
        "INSERT INTO consolidation_metrics (run_id, precision_score, compression_ratio, memories_created, memories_archived)
         VALUES ('run-1', 0.95, 0.6, 5, 3)",
        [],
    ).unwrap();

    let (run_id, created, archived): (String, i64, i64) = conn
        .query_row(
            "SELECT run_id, memories_created, memories_archived FROM consolidation_metrics LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(run_id, "run-1");
    assert_eq!(created, 5);
    assert_eq!(archived, 3);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SA-08: Degradation log records events
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn sa_08_degradation_log() {
    let conn = raw_conn();
    conn.execute(
        "INSERT INTO degradation_log (component, failure, fallback, details) VALUES ('storage', 'timeout', 'retry', '{}')",
        [],
    ).unwrap();

    let (component, failure, fallback): (String, String, String) = conn
        .query_row(
            "SELECT component, failure, fallback FROM degradation_log LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(component, "storage");
    assert_eq!(failure, "timeout");
    assert_eq!(fallback, "retry");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SA-09: Session analytics roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn sa_09_session_analytics() {
    let conn = raw_conn();
    cortex_storage::queries::session_ops::create_session(&conn, "s9", 4096).unwrap();

    conn.execute(
        "INSERT INTO session_analytics (session_id, event_type, event_data)
         VALUES ('s9', 'tool_call', '{\"tool\": \"search\"}')",
        [],
    ).unwrap();

    let event_type: String = conn
        .query_row(
            "SELECT event_type FROM session_analytics WHERE session_id = 's9'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(event_type, "tool_call");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SA-10: Audit actor serialization
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn sa_10_audit_actor_serialization() {
    let conn = raw_conn();
    conn.execute(
        "INSERT INTO memory_audit_log (memory_id, operation, actor, details) VALUES ('a10', 'create', 'system', '{}')",
        [],
    ).unwrap();
    conn.execute(
        "INSERT INTO memory_audit_log (memory_id, operation, actor, details) VALUES ('a10', 'update', 'user:alice', '{}')",
        [],
    ).unwrap();

    let actors: Vec<String> = conn
        .prepare("SELECT actor FROM memory_audit_log WHERE memory_id = 'a10' ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(actors, vec!["system", "user:alice"]);
}

//! Cat 11: Multi-Agent Namespace Isolation (MA-01 through MA-12)

use rusqlite::Connection;

use cortex_core::memory::*;
use cortex_core::models::agent::AgentId;
use cortex_core::models::namespace::{NamespaceId, NamespaceScope};
use cortex_core::traits::IMemoryStorage;
use cortex_storage::pool::pragmas;
use cortex_storage::StorageEngine;

fn raw_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    pragmas::apply_pragmas(&conn).unwrap();
    cortex_storage::migrations::run_migrations(&conn).unwrap();
    conn
}

fn make_memory_ns(id: &str, ns: &NamespaceId) -> BaseMemory {
    let now = chrono::Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: format!("obs {id}"),
        evidence: vec![],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
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
        tags: vec!["important".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: ns.clone(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&tc).unwrap(),
    }
}

fn ns(name: &str) -> NamespaceId {
    NamespaceId {
        scope: NamespaceScope::Agent(AgentId::from(name)),
        name: name.to_string(),
    }
}

fn ensure_agent(conn: &Connection, agent_id: &str) {
    conn.execute(
        "INSERT OR IGNORE INTO agent_registry (agent_id, name, namespace_id, capabilities, registered_at, last_active)
         VALUES (?1, ?1, 'agent://default/', '[]', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        rusqlite::params![agent_id],
    ).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-01: agent_registry roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_01_agent_registry_roundtrip() {
    let conn = raw_conn();
    conn.execute(
        "INSERT INTO agent_registry (agent_id, name, namespace_id, capabilities, registered_at, last_active)
         VALUES ('bot1', 'TestBot', 'agent://bot1/', '[\"search\",\"embed\"]', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [],
    ).unwrap();

    let (name, caps, status): (String, String, String) = conn
        .query_row(
            "SELECT name, capabilities, status FROM agent_registry WHERE agent_id = 'bot1'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(name, "TestBot");
    assert_eq!(status, "active");
    let parsed: Vec<String> = serde_json::from_str(&caps).unwrap();
    assert_eq!(parsed, vec!["search", "embed"]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-02: memory_namespaces scope + name uniqueness
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_02_namespace_uniqueness() {
    let conn = raw_conn();
    ensure_agent(&conn, "bot1");
    conn.execute(
        "INSERT INTO memory_namespaces (namespace_id, scope, owner_agent, created_at)
         VALUES ('agent://bot1/', 'agent', 'bot1', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [],
    ).unwrap();

    let result = conn.execute(
        "INSERT INTO memory_namespaces (namespace_id, scope, owner_agent, created_at)
         VALUES ('agent://bot1/', 'agent', 'bot1', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [],
    );
    assert!(result.is_err(), "duplicate namespace should fail");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-03: namespace_permissions CRUD
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_03_namespace_permissions_crud() {
    let conn = raw_conn();
    ensure_agent(&conn, "bot2");
    // Create namespace first (FK constraint).
    conn.execute(
        "INSERT INTO memory_namespaces (namespace_id, scope, owner_agent, created_at)
         VALUES ('agent://ns1/', 'agent', 'bot2', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [],
    ).unwrap();

    conn.execute(
        "INSERT INTO namespace_permissions (namespace_id, agent_id, permissions, granted_at, granted_by)
         VALUES ('agent://ns1/', 'bot2', 'read', strftime('%Y-%m-%dT%H:%M:%fZ','now'), 'bot2')",
        [],
    ).unwrap();

    let perms: String = conn
        .query_row(
            "SELECT permissions FROM namespace_permissions WHERE agent_id = 'bot2' AND namespace_id = 'agent://ns1/'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(perms, "read");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-04: Namespace filter isolates query_by_type
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_04_namespace_isolates_query_by_type() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let ns1 = ns("bot1");
    let ns2 = ns("bot2");

    for i in 0..3 {
        storage.create(&make_memory_ns(&format!("ma04-ns1-{i}"), &ns1)).unwrap();
    }
    for i in 0..2 {
        storage.create(&make_memory_ns(&format!("ma04-ns2-{i}"), &ns2)).unwrap();
    }

    let results = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::memory_query::query_by_type(conn, MemoryType::Core, Some(&ns1))
    }).unwrap();
    assert_eq!(results.len(), 3, "namespace filter should isolate to ns1 only");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-05: Namespace filter isolates query_by_confidence_range
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_05_namespace_isolates_confidence_query() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let ns1 = ns("bot1");
    let ns2 = ns("bot2");

    for i in 0..3 {
        let mut mem = make_memory_ns(&format!("ma05-ns1-{i}"), &ns1);
        mem.confidence = Confidence::new(0.7);
        storage.create(&mem).unwrap();
    }
    for i in 0..2 {
        let mut mem = make_memory_ns(&format!("ma05-ns2-{i}"), &ns2);
        mem.confidence = Confidence::new(0.7);
        storage.create(&mem).unwrap();
    }

    let results = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::memory_query::query_by_confidence_range(conn, 0.5, 1.0, Some(&ns1))
    }).unwrap();
    assert_eq!(results.len(), 3, "should only return ns1 memories");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-06: Namespace filter isolates query_by_tags
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_06_namespace_isolates_tag_query() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let ns1 = ns("bot1");
    let ns2 = ns("bot2");

    storage.create(&make_memory_ns("ma06-ns1", &ns1)).unwrap();
    storage.create(&make_memory_ns("ma06-ns2", &ns2)).unwrap();

    let results = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::memory_query::query_by_tags(conn, &["important".into()], Some(&ns1))
    }).unwrap();
    assert_eq!(results.len(), 1, "should only return ns1 memories tagged 'important'");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-07: memory_projections stores config
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_07_memory_projections_config() {
    let conn = raw_conn();
    ensure_agent(&conn, "proj-bot");
    conn.execute(
        "INSERT INTO memory_namespaces (namespace_id, scope, owner_agent, created_at)
         VALUES ('agent://ns-src/', 'agent', 'proj-bot', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [],
    ).unwrap();
    conn.execute(
        "INSERT INTO memory_namespaces (namespace_id, scope, owner_agent, created_at)
         VALUES ('agent://ns-tgt/', 'agent', 'proj-bot', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [],
    ).unwrap();

    conn.execute(
        "INSERT INTO memory_projections (projection_id, source_namespace, target_namespace, filter_json, created_at, created_by)
         VALUES ('proj1', 'agent://ns-src/', 'agent://ns-tgt/', '{\"fields\": [\"summary\", \"tags\"]}', strftime('%Y-%m-%dT%H:%M:%fZ','now'), 'proj-bot')",
        [],
    ).unwrap();

    let filter: String = conn
        .query_row(
            "SELECT filter_json FROM memory_projections WHERE projection_id = 'proj1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&filter).unwrap();
    assert!(parsed["fields"].is_array());
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-08: provenance_log tracks actions
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_08_provenance_log() {
    let conn = raw_conn();
    ensure_agent(&conn, "bot1");
    // provenance_log has FK to memories, so create a memory.
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "test".into(),
        evidence: vec![],
    });
    let mem = BaseMemory {
        id: "m1".into(),
        memory_type: MemoryType::Insight,
        content: tc.clone(),
        summary: "s".into(),
        transaction_time: chrono::Utc::now(),
        valid_time: chrono::Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: chrono::Utc::now(),
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
    let storage = StorageEngine::open_in_memory().unwrap();
    storage.create(&mem).unwrap();
    // Use the writer connection for provenance_log inserts too.
    storage.pool().writer.with_conn_sync(|conn| {
        ensure_agent(conn, "bot1");
        conn.execute(
            "INSERT INTO provenance_log (memory_id, hop_index, agent_id, action, timestamp, confidence_delta)
             VALUES ('m1', 1, 'bot1', 'share', strftime('%Y-%m-%dT%H:%M:%fZ','now'), 0.0)",
            [],
        ).unwrap();

        let (action, delta): (String, f64) = conn
            .query_row(
                "SELECT action, confidence_delta FROM provenance_log WHERE memory_id = 'm1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(action, "share");
        assert!((delta - 0.0).abs() < 1e-10);
        Ok(())
    }).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-09: agent_trust stores bidirectional trust
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_09_agent_trust() {
    let conn = raw_conn();
    ensure_agent(&conn, "agentA");
    ensure_agent(&conn, "agentB");

    conn.execute(
        "INSERT INTO agent_trust (agent_id, target_agent, overall_trust, evidence, last_updated)
         VALUES ('agentA', 'agentB', 0.8, '[]', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [],
    ).unwrap();

    let score: f64 = conn
        .query_row(
            "SELECT overall_trust FROM agent_trust WHERE agent_id = 'agentA' AND target_agent = 'agentB'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!((score - 0.8).abs() < 1e-10);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-10: delta_queue persists CRDT deltas
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_10_delta_queue() {
    let conn = raw_conn();
    ensure_agent(&conn, "src_agent");
    ensure_agent(&conn, "tgt_agent");

    conn.execute(
        "INSERT INTO delta_queue (source_agent, target_agent, memory_id, delta_json, vector_clock, created_at)
         VALUES ('src_agent', 'tgt_agent', 'm1', '{\"id\": \"m1\"}', '{}', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [],
    ).unwrap();

    let (delta_json, applied): (String, i64) = conn
        .query_row(
            "SELECT delta_json, applied FROM delta_queue WHERE source_agent = 'src_agent'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&delta_json).unwrap();
    assert_eq!(parsed["id"], "m1");
    assert_eq!(applied, 0, "new delta should be unapplied");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-11: Agent registry rejects duplicate agent_id
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_11_agent_registry_duplicate_rejected() {
    let conn = raw_conn();
    ensure_agent(&conn, "dup-agent");
    let result = conn.execute(
        "INSERT INTO agent_registry (agent_id, name, namespace_id, registered_at, last_active)
         VALUES ('dup-agent', 'Dup', 'agent://default/', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [],
    );
    assert!(result.is_err(), "duplicate agent_id should fail");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MA-12: Namespace filter works with query_by_importance
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ma_12_namespace_isolates_importance_query() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let ns1 = ns("bot1");
    let ns2 = ns("bot2");

    for i in 0..2 {
        storage.create(&make_memory_ns(&format!("ma12-ns1-{i}"), &ns1)).unwrap();
    }
    storage.create(&make_memory_ns("ma12-ns2-0", &ns2)).unwrap();

    let results = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::memory_query::query_by_importance(conn, Importance::Normal, Some(&ns1))
    }).unwrap();
    assert_eq!(results.len(), 2, "should only return ns1 memories");
}

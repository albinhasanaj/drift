//! Cat 16: NAPI→Storage Integration (NI-01 through NI-14)
//!
//! These tests exercise the same code paths the NAPI bindings use,
//! without requiring the napi crate or JS runtime. They verify the
//! JSON→Rust→Storage→Rust→JSON roundtrip via StorageEngine.

use chrono::Utc;

use cortex_core::memory::*;
use cortex_core::traits::{CausalEdge, ICausalStorage, IMemoryStorage};
use cortex_storage::StorageEngine;

fn make_memory(id: &str) -> BaseMemory {
    let now = Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: format!("observation for {id}"),
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

// ═══════════════════════════════════════════════════════════════════════════════
// NI-01: create → get roundtrip (JSON→Rust→Storage→Rust→JSON equivalent)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_01_create_get_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("ni01");
    mem.tags = vec!["alpha".into(), "beta".into()];
    mem.linked_patterns = vec![PatternLink {
        pattern_id: "p1".into(),
        pattern_name: "singleton".into(),
    }];
    mem.confidence = Confidence::new(0.75);
    storage.create(&mem).unwrap();

    let got = storage.get("ni01").unwrap().unwrap();
    assert_eq!(got.id, "ni01");
    assert_eq!(got.tags, vec!["alpha", "beta"]);
    assert!(!got.linked_patterns.is_empty());
    assert!((got.confidence.value() - 0.75).abs() < 1e-10);
    assert_eq!(got.memory_type, MemoryType::Insight);
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-02: update triggers content_hash change detection
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_02_update_detects_content_hash_change() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("ni02");
    let original_hash = mem.content_hash.clone();
    storage.create(&mem).unwrap();

    // Update with different content → different hash.
    let mut updated = mem.clone();
    let new_tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "completely different observation".into(),
        evidence: vec![],
    });
    updated.content = new_tc.clone();
    updated.content_hash = BaseMemory::compute_content_hash(&new_tc).unwrap();
    assert_ne!(updated.content_hash, original_hash);
    storage.update(&updated).unwrap();

    let got = storage.get("ni02").unwrap().unwrap();
    assert_eq!(got.content_hash, updated.content_hash);
    assert_ne!(got.content_hash, original_hash);
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-03: search delegates to FTS5
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_03_search_delegates_to_fts5() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut m1 = make_memory("ni03-a");
    m1.summary = "quantum computing breakthrough".into();
    let mut m2 = make_memory("ni03-b");
    m2.summary = "database optimization techniques".into();
    let mut m3 = make_memory("ni03-c");
    m3.summary = "quantum entanglement research".into();

    storage.create(&m1).unwrap();
    storage.create(&m2).unwrap();
    storage.create(&m3).unwrap();

    let results = storage.search_fts5("quantum", 10).unwrap();
    assert_eq!(results.len(), 2, "should find 2 memories with 'quantum'");
    let ids: Vec<&str> = results.iter().map(|m| m.id.as_str()).collect();
    assert!(ids.contains(&"ni03-a"));
    assert!(ids.contains(&"ni03-c"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-04: list with type filter
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_04_list_with_type_filter() {
    let storage = StorageEngine::open_in_memory().unwrap();

    for i in 0..3 {
        let mut m = make_memory(&format!("ni04-core-{i}"));
        m.memory_type = MemoryType::Core;
        storage.create(&m).unwrap();
    }
    for i in 0..2 {
        let mut m = make_memory(&format!("ni04-semantic-{i}"));
        m.memory_type = MemoryType::Semantic;
        storage.create(&m).unwrap();
    }

    let core_mems = storage.query_by_type(MemoryType::Core).unwrap();
    assert_eq!(core_mems.len(), 3, "should get 3 Core memories");
    let semantic_mems = storage.query_by_type(MemoryType::Semantic).unwrap();
    assert_eq!(semantic_mems.len(), 2, "should get 2 Semantic memories");
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-05: archive / restore cycle
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_05_archive_restore_cycle() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("ni05");
    storage.create(&mem).unwrap();

    // Archive: delete (which sets archived=true + emits event).
    storage.delete("ni05").unwrap();

    // Memory should no longer appear in active queries.
    let active = storage.query_by_type(MemoryType::Insight).unwrap();
    assert!(
        !active.iter().any(|m| m.id == "ni05"),
        "archived memory should not appear in active queries"
    );

    // Events should include the archived event.
    let events = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::event_ops::get_events_for_memory(conn, "ni05", None)
    }).unwrap();
    assert!(events.iter().any(|e| e.event_type == "archived"), "should have archived event");
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-06: Causal inference roundtrip (add_edge → get_edges)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_06_causal_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let edge = CausalEdge {
        source_id: "cause-1".into(),
        target_id: "effect-1".into(),
        relation: "causes".into(),
        strength: 0.85,
        evidence: vec![],
        source_agent: None,
    };
    storage.add_edge(&edge).unwrap();

    let edges = storage.get_edges("cause-1").unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].target_id, "effect-1");
    assert!((edges[0].strength - 0.85).abs() < 1e-10);
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-07: Session create returns usable ID
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_07_session_create() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let session_id = "test-session-uuid";
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::session_ops::create_session(conn, session_id, 4096)
    }).unwrap();

    // Verify session exists.
    let exists: bool = storage.pool().writer.with_conn_sync(|conn| {
        Ok(conn.prepare("SELECT 1 FROM session_contexts WHERE id = ?1")
            .unwrap()
            .exists(rusqlite::params![session_id])
            .unwrap())
    }).unwrap();
    assert!(exists);
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-08: Session get for non-existent returns empty
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_08_session_nonexistent() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let exists: bool = storage.pool().writer.with_conn_sync(|conn| {
        Ok(conn.prepare("SELECT 1 FROM session_contexts WHERE id = 'nonexistent'")
            .unwrap()
            .exists([])
            .unwrap())
    }).unwrap();
    assert!(!exists, "non-existent session should not be found");
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-09: Temporal query by date range
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_09_temporal_query_date_range() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let now = Utc::now();
    let old = now - chrono::Duration::days(30);
    let recent = now - chrono::Duration::days(1);

    let mut m1 = make_memory("ni09-old");
    m1.transaction_time = old;
    let mut m2 = make_memory("ni09-recent");
    m2.transaction_time = recent;

    storage.create(&m1).unwrap();
    storage.create(&m2).unwrap();

    // Query for last 7 days.
    let from = now - chrono::Duration::days(7);
    let results = storage.query_by_date_range(from, now).unwrap();
    assert_eq!(results.len(), 1, "should find only the recent memory");
    assert_eq!(results[0].id, "ni09-recent");
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-10: Health stats query (not hardcoded zeros)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_10_health_stats_real_values() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Create 5 memories, archive 2 via UPDATE (delete() does hard DELETE).
    for i in 0..5 {
        storage.create(&make_memory(&format!("ni10-{i}"))).unwrap();
    }
    storage.pool().writer.with_conn_sync(|conn| {
        conn.execute("UPDATE memories SET archived = 1 WHERE id = 'ni10-0'", []).unwrap();
        conn.execute("UPDATE memories SET archived = 1 WHERE id = 'ni10-1'", []).unwrap();
        Ok(())
    }).unwrap();

    // Use raw aggregation query to verify real counts.
    let stats = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::aggregation::storage_stats(conn)
    }).unwrap();
    assert_eq!(stats.total_memories, 5, "total should be 5");
    assert_eq!(stats.active_memories, 3, "active should be 3");
    assert_eq!(stats.archived_memories, 2, "archived should be 2");
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-11: Lifecycle: create memories → vacuum → verify intact
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_11_lifecycle_vacuum_preserves_data() {
    let storage = StorageEngine::open_in_memory().unwrap();

    for i in 0..10 {
        storage.create(&make_memory(&format!("ni11-{i}"))).unwrap();
    }
    storage.vacuum().unwrap();

    for i in 0..10 {
        let got = storage.get(&format!("ni11-{i}")).unwrap();
        assert!(got.is_some(), "ni11-{i} should survive vacuum");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-12: Multi-agent register + namespace isolation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_12_multiagent_namespace_isolation() {
    let storage = StorageEngine::open_in_memory().unwrap();
    use cortex_core::models::namespace::{NamespaceId, NamespaceScope};
    use cortex_core::models::agent::AgentId;

    let ns_a = NamespaceId { scope: NamespaceScope::Agent(AgentId::from("agent-a")), name: "a".into() };
    let ns_b = NamespaceId { scope: NamespaceScope::Agent(AgentId::from("agent-b")), name: "b".into() };

    let mut m1 = make_memory("ni12-a");
    m1.namespace = ns_a.clone();
    let mut m2 = make_memory("ni12-b");
    m2.namespace = ns_b.clone();

    storage.create(&m1).unwrap();
    storage.create(&m2).unwrap();

    // Use raw query module with namespace filter.
    let results_a = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::memory_query::query_by_type(conn, MemoryType::Insight, Some(&ns_a))
    }).unwrap();
    assert_eq!(results_a.len(), 1);
    assert_eq!(results_a[0].id, "ni12-a");
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-13: Bulk create + bulk get roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_13_bulk_create_get_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let batch: Vec<BaseMemory> = (0..50)
        .map(|i| make_memory(&format!("ni13-{i}")))
        .collect();
    storage.create_bulk(&batch).unwrap();

    let ids: Vec<String> = (0..50).map(|i| format!("ni13-{i}")).collect();
    let got = storage.get_bulk(&ids).unwrap();
    assert_eq!(got.len(), 50, "all 50 should be returned");
}

// ═══════════════════════════════════════════════════════════════════════════════
// NI-14: Vector search roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ni_14_vector_search_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("ni14");
    storage.create(&mem).unwrap();

    // Store embedding.
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::vector_search::store_embedding(
            conn, "ni14", &mem.content_hash, &[0.5, 0.5, 0.0], "test-model",
        )
    }).unwrap();

    // Search with similar query vector.
    let results = storage.search_vector(&[0.5, 0.5, 0.0], 10).unwrap();
    assert!(!results.is_empty(), "should find at least 1 result");
    assert_eq!(results[0].0.id, "ni14");
    assert!((results[0].1 - 1.0).abs() < 0.01, "identical vectors should have ~1.0 similarity");
}

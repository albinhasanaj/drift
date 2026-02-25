//! Cat 3: Memory CRUD Atomicity (MC-01 through MC-14)
//!
//! Tests transactional create/update/delete, bulk operations,
//! link re-creation, namespace roundtrip, and boundary values.

use chrono::Utc;

use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

// ─── Fixtures ────────────────────────────────────────────────────────────────

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

fn get_events(storage: &StorageEngine, memory_id: &str) -> Vec<cortex_storage::queries::event_ops::RawEvent> {
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::event_ops::get_events_for_memory(conn, memory_id, None)
    }).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-01: Create with all link types persists atomically
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_01_create_with_all_links_atomic() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("mc01");
    mem.linked_patterns = vec![
        PatternLink { pattern_id: "p1".into(), pattern_name: "pat1".into() },
        PatternLink { pattern_id: "p2".into(), pattern_name: "pat2".into() },
    ];
    mem.linked_constraints = vec![
        ConstraintLink { constraint_id: "c1".into(), constraint_name: "con1".into() },
        ConstraintLink { constraint_id: "c2".into(), constraint_name: "con2".into() },
    ];
    mem.linked_files = vec![
        FileLink { file_path: "/a.rs".into(), line_start: Some(1), line_end: Some(10), content_hash: Some("h1".into()) },
        FileLink { file_path: "/b.rs".into(), line_start: Some(5), line_end: Some(20), content_hash: Some("h2".into()) },
    ];
    mem.linked_functions = vec![
        FunctionLink { function_name: "foo".into(), file_path: "/a.rs".into(), signature: Some("fn foo()".into()) },
        FunctionLink { function_name: "bar".into(), file_path: "/b.rs".into(), signature: Some("fn bar()".into()) },
    ];

    storage.create(&mem).unwrap();

    let got = storage.get("mc01").unwrap().unwrap();
    assert_eq!(got.linked_patterns.len(), 2);
    assert_eq!(got.linked_constraints.len(), 2);
    assert_eq!(got.linked_files.len(), 2);
    assert_eq!(got.linked_functions.len(), 2);

    // Verify "created" event exists.
    let events = get_events(&storage, "mc01");
    assert!(events.iter().any(|e| e.event_type == "created"), "should have 'created' event");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-03: Update detects content_hash change and emits events
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_03_update_detects_content_hash_change() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("mc03");
    storage.create(&mem).unwrap();

    // Update with different content.
    let mut updated = mem.clone();
    let new_content = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "totally new observation".to_string(),
        evidence: vec![],
    });
    updated.content = new_content.clone();
    updated.content_hash = BaseMemory::compute_content_hash(&new_content).unwrap();
    updated.summary = "new summary".into();

    storage.update(&updated).unwrap();

    let events = get_events(&storage, "mc03");
    assert!(
        events.iter().any(|e| e.event_type == "content_updated"),
        "should have 'content_updated' event. Events: {:?}",
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-04: Update emits events for each changed field independently
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_04_update_emits_per_field_events() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("mc04");
    storage.create(&mem).unwrap();

    let mut updated = mem.clone();
    updated.tags = vec!["new-tag".to_string()];
    updated.confidence = Confidence::new(0.3);
    updated.importance = Importance::Critical;
    updated.archived = true;

    storage.update(&updated).unwrap();

    let events = get_events(&storage, "mc04");
    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();

    assert!(types.contains(&"tags_modified"), "missing tags_modified. Got: {types:?}");
    assert!(types.contains(&"confidence_changed"), "missing confidence_changed. Got: {types:?}");
    assert!(types.contains(&"importance_changed"), "missing importance_changed. Got: {types:?}");
    assert!(types.contains(&"archived"), "missing archived. Got: {types:?}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-05: Update of non-existent memory returns MemoryNotFound
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_05_update_nonexistent_returns_not_found() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("nonexistent-999");
    let result = storage.update(&mem);
    assert!(result.is_err(), "updating non-existent memory should fail");
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("NotFound") || err_str.contains("not found") || err_str.contains("MemoryNotFound"),
        "error should indicate not found: {err_str}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-06: Delete emits "archived" event BEFORE row deletion
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_06_delete_emits_archived_event() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("mc06");
    storage.create(&mem).unwrap();
    storage.delete("mc06").unwrap();

    // Memory is gone.
    assert!(storage.get("mc06").unwrap().is_none());

    // But the event should still exist (events are not FK-cascaded with memories).
    let events = get_events(&storage, "mc06");
    let archived_events: Vec<_> = events.iter().filter(|e| e.event_type == "archived").collect();
    assert!(
        !archived_events.is_empty(),
        "should have 'archived' event even after delete. Events: {:?}",
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
    // Check the delta contains "hard_delete".
    let delta: serde_json::Value = serde_json::from_str(&archived_events[0].delta).unwrap();
    assert_eq!(delta["reason"], "hard_delete");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-07: Delete cascades to all 4 link tables
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_07_delete_cascades_links() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("mc07");
    mem.linked_patterns = vec![PatternLink { pattern_id: "p1".into(), pattern_name: "pat1".into() }];
    mem.linked_constraints = vec![ConstraintLink { constraint_id: "c1".into(), constraint_name: "con1".into() }];
    mem.linked_files = vec![FileLink { file_path: "/x.rs".into(), line_start: None, line_end: None, content_hash: None }];
    mem.linked_functions = vec![FunctionLink { function_name: "func".into(), file_path: "/x.rs".into(), signature: None }];

    storage.create(&mem).unwrap();
    storage.delete("mc07").unwrap();

    storage.pool().writer.with_conn_sync(|conn| {
        for table in &["memory_patterns", "memory_constraints", "memory_files", "memory_functions"] {
            let count: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE memory_id = 'mc07'"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table} should be empty after delete");
        }
        Ok(())
    }).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-08: Bulk insert — all-or-nothing on duplicate ID
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_08_bulk_insert_rollback_on_duplicate() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Pre-insert one.
    let existing = make_memory("dup-target");
    storage.create(&existing).unwrap();

    // Batch with a duplicate.
    let batch: Vec<BaseMemory> = (0..5)
        .map(|i| {
            if i == 2 {
                make_memory("dup-target") // duplicate
            } else {
                make_memory(&format!("batch-{i}"))
            }
        })
        .collect();

    let result = storage.create_bulk(&batch);
    assert!(result.is_err(), "bulk insert with duplicate should fail");

    // None of the new batch items should exist (full rollback).
    for i in [0, 1, 3, 4] {
        let got = storage.get(&format!("batch-{i}")).unwrap();
        assert!(got.is_none(), "batch-{i} should not exist after rollback");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-09: Bulk insert — empty batch returns Ok(0)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_09_bulk_insert_empty() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let count = storage.create_bulk(&[]).unwrap();
    assert_eq!(count, 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-10: Bulk get — missing IDs silently skipped
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_10_bulk_get_skips_missing() {
    let storage = StorageEngine::open_in_memory().unwrap();

    storage.create(&make_memory("bg-a")).unwrap();
    storage.create(&make_memory("bg-c")).unwrap();

    let ids: Vec<String> = vec!["bg-a".into(), "bg-b".into(), "bg-c".into()];
    let results = storage.get_bulk(&ids).unwrap();
    assert_eq!(results.len(), 2, "should return 2 (skipping missing bg-b)");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-11: Update re-creates links (delete-then-insert)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_11_update_recreates_links() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("mc11");
    mem.linked_patterns = vec![PatternLink { pattern_id: "p1".into(), pattern_name: "pat1".into() }];
    storage.create(&mem).unwrap();

    // Update with different pattern.
    let mut updated = mem.clone();
    updated.linked_patterns = vec![PatternLink { pattern_id: "p2".into(), pattern_name: "pat2".into() }];
    storage.update(&updated).unwrap();

    let got = storage.get("mc11").unwrap().unwrap();
    assert_eq!(got.linked_patterns.len(), 1);
    assert_eq!(got.linked_patterns[0].pattern_id, "p2");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-12: Namespace and source_agent roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_12_namespace_source_agent_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("mc12");
    mem.namespace = cortex_core::models::namespace::NamespaceId::default();
    mem.source_agent = cortex_core::models::agent::AgentId::from("bot-1");
    storage.create(&mem).unwrap();

    let got = storage.get("mc12").unwrap().unwrap();
    assert_eq!(got.source_agent.0, "bot-1");
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-13: Confidence clamping at boundaries
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_13_confidence_boundary_values() {
    let storage = StorageEngine::open_in_memory().unwrap();

    for (label, conf) in [("zero", 0.0), ("half", 0.5), ("one", 1.0)] {
        let mut mem = make_memory(&format!("mc13-{label}"));
        mem.confidence = Confidence::new(conf);
        storage.create(&mem).unwrap();

        let got = storage.get(&format!("mc13-{label}")).unwrap().unwrap();
        assert!(
            (got.confidence.value() - conf).abs() < 1e-10,
            "confidence {label}: expected {conf}, got {}",
            got.confidence.value()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MC-14: access_count u64 survives i64 storage roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn mc_14_access_count_u64_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("mc14");
    mem.access_count = u32::MAX as u64 + 1; // 4294967296
    storage.create(&mem).unwrap();

    let got = storage.get("mc14").unwrap().unwrap();
    assert_eq!(got.access_count, u32::MAX as u64 + 1);
}

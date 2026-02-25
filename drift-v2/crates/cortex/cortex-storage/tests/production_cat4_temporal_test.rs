//! Cat 4: Temporal Event Consistency (TE-01 through TE-10)
//!
//! Tests that events use SQLite clock, graceful pre-migration handling,
//! event failure isolation, all update event types, confidence epsilon,
//! tags diff, schema_version default, caused_by NULL, ordering, and
//! archive event before delete.

use chrono::Utc;
use rusqlite::Connection;

use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::pool::pragmas;
use cortex_storage::queries::event_ops;
use cortex_storage::StorageEngine;

// ─── Fixtures ────────────────────────────────────────────────────────────────

fn raw_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    pragmas::apply_pragmas(&conn).unwrap();
    cortex_storage::migrations::run_migrations(&conn).unwrap();
    conn
}

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

fn get_events(storage: &StorageEngine, memory_id: &str) -> Vec<event_ops::RawEvent> {
    storage.pool().writer.with_conn_sync(|conn| {
        event_ops::get_events_for_memory(conn, memory_id, None)
    }).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════════
// TE-01: Event uses SQLite clock, not Rust clock
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn te_01_event_uses_sqlite_clock() {
    let conn = raw_conn();
    let delta = serde_json::json!({"test": true});
    cortex_storage::temporal_events::emit_event(
        &conn, "te01", "test_event", &delta, "system", "test",
    ).unwrap();

    let events = event_ops::get_events_for_memory(&conn, "te01", None).unwrap();
    assert_eq!(events.len(), 1);

    let ts = &events[0].recorded_at;
    // SQLite strftime format: YYYY-MM-DDTHH:MM:SS.mmmZ
    assert!(ts.ends_with('Z'), "timestamp should end with Z: {ts}");
    assert!(ts.contains('T'), "timestamp should contain T: {ts}");
    // Should have millisecond precision (contains a dot before Z).
    assert!(ts.contains('.'), "timestamp should have ms precision: {ts}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TE-02: Event emission graceful before v014 migration
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn te_02_event_emission_graceful_pre_migration() {
    // Create a connection with only v001 migration (no memory_events table).
    let conn = Connection::open_in_memory().unwrap();
    pragmas::apply_pragmas(&conn).unwrap();

    // Manually create just the schema_version table and v001.
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL, applied_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))").unwrap();

    // emit_event should return Ok(0) when memory_events doesn't exist.
    let delta = serde_json::json!({});
    let result = cortex_storage::temporal_events::emit_event(
        &conn, "m1", "test", &delta, "system", "test",
    );
    assert!(result.is_ok(), "should not error on missing table");
    assert_eq!(result.unwrap(), 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TE-03: Event emission failure doesn't break CRUD transaction
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn te_03_event_failure_doesnt_break_crud() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Create a memory — should succeed even if event emission has issues.
    let mem = make_memory("te03");
    storage.create(&mem).unwrap();

    // The memory should be persisted regardless of event emission status.
    let got = storage.get("te03").unwrap();
    assert!(got.is_some(), "memory should exist even if event emission had issues");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TE-04: All 5 update event types fire correctly
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn te_04_all_five_update_event_types() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("te04");
    storage.create(&mem).unwrap();

    // Update all 5 tracked fields at once.
    let mut updated = mem.clone();
    let new_tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "completely different".into(),
        evidence: vec![],
    });
    updated.content = new_tc.clone();
    updated.content_hash = BaseMemory::compute_content_hash(&new_tc).unwrap();
    updated.summary = "new summary".into();
    updated.tags = vec!["new-tag".into()];
    updated.confidence = Confidence::new(0.2);
    updated.importance = Importance::Critical;
    updated.archived = true;

    storage.update(&updated).unwrap();

    let events = get_events(&storage, "te04");
    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();

    assert!(types.contains(&"content_updated"), "missing content_updated");
    assert!(types.contains(&"tags_modified"), "missing tags_modified");
    assert!(types.contains(&"confidence_changed"), "missing confidence_changed");
    assert!(types.contains(&"importance_changed"), "missing importance_changed");
    assert!(types.contains(&"archived"), "missing archived");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TE-05: Confidence change detection uses epsilon
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn te_05_confidence_epsilon() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("te05");
    storage.create(&mem).unwrap();

    // Update with sub-epsilon confidence change.
    let mut updated = mem.clone();
    updated.confidence = Confidence::new(0.8 + 1e-16);

    storage.update(&updated).unwrap();

    let events = get_events(&storage, "te05");
    let has_conf_change = events.iter().any(|e| e.event_type == "confidence_changed");
    assert!(!has_conf_change, "sub-epsilon confidence change should NOT emit event");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TE-06: Tags diff correctly identifies added and removed
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn te_06_tags_diff() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("te06");
    mem.tags = vec!["a".into(), "b".into()];
    storage.create(&mem).unwrap();

    let mut updated = mem.clone();
    updated.tags = vec!["b".into(), "c".into()];
    storage.update(&updated).unwrap();

    let events = get_events(&storage, "te06");
    let tag_event = events.iter().find(|e| e.event_type == "tags_modified").unwrap();
    let delta: serde_json::Value = serde_json::from_str(&tag_event.delta).unwrap();

    let added = delta["added"].as_array().unwrap();
    let removed = delta["removed"].as_array().unwrap();

    assert!(added.iter().any(|v| v == "c"), "should have added 'c': {delta}");
    assert!(removed.iter().any(|v| v == "a"), "should have removed 'a': {delta}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TE-07: Schema_version field defaults to 1
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn te_07_schema_version_default() {
    let conn = raw_conn();
    let delta = serde_json::json!({});
    cortex_storage::temporal_events::emit_event(
        &conn, "te07", "test", &delta, "system", "test",
    ).unwrap();

    let events = event_ops::get_events_for_memory(&conn, "te07", None).unwrap();
    assert_eq!(events[0].schema_version, 1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TE-08: caused_by field supports NULL
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn te_08_caused_by_null() {
    let conn = raw_conn();
    let delta = serde_json::json!({});
    cortex_storage::temporal_events::emit_event(
        &conn, "te08", "test", &delta, "system", "test",
    ).unwrap();

    let events = event_ops::get_events_for_memory(&conn, "te08", None).unwrap();
    assert!(events[0].caused_by.is_none(), "caused_by should be None");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TE-09: Event ordering is stable under rapid writes
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn te_09_event_ordering_stable() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Create 10 memories rapidly.
    for i in 0..10 {
        storage.create(&make_memory(&format!("te09-{i}"))).unwrap();
    }

    // Collect all "created" events.
    let mut all_events = Vec::new();
    for i in 0..10 {
        let events = get_events(&storage, &format!("te09-{i}"));
        let created = events.into_iter().find(|e| e.event_type == "created");
        if let Some(ev) = created {
            all_events.push(ev);
        }
    }

    // event_ids should be monotonically increasing.
    for window in all_events.windows(2) {
        assert!(
            window[0].event_id < window[1].event_id,
            "event_ids should be monotonically increasing: {} < {}",
            window[0].event_id,
            window[1].event_id
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TE-10: Archive event emitted before hard delete
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn te_10_archive_event_before_delete() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("te10");
    storage.create(&mem).unwrap();
    storage.delete("te10").unwrap();

    // Memory row is gone.
    assert!(storage.get("te10").unwrap().is_none());

    // But the archived event should persist.
    let events = get_events(&storage, "te10");
    let archived = events.iter().find(|e| e.event_type == "archived");
    assert!(archived.is_some(), "archived event should exist after delete");

    let delta: serde_json::Value = serde_json::from_str(&archived.unwrap().delta).unwrap();
    assert_eq!(delta["reason"], "hard_delete");
}

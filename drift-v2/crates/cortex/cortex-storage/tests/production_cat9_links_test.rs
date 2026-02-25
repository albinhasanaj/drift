//! Cat 9: Link Operations & Cascade (LK-01 through LK-10)
//!
//! Tests INSERT OR IGNORE on duplicate, event emission, atomic remove,
//! field storage, concurrent access, and idempotent remove.

use std::sync::Arc;

use chrono::Utc;

use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::queries::event_ops;
use cortex_storage::StorageEngine;

// ─── Fixtures ────────────────────────────────────────────────────────────────

fn make_memory(id: &str) -> BaseMemory {
    let now = Utc::now();
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

fn get_events(storage: &StorageEngine, memory_id: &str) -> Vec<event_ops::RawEvent> {
    storage.pool().writer.with_conn_sync(|conn| {
        event_ops::get_events_for_memory(conn, memory_id, None)
    }).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════════
// LK-01: add_pattern_link INSERT OR IGNORE on duplicate
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn lk_01_pattern_link_ignore_duplicate() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("lk01");
    storage.create(&mem).unwrap();

    let link = PatternLink { pattern_id: "p1".into(), pattern_name: "pat1".into() };
    storage.add_pattern_link("lk01", &link).unwrap();
    storage.add_pattern_link("lk01", &link).unwrap(); // duplicate

    let got = storage.get("lk01").unwrap().unwrap();
    assert_eq!(got.linked_patterns.len(), 1, "duplicate should be ignored");
}

// ═══════════════════════════════════════════════════════════════════════════════
// LK-02: add_pattern_link emits link_added event
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn lk_02_pattern_link_emits_event() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("lk02");
    storage.create(&mem).unwrap();

    let link = PatternLink { pattern_id: "p1".into(), pattern_name: "pat1".into() };
    storage.add_pattern_link("lk02", &link).unwrap();

    let events = get_events(&storage, "lk02");
    let link_events: Vec<_> = events.iter().filter(|e| e.event_type == "link_added").collect();
    assert!(!link_events.is_empty(), "should emit link_added event");

    let delta: serde_json::Value = serde_json::from_str(&link_events[0].delta).unwrap();
    assert_eq!(delta["link_type"], "pattern");
    assert_eq!(delta["target"], "p1");
}

// ═══════════════════════════════════════════════════════════════════════════════
// LK-03: remove_pattern_link is atomic SQL DELETE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn lk_03_remove_pattern_link_atomic() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("lk03");
    storage.create(&mem).unwrap();

    let link1 = PatternLink { pattern_id: "p1".into(), pattern_name: "pat1".into() };
    let link2 = PatternLink { pattern_id: "p2".into(), pattern_name: "pat2".into() };
    storage.add_pattern_link("lk03", &link1).unwrap();
    storage.add_pattern_link("lk03", &link2).unwrap();

    // Remove p1, p2 should remain.
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_pattern_link(conn, "lk03", "p1")
    }).unwrap();

    let got = storage.get("lk03").unwrap().unwrap();
    assert_eq!(got.linked_patterns.len(), 1);
    assert_eq!(got.linked_patterns[0].pattern_id, "p2");
}

// ═══════════════════════════════════════════════════════════════════════════════
// LK-04: add_file_link stores all fields
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn lk_04_file_link_stores_all_fields() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("lk04");
    storage.create(&mem).unwrap();

    let link = FileLink {
        file_path: "/src/main.rs".into(),
        line_start: Some(10),
        line_end: Some(50),
        content_hash: Some("abc123".into()),
    };
    storage.add_file_link("lk04", &link).unwrap();

    let got = storage.get("lk04").unwrap().unwrap();
    assert_eq!(got.linked_files.len(), 1);
    let f = &got.linked_files[0];
    assert_eq!(f.file_path, "/src/main.rs");
    assert_eq!(f.line_start, Some(10));
    assert_eq!(f.line_end, Some(50));
    assert_eq!(f.content_hash, Some("abc123".into()));
}

// ═══════════════════════════════════════════════════════════════════════════════
// LK-05: add_function_link stores signature
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn lk_05_function_link_stores_signature() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("lk05");
    storage.create(&mem).unwrap();

    let link = FunctionLink {
        function_name: "process_data".into(),
        file_path: "/src/lib.rs".into(),
        signature: Some("fn process_data(input: &[u8]) -> Result<Vec<u8>>".into()),
    };
    storage.add_function_link("lk05", &link).unwrap();

    let got = storage.get("lk05").unwrap().unwrap();
    assert_eq!(got.linked_functions.len(), 1);
    assert_eq!(got.linked_functions[0].signature, Some("fn process_data(input: &[u8]) -> Result<Vec<u8>>".into()));
}

// ═══════════════════════════════════════════════════════════════════════════════
// LK-06: remove_file_link by file_path
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn lk_06_remove_file_link_by_path() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("lk06");
    storage.create(&mem).unwrap();

    let link_a = FileLink { file_path: "/a.rs".into(), line_start: None, line_end: None, content_hash: None };
    let link_b = FileLink { file_path: "/b.rs".into(), line_start: None, line_end: None, content_hash: None };
    storage.add_file_link("lk06", &link_a).unwrap();
    storage.add_file_link("lk06", &link_b).unwrap();

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_file_link(conn, "lk06", "/a.rs")
    }).unwrap();

    let got = storage.get("lk06").unwrap().unwrap();
    assert_eq!(got.linked_files.len(), 1);
    assert_eq!(got.linked_files[0].file_path, "/b.rs");
}

// ═══════════════════════════════════════════════════════════════════════════════
// LK-07: remove_function_link by function_name
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn lk_07_remove_function_link_by_name() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("lk07");
    storage.create(&mem).unwrap();

    let link_foo = FunctionLink { function_name: "foo".into(), file_path: "/a.rs".into(), signature: None };
    let link_bar = FunctionLink { function_name: "bar".into(), file_path: "/a.rs".into(), signature: None };
    storage.add_function_link("lk07", &link_foo).unwrap();
    storage.add_function_link("lk07", &link_bar).unwrap();

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_function_link(conn, "lk07", "foo")
    }).unwrap();

    let got = storage.get("lk07").unwrap().unwrap();
    assert_eq!(got.linked_functions.len(), 1);
    assert_eq!(got.linked_functions[0].function_name, "bar");
}

// ═══════════════════════════════════════════════════════════════════════════════
// LK-08: All 4 remove ops emit link_removed event
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn lk_08_all_remove_ops_emit_event() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("lk08");
    storage.create(&mem).unwrap();

    storage.add_pattern_link("lk08", &PatternLink { pattern_id: "p1".into(), pattern_name: "p".into() }).unwrap();
    storage.add_constraint_link("lk08", &ConstraintLink { constraint_id: "c1".into(), constraint_name: "c".into() }).unwrap();
    storage.add_file_link("lk08", &FileLink { file_path: "/a.rs".into(), line_start: None, line_end: None, content_hash: None }).unwrap();
    storage.add_function_link("lk08", &FunctionLink { function_name: "f".into(), file_path: "/a.rs".into(), signature: None }).unwrap();

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_pattern_link(conn, "lk08", "p1")?;
        cortex_storage::queries::link_ops::remove_constraint_link(conn, "lk08", "c1")?;
        cortex_storage::queries::link_ops::remove_file_link(conn, "lk08", "/a.rs")?;
        cortex_storage::queries::link_ops::remove_function_link(conn, "lk08", "f")?;
        Ok(())
    }).unwrap();

    let events = get_events(&storage, "lk08");
    let removed_events: Vec<_> = events.iter().filter(|e| e.event_type == "link_removed").collect();
    assert_eq!(removed_events.len(), 4, "should have 4 link_removed events");

    let link_types: Vec<String> = removed_events.iter().map(|e| {
        let d: serde_json::Value = serde_json::from_str(&e.delta).unwrap();
        d["link_type"].as_str().unwrap().to_string()
    }).collect();
    assert!(link_types.contains(&"pattern".to_string()));
    assert!(link_types.contains(&"constraint".to_string()));
    assert!(link_types.contains(&"file".to_string()));
    assert!(link_types.contains(&"function".to_string()));
}

// ═══════════════════════════════════════════════════════════════════════════════
// LK-09: Link operations survive concurrent access
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn lk_09_links_concurrent_access() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lk09.db");
    let storage = Arc::new(StorageEngine::open(&path).unwrap());

    let mem = make_memory("lk09");
    storage.create(&mem).unwrap();

    let s1 = Arc::clone(&storage);
    let s2 = Arc::clone(&storage);

    let h1 = std::thread::spawn(move || {
        s1.add_pattern_link("lk09", &PatternLink { pattern_id: "p1".into(), pattern_name: "pat1".into() })
    });
    let h2 = std::thread::spawn(move || {
        s2.add_pattern_link("lk09", &PatternLink { pattern_id: "p2".into(), pattern_name: "pat2".into() })
    });

    h1.join().unwrap().unwrap();
    h2.join().unwrap().unwrap();

    let got = storage.get("lk09").unwrap().unwrap();
    assert_eq!(got.linked_patterns.len(), 2, "both concurrent link adds should succeed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// LK-10: Removing non-existent link is idempotent
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn lk_10_remove_nonexistent_link_idempotent() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("lk10");
    storage.create(&mem).unwrap();

    // Remove a pattern that was never added.
    let result = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_pattern_link(conn, "lk10", "nonexistent")
    });
    assert!(result.is_ok(), "removing non-existent link should not error");
}

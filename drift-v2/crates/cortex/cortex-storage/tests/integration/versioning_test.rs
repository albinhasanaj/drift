//! Integration test: version tracking, rollback, retention.

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
            project_name: "original".to_string(),
            description: "test".to_string(),
            metadata: serde_json::json!({}),
        }),
        summary: "original summary".to_string(),
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
        content_hash: "ver_hash".to_string(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

#[test]
fn test_version_tracking_on_update() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut memory = make_memory("ver-1");
    engine.create(&memory).unwrap();

    // Update the memory.
    memory.summary = "updated summary".to_string();
    engine.update(&memory).unwrap();

    // Check version history.
    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let history = cortex_storage::versioning::query::get_history(conn, "ver-1")?;
            assert!(!history.is_empty(), "should have at least 1 version");
            assert_eq!(history[0].summary, "original summary");
            Ok(())
        })
        .unwrap();
}

#[test]
fn test_version_rollback() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut memory = make_memory("ver-rollback");
    engine.create(&memory).unwrap();

    // Update twice.
    memory.summary = "v2 summary".to_string();
    engine.update(&memory).unwrap();

    memory.summary = "v3 summary".to_string();
    engine.update(&memory).unwrap();

    // Rollback to version 1 (the original snapshot).
    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            cortex_storage::versioning::rollback::rollback_to_version(conn, "ver-rollback", 1)
        })
        .unwrap();

    // Verify content was rolled back.
    let retrieved = engine.get("ver-rollback").unwrap().unwrap();
    assert_eq!(retrieved.summary, "original summary");
}

#[test]
fn test_version_retention() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut memory = make_memory("ver-retention");
    engine.create(&memory).unwrap();

    // Update 11 times (should create 11 versions, but retention keeps only 10).
    for i in 0..11 {
        memory.summary = format!("update {i}");
        engine.update(&memory).unwrap();
    }

    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let count = cortex_storage::queries::version_ops::version_count(conn, "ver-retention")?;
            assert!(
                count <= 10,
                "should retain at most 10 versions, got {count}"
            );
            Ok(())
        })
        .unwrap();
}

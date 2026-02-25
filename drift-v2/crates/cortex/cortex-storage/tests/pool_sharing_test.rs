//! Phase B tests B-10, B-11: Connection pool sharing verification.
//!
//! Verifies that Arc-wrapped writer/readers in ConnectionPool support
//! sharing without creating duplicate connections.

use std::sync::Arc;

use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

/// B-11: File-backed mode — verify writer is shared (Arc strong count).
/// After cloning writer for temporal + multiagent, there should be exactly
/// 1 writer instance with strong_count = 3 (pool + temporal + multiagent).
#[test]
fn b11_writer_is_shared_not_duplicated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("test.db");
    let storage = Arc::new(StorageEngine::open(&db_path).expect("open file-backed storage"));

    // Simulate what the runtime does: clone writer and readers for sharing.
    let writer_clone1 = storage.pool().writer.clone(); // for temporal
    let writer_clone2 = storage.pool().writer.clone(); // for multiagent

    // The original pool writer + 2 clones = 3 strong references.
    assert_eq!(
        Arc::strong_count(&storage.pool().writer),
        3,
        "writer should be shared via Arc, not duplicated"
    );

    // Readers too.
    let _readers_clone1 = storage.pool().readers.clone();
    let _readers_clone2 = storage.pool().readers.clone();
    assert_eq!(
        Arc::strong_count(&storage.pool().readers),
        3,
        "readers should be shared via Arc, not duplicated"
    );

    // Write through one reference, read through another — all see the same data.
    use cortex_core::memory::*;
    let now = chrono::Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "shared test".to_string(),
        evidence: vec![],
    });
    let memory = BaseMemory {
        id: "shared-writer-test".to_string(),
        memory_type: MemoryType::Insight,
        content: tc.clone(),
        summary: "shared test".to_string(),
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

    // Write through clone1 (simulating temporal engine's writer).
    writer_clone1
        .with_conn_sync(|conn| {
            cortex_storage::queries::memory_crud::insert_memory(conn, &memory)
        })
        .expect("insert via clone1");

    // Read through clone2 (simulating multiagent engine's writer).
    let found = writer_clone2
        .with_conn_sync(|conn| {
            cortex_storage::queries::memory_crud::get_memory(conn, "shared-writer-test")
        })
        .expect("get via clone2");
    assert!(found.is_some(), "memory written by clone1 should be visible to clone2");

    // Also readable through the original storage engine.
    let found2 = storage.get("shared-writer-test").expect("get via storage");
    assert!(found2.is_some(), "memory should be visible through storage engine too");
}

/// B-10: In-memory mode — data written through writer is visible to pool readers.
/// This verifies that the Arc-wrapped connections share the same underlying DB.
#[test]
fn b10_in_memory_writer_visible_to_storage() {
    let storage = Arc::new(StorageEngine::open_in_memory().expect("in-memory storage"));

    // Clone writer+readers like the runtime does.
    let writer = storage.pool().writer.clone();

    // Write through the cloned writer.
    use cortex_core::memory::*;
    let now = chrono::Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "in-memory shared test".to_string(),
        evidence: vec![],
    });
    let memory = BaseMemory {
        id: "inmem-shared-test".to_string(),
        memory_type: MemoryType::Insight,
        content: tc.clone(),
        summary: "in-memory shared test".to_string(),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(0.7),
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

    writer
        .with_conn_sync(|conn| {
            cortex_storage::queries::memory_crud::insert_memory(conn, &memory)
        })
        .expect("insert via cloned writer");

    // Read through the storage engine's IMemoryStorage impl.
    let found = storage.get("inmem-shared-test").expect("get via storage");
    assert!(
        found.is_some(),
        "memory written via cloned writer should be visible through StorageEngine"
    );
}

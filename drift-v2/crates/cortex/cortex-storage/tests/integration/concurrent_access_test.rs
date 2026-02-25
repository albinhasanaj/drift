//! Integration test: read pool + write connection under load.

use std::sync::Arc;

use chrono::Utc;
use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

fn make_memory(id: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Episodic,
        content: TypedContent::Episodic(EpisodicContent {
            interaction: "test event".to_string(),
            context: "test context".to_string(),
            outcome: Some("test outcome".to_string()),
        }),
        summary: "concurrent test".to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
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
        content_hash: "concurrent_hash".to_string(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

#[test]
fn test_concurrent_reads_during_write() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("concurrent.db");
    let engine = Arc::new(StorageEngine::open(&db_path).unwrap());

    // Insert some initial data.
    for i in 0..10 {
        engine.create(&make_memory(&format!("init-{i}"))).unwrap();
    }

    // Spawn reader threads.
    let mut handles = vec![];
    for t in 0..4 {
        let engine = Arc::clone(&engine);
        handles.push(std::thread::spawn(move || {
            for i in 0..10 {
                let _ = engine.get(&format!("init-{i}"));
                let _ = engine.query_by_type(MemoryType::Episodic);
            }
            t // return thread id for verification
        }));
    }

    // Writer thread.
    let writer_engine = Arc::clone(&engine);
    let writer = std::thread::spawn(move || {
        for i in 10..20 {
            writer_engine
                .create(&make_memory(&format!("write-{i}")))
                .unwrap();
        }
    });

    // Wait for all threads.
    writer.join().expect("writer should not panic");
    for handle in handles {
        handle.join().expect("reader should not panic");
    }

    // Verify all writes succeeded.
    for i in 10..20 {
        assert!(
            engine.get(&format!("write-{i}")).unwrap().is_some(),
            "write-{i} should exist"
        );
    }
}

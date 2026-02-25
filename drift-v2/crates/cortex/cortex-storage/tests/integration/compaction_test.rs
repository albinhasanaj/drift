//! Integration test: archived cleanup + vacuum + dedup.

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
            interaction: "compaction test".to_string(),
            context: "testing".to_string(),
            outcome: Some("pass".to_string()),
        }),
        summary: "compaction".to_string(),
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
        content_hash: "compact_hash".to_string(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

#[test]
fn test_vacuum() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("vac-1")).unwrap();

    // Vacuum should not error.
    engine.vacuum().unwrap();
}

#[test]
fn test_storage_health() {
    let engine = StorageEngine::open_in_memory().unwrap();
    for i in 0..5 {
        engine.create(&make_memory(&format!("health-{i}"))).unwrap();
    }

    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let report = cortex_storage::compaction::storage_health::report(conn)?;
            assert_eq!(report.active_memories, 5);
            assert_eq!(report.archived_memories, 0);
            Ok(())
        })
        .unwrap();
}

#[test]
fn test_embedding_dedup() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("dedup-1")).unwrap();
    engine.create(&make_memory("dedup-2")).unwrap();

    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            // Store embeddings with the same content hash.
            let embedding = vec![0.1f32, 0.2, 0.3];
            cortex_storage::queries::vector_search::store_embedding(
                conn,
                "dedup-1",
                "same_hash",
                &embedding,
                "test-model",
            )?;
            cortex_storage::queries::vector_search::store_embedding(
                conn,
                "dedup-2",
                "same_hash",
                &embedding,
                "test-model",
            )?;

            // Should only have 1 embedding row (deduped by content_hash).
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM memory_embeddings", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 1, "should share embedding row");

            // But 2 links.
            let link_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM memory_embedding_link", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(link_count, 2, "should have 2 links");

            Ok(())
        })
        .unwrap();
}

#[test]
fn test_orphaned_embedding_cleanup() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("orphan-1")).unwrap();

    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let embedding = vec![0.1f32, 0.2, 0.3];
            cortex_storage::queries::vector_search::store_embedding(
                conn,
                "orphan-1",
                "orphan_hash",
                &embedding,
                "test-model",
            )?;

            // Delete the memory (link will be cascade-deleted).
            cortex_storage::queries::memory_crud::delete_memory(conn, "orphan-1")?;

            // Cleanup orphaned embeddings.
            let cleaned =
                cortex_storage::compaction::embedding_dedup::cleanup_orphaned_embeddings(conn)?;
            assert_eq!(cleaned, 1);

            Ok(())
        })
        .unwrap();
}

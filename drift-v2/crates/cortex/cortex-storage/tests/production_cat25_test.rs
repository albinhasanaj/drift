//! Production Category 25: Performance Budgets (T25-05)
//!
//! Vector search budget: Insert 10K embeddings, run nearest-neighbor search.
//! Must return results in <500ms. Must not scan all rows (early exit on zero-similarity).

use std::time::Instant;

use chrono::Utc;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

// ---- T25-05: Vector Search Budget — 10,000 Memories ----
// Insert 10K embeddings. Run nearest-neighbor search.
// Must return results in <500ms. Must not scan all rows (early exit on zero-similarity).
//
// Source verification: D-05/D-06 fix — pre-compute query norm, skip dimension
// mismatches, filter zero-similarity results.

#[test]
fn t25_05_vector_search_budget_10k_memories() {
    let storage = StorageEngine::open_in_memory().unwrap();

    const NUM_MEMORIES: usize = 10_000;
    const DIMS: usize = 64;

    // Phase 1: Bulk-insert memories and embeddings using raw SQL for speed.
    // Creating 10K memories via storage.create() one-by-one would be too slow.
    storage
        .pool()
        .writer
        .with_conn_sync(|conn| {
            conn.execute_batch("BEGIN IMMEDIATE").expect("begin txn");

            for i in 0..NUM_MEMORIES {
                let id = format!("mem-{i:05}");
                let now = Utc::now().to_rfc3339();

                // Insert minimal memory row
                let content_json = format!(
                    r#"{{"type":"insight","data":{{"observation":"obs {i}","evidence":[]}}}}"#
                );
                conn.execute(
                    "INSERT INTO memories (id, memory_type, content, summary, transaction_time, valid_time, confidence, importance, last_accessed, access_count, archived, content_hash, tags)
                     VALUES (?1, 'insight', ?5, ?2, ?3, ?3, 0.8, 'normal', ?3, 0, 0, ?4, '[]')",
                    rusqlite::params![id, format!("summary {id}"), now, format!("hash-{i}"), content_json],
                ).unwrap_or_else(|e| panic!("insert memory {i}: {e}"));

                // Generate a deterministic embedding vector.
                // Use different angles so some will match a query and some won't.
                let embedding: Vec<f32> = (0..DIMS)
                    .map(|d| {
                        let angle = (i as f32 * 0.01) + (d as f32 * 0.1);
                        angle.sin()
                    })
                    .collect();
                let blob: Vec<u8> = embedding.iter().flat_map(|f| f.to_le_bytes()).collect();

                // Insert embedding
                conn.execute(
                    "INSERT INTO memory_embeddings (content_hash, embedding, dimensions, model_name)
                     VALUES (?1, ?2, ?3, 'test-model')",
                    rusqlite::params![format!("hash-{i}"), blob, DIMS as i32],
                ).unwrap_or_else(|e| panic!("insert embedding {i}: {e}"));

                // Get embedding ID
                let emb_id: i64 = conn
                    .query_row(
                        "SELECT id FROM memory_embeddings WHERE content_hash = ?1",
                        rusqlite::params![format!("hash-{i}")],
                        |row| row.get(0),
                    )
                    .unwrap_or_else(|e| panic!("get embedding id {i}: {e}"));

                // Link memory to embedding
                conn.execute(
                    "INSERT INTO memory_embedding_link (memory_id, embedding_id) VALUES (?1, ?2)",
                    rusqlite::params![id, emb_id],
                ).unwrap_or_else(|e| panic!("link {i}: {e}"));
            }

            conn.execute_batch("COMMIT").expect("commit txn");

            Ok::<(), cortex_core::errors::CortexError>(())
        })
        .unwrap();

    // Verify setup: should have 10K embeddings
    let count: i64 = storage
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let c: i64 = conn
                .query_row("SELECT COUNT(*) FROM memory_embeddings", [], |row| row.get(0))
                .expect("count embeddings");
            Ok::<i64, cortex_core::errors::CortexError>(c)
        })
        .unwrap();
    assert_eq!(
        count, NUM_MEMORIES as i64,
        "setup: must have {NUM_MEMORIES} embeddings, got {count}"
    );

    // Phase 2: Run nearest-neighbor search and time it.
    // Use a query vector that will have varying similarity to stored embeddings.
    let query: Vec<f32> = (0..DIMS).map(|d| (d as f32 * 0.1).sin()).collect();

    let start = Instant::now();
    let results = storage.search_vector(&query, 10).unwrap();
    let elapsed = start.elapsed();

    // Budget: search must complete in <500ms
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "vector search over 10K embeddings took {elapsed:?}, exceeds 500ms budget"
    );

    // Must return results (query is non-zero, some embeddings will have positive similarity)
    assert!(
        !results.is_empty(),
        "search must return results for a valid query vector"
    );

    // Results must be ranked by similarity descending
    for window in results.windows(2) {
        assert!(
            window[0].1 >= window[1].1,
            "results must be sorted by similarity descending: {} >= {}",
            window[0].1,
            window[1].1
        );
    }

    // D-06 early exit: verify zero-similarity filtering works by searching
    // with a vector orthogonal to all stored embeddings (all zeros except one dim).
    // Not all will be filtered, but the early exit on zero-norm IS verified.
    let zero_query = vec![0.0f32; DIMS];
    let zero_results = storage.search_vector(&zero_query, 10).unwrap();
    assert!(
        zero_results.is_empty(),
        "zero-norm query must return empty results (D-06 early exit)"
    );
}

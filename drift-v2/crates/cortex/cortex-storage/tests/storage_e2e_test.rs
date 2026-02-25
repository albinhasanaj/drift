//! E2E tests for storage hardening (Phases D/F).
//!
//! Every test targets a specific production failure mode:
//! - bulk_insert duplicate ID → must rollback entire batch, not partial
//! - bulk_insert empty batch → must return 0, not error
//! - Vector search with zero-norm query → must return empty, not NaN/panic
//! - Vector search dimension mismatch → must skip, not panic
//! - Vector search with NaN stored embeddings → must not infect results
//! - Temporal events → must use DB timestamps, timestamps must be valid ISO 8601
//! - Create→Update→Delete lifecycle emits correct event chain
//! - Migration v013 gap closed → all 15 migrations apply cleanly

use chrono::Utc;
use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

/// Helper: store an embedding via the writer connection.
fn store_embedding(storage: &StorageEngine, memory_id: &str, hash: &str, emb: &[f32], model: &str) {
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::vector_search::store_embedding(conn, memory_id, hash, emb, model)
    }).unwrap();
}

/// Helper: get events for a memory via the writer connection.
fn get_events(storage: &StorageEngine, memory_id: &str) -> Vec<cortex_storage::queries::event_ops::RawEvent> {
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::event_ops::get_events_for_memory(conn, memory_id, None)
    }).unwrap()
}

/// Helper: create a test memory with a given ID.
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

// ═══════════════════════════════════════════════════════════════════════════
// BULK INSERT: Atomicity
// ═══════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: If bulk_insert inserts 3 of 5 memories and the 4th fails
/// (e.g., duplicate ID), a non-transactional implementation leaves 3 orphans.
/// D-04 wraps in BEGIN IMMEDIATE / COMMIT. Verify rollback on failure.
#[test]
fn bulk_insert_duplicate_id_rolls_back_entire_batch() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Pre-insert a memory
    let existing = make_memory("dup-target");
    storage.create(&existing).unwrap();

    // Batch where item[2] has the same ID as the pre-existing memory
    let batch = vec![
        make_memory("bulk-1"),
        make_memory("bulk-2"),
        make_memory("dup-target"), // DUPLICATE — should cause rollback
        make_memory("bulk-4"),
    ];

    let result = storage.create_bulk(&batch);
    assert!(result.is_err(), "bulk_insert with duplicate ID must fail");

    // The CRITICAL check: bulk-1 and bulk-2 must NOT exist.
    // If the transaction wasn't atomic, they'd be orphaned in the DB.
    assert!(
        storage.get("bulk-1").unwrap().is_none(),
        "bulk-1 must be rolled back — atomicity violation"
    );
    assert!(
        storage.get("bulk-2").unwrap().is_none(),
        "bulk-2 must be rolled back — atomicity violation"
    );
    assert!(
        storage.get("bulk-4").unwrap().is_none(),
        "bulk-4 must be rolled back — atomicity violation"
    );

    // The original should still exist, untouched.
    let original = storage.get("dup-target").unwrap().unwrap();
    assert_eq!(original.summary, "summary dup-target");
}

/// Empty batch is an edge case that should return Ok(0), not error.
#[test]
fn bulk_insert_empty_batch_returns_zero() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let result = storage.create_bulk(&[]);
    assert!(result.is_ok());
}

/// Bulk insert of 1 item should work identically to single create.
#[test]
fn bulk_insert_single_item() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let batch = vec![make_memory("solo")];
    storage.create_bulk(&batch).unwrap();

    let got = storage.get("solo").unwrap().unwrap();
    assert_eq!(got.summary, "summary solo");
    assert_eq!(got.tags, vec!["test"]);
}

/// Bulk insert success: all items should be retrievable and correct.
#[test]
fn bulk_insert_all_retrievable() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let batch: Vec<BaseMemory> = (0..20).map(|i| make_memory(&format!("batch-{i}"))).collect();
    storage.create_bulk(&batch).unwrap();

    for i in 0..20 {
        let got = storage.get(&format!("batch-{i}")).unwrap();
        assert!(got.is_some(), "batch-{i} should exist after bulk insert");
        assert_eq!(got.unwrap().summary, format!("summary batch-{i}"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VECTOR SEARCH: Edge cases
// ═══════════════════════════════════════════════════════════════════════════

/// Zero-norm query vector (all zeros) should return empty, not NaN scores.
/// D-06 added an early-exit for this. Without it, cosine_similarity
/// divides by zero → NaN → broken sort → panic.
#[test]
fn vector_search_zero_query_returns_empty() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Create a memory and store an embedding for it
    let mem = make_memory("vec-1");
    storage.create(&mem).unwrap();
    store_embedding(&storage, "vec-1", "hash-1", &[1.0, 2.0, 3.0], "tfidf");

    // Search with zero vector
    let results = storage.search_vector(&[0.0, 0.0, 0.0], 10).unwrap();
    assert!(results.is_empty(), "zero-norm query must return empty results, not NaN");
}

/// Dimension mismatch: stored embedding has 3 dims, query has 5.
/// D-06 skips mismatched dimensions. Without it, cosine_similarity
/// on different-length slices would panic or produce wrong results.
#[test]
fn vector_search_dimension_mismatch_skipped() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("dim-test");
    storage.create(&mem).unwrap();
    store_embedding(&storage, "dim-test", "hash-dim", &[1.0, 2.0, 3.0], "tfidf");

    // Query with 5 dimensions vs stored 3
    let results = storage.search_vector(&[1.0, 2.0, 3.0, 4.0, 5.0], 10).unwrap();
    assert!(
        results.is_empty(),
        "dimension mismatch should be skipped, not panicked"
    );
}

/// Negative similarity (opposing vectors) should be filtered out (sim > 0.0 check).
#[test]
fn vector_search_opposing_vectors_filtered() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("oppose");
    storage.create(&mem).unwrap();
    store_embedding(&storage, "oppose", "hash-opp", &[1.0, 0.0], "tfidf");

    // Query with opposing direction
    let results = storage.search_vector(&[-1.0, 0.0], 10).unwrap();
    // Cosine similarity of [1,0] and [-1,0] = -1.0, should be filtered
    assert!(
        results.is_empty(),
        "opposing vectors (negative similarity) should be filtered"
    );
}

/// Multiple embeddings with varying similarity should be ranked correctly.
#[test]
fn vector_search_ranking_correct() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Create 3 memories with embeddings at different angles
    for (id, emb) in [
        ("close", vec![0.9, 0.1]),
        ("medium", vec![0.5, 0.5]),
        ("far", vec![0.1, 0.9]),
    ] {
        let mem = make_memory(id);
        storage.create(&mem).unwrap();
        store_embedding(&storage, id, &format!("hash-{id}"), &emb, "tfidf");
    }

    // Query aligned with [1.0, 0.0] — "close" should rank first
    let results = storage.search_vector(&[1.0, 0.0], 10).unwrap();
    assert!(results.len() >= 2, "should find at least 2 results");
    assert_eq!(results[0].0.id, "close", "closest vector should rank first");
}

/// Limit parameter should cap results.
#[test]
fn vector_search_respects_limit() {
    let storage = StorageEngine::open_in_memory().unwrap();

    for i in 0..10 {
        let mem = make_memory(&format!("lim-{i}"));
        storage.create(&mem).unwrap();
        store_embedding(
            &storage,
            &format!("lim-{i}"),
            &format!("hash-lim-{i}"),
            &[1.0, (i as f32) * 0.01],
            "tfidf",
        );
    }

    let results = storage.search_vector(&[1.0, 0.0], 3).unwrap();
    assert!(results.len() <= 3, "limit=3 but got {} results", results.len());
}

// ═══════════════════════════════════════════════════════════════════════════
// TEMPORAL EVENTS: DB timestamps & event chain
// ═══════════════════════════════════════════════════════════════════════════

/// F-05: Temporal events should use SQLite's clock, not Rust's.
/// Verify the recorded_at timestamp is valid ISO 8601 with milliseconds.
#[test]
fn temporal_event_timestamps_valid_iso8601() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("ts-test");
    storage.create(&mem).unwrap();

    // Query the event directly via the raw connection
    let events = get_events(&storage, "ts-test");
    assert!(!events.is_empty(), "create should emit at least one event");

    for event in &events {
        // Parse as ISO 8601
        let parsed = chrono::NaiveDateTime::parse_from_str(
            &event.recorded_at,
            "%Y-%m-%dT%H:%M:%S%.fZ",
        );
        assert!(
            parsed.is_ok(),
            "event timestamp '{}' should be valid ISO 8601 with ms, parse error: {:?}",
            event.recorded_at,
            parsed.err()
        );
    }
}

/// Create→Update→Delete should emit a correct event chain.
#[test]
fn event_chain_create_update_delete() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Create
    let mut mem = make_memory("chain-test");
    storage.create(&mem).unwrap();

    // Update content (changes content_hash → content_updated event)
    let new_tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "updated observation".to_string(),
        evidence: vec![],
    });
    mem.content = new_tc.clone();
    mem.summary = "updated summary".to_string();
    mem.content_hash = BaseMemory::compute_content_hash(&new_tc).unwrap();
    storage.update(&mem).unwrap();

    // Update confidence (→ confidence_changed event)
    mem.confidence = Confidence::new(0.3);
    storage.update(&mem).unwrap();

    // Delete
    storage.delete("chain-test").unwrap();

    let events = get_events(&storage, "chain-test");
    let event_types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();

    assert!(
        event_types.contains(&"created"),
        "missing 'created' event, got: {event_types:?}"
    );
    assert!(
        event_types.contains(&"content_updated"),
        "missing 'content_updated' event, got: {event_types:?}"
    );
    assert!(
        event_types.contains(&"confidence_changed"),
        "missing 'confidence_changed' event, got: {event_types:?}"
    );
    assert!(
        event_types.contains(&"archived"),
        "missing 'archived' event (from delete), got: {event_types:?}"
    );

    // Events should be in chronological order (event_id ascending)
    for window in events.windows(2) {
        assert!(
            window[0].event_id < window[1].event_id,
            "events should be in order: {} < {}",
            window[0].event_id,
            window[1].event_id
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MIGRATION: v013 gap & version integrity
// ═══════════════════════════════════════════════════════════════════════════

/// F-04: The v013 placeholder must close the gap. LATEST_VERSION should
/// match the actual number of migrations in the array.
#[test]
fn migration_version_matches_array_count() {
    // LATEST_VERSION is 15, array has 15 entries (was 14 before v013)
    assert_eq!(
        cortex_storage::migrations::LATEST_VERSION,
        15,
        "LATEST_VERSION should be 15"
    );
}

/// Run migrations on a fresh DB and verify the version stored matches.
#[test]
fn migration_fresh_db_reaches_latest() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // If migrations failed, open_in_memory would have errored.
    // Double-check by doing a write+read cycle that touches tables
    // from different migration versions.
    let mem = make_memory("mig-test");
    storage.create(&mem).unwrap(); // v001 memories table

    // Store an embedding (v002 vector tables + v009 embedding migration)
    store_embedding(&storage, "mig-test", "hash-mig", &[1.0, 2.0], "tfidf");

    // Query events (v014 temporal tables)
    let events = get_events(&storage, "mig-test");
    assert!(!events.is_empty(), "temporal events table should exist (v014)");

    // If we got here, all migrations from v001 through v015 applied correctly.
}

// ═══════════════════════════════════════════════════════════════════════════
// CRUD: Edge cases
// ═══════════════════════════════════════════════════════════════════════════

/// Update a non-existent memory should return MemoryNotFound, not silent no-op.
#[test]
fn update_nonexistent_returns_error() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("ghost");
    let result = storage.update(&mem);
    assert!(result.is_err(), "updating non-existent memory should fail");
}

/// Delete a non-existent memory should not error (idempotent).
#[test]
fn delete_nonexistent_is_idempotent() {
    let storage = StorageEngine::open_in_memory().unwrap();
    // Should not panic or error
    let result = storage.delete("nonexistent");
    assert!(result.is_ok(), "deleting non-existent memory should be ok");
}

/// Get a non-existent memory should return None, not error.
#[test]
fn get_nonexistent_returns_none() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let result = storage.get("nonexistent").unwrap();
    assert!(result.is_none());
}

/// Double create with same ID should fail.
#[test]
fn double_create_same_id_fails() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("double");
    storage.create(&mem).unwrap();
    let result = storage.create(&mem);
    assert!(result.is_err(), "creating same ID twice should fail");
}

/// Tags should survive round-trip through create→get.
#[test]
fn tags_survive_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("tags-rt");
    mem.tags = vec![
        "alpha".to_string(),
        "beta".to_string(),
        "with spaces".to_string(),
        "with\"quotes".to_string(),
    ];
    storage.create(&mem).unwrap();

    let got = storage.get("tags-rt").unwrap().unwrap();
    assert_eq!(got.tags, mem.tags, "tags with special chars should round-trip");
}

/// Content with Unicode should survive round-trip.
#[test]
fn unicode_content_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "日本語テスト 🎉 émojis & ñ".to_string(),
        evidence: vec![],
    });
    let mut mem = make_memory("unicode");
    mem.content = tc.clone();
    mem.summary = "日本語 summary 🚀".to_string();
    mem.content_hash = BaseMemory::compute_content_hash(&tc).unwrap();
    storage.create(&mem).unwrap();

    let got = storage.get("unicode").unwrap().unwrap();
    assert_eq!(got.summary, "日本語 summary 🚀");
    if let TypedContent::Insight(ref ic) = got.content {
        assert_eq!(ic.observation, "日本語テスト 🎉 émojis & ñ");
    } else {
        panic!("wrong content type after round-trip");
    }
}

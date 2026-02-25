//! Cat 7: Vector Search & Embedding Storage (VS-01 through VS-12)
//!
//! Tests embedding dedup by content_hash, memory-embedding link,
//! re-embed upsert, SAVEPOINT rollback, cosine similarity, zero-norm,
//! dimension mismatch, limit, negative similarity filter, bytes roundtrip,
//! model_name tracking, and full BaseMemory fetch.

use chrono::Utc;

use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::queries::vector_search;
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

fn store_emb(storage: &StorageEngine, memory_id: &str, hash: &str, emb: &[f32], model: &str) {
    storage.pool().writer.with_conn_sync(|conn| {
        vector_search::store_embedding(conn, memory_id, hash, emb, model)
    }).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-01: store_embedding deduplicates by content_hash
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_01_embedding_dedup_by_content_hash() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem1 = make_memory("vs01-m1");
    let mem2 = make_memory("vs01-m2");
    storage.create(&mem1).unwrap();
    storage.create(&mem2).unwrap();

    let emb = vec![1.0f32, 0.0, 0.0];
    store_emb(&storage, "vs01-m1", "shared-hash", &emb, "model-a");
    store_emb(&storage, "vs01-m2", "shared-hash", &emb, "model-a");

    // Should be only 1 embedding row (ON CONFLICT DO UPDATE).
    let count: i64 = storage.pool().writer.with_conn_sync(|conn| {
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM memory_embeddings WHERE content_hash = 'shared-hash'",
            [],
            |row| row.get(0),
        ).unwrap())
    }).unwrap();
    assert_eq!(count, 1, "should deduplicate by content_hash");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-02: store_embedding links memory to embedding
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_02_embedding_link_created() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("vs02");
    storage.create(&mem).unwrap();

    store_emb(&storage, "vs02", "h-vs02", &[1.0, 0.0, 0.0], "model");

    let count: i64 = storage.pool().writer.with_conn_sync(|conn| {
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM memory_embedding_link WHERE memory_id = 'vs02'",
            [],
            |row| row.get(0),
        ).unwrap())
    }).unwrap();
    assert_eq!(count, 1, "should have exactly 1 link");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-03: store_embedding upserts link on re-embed
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_03_reembed_upserts_link() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("vs03");
    storage.create(&mem).unwrap();

    store_emb(&storage, "vs03", "h1", &[1.0, 0.0, 0.0], "model");
    store_emb(&storage, "vs03", "h2", &[0.0, 1.0, 0.0], "model");

    // Should still have 1 link (upserted), pointing to the new embedding.
    let link_count: i64 = storage.pool().writer.with_conn_sync(|conn| {
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM memory_embedding_link WHERE memory_id = 'vs03'",
            [],
            |row| row.get(0),
        ).unwrap())
    }).unwrap();
    assert_eq!(link_count, 1, "should have 1 link after re-embed (upsert)");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-05: search_vector cosine similarity correctness
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_05_cosine_similarity_correctness() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem_a = make_memory("vs05-a");
    let mem_b = make_memory("vs05-b");
    let mem_c = make_memory("vs05-c");
    storage.create(&mem_a).unwrap();
    storage.create(&mem_b).unwrap();
    storage.create(&mem_c).unwrap();

    store_emb(&storage, "vs05-a", "ha", &[1.0, 0.0, 0.0], "model");
    store_emb(&storage, "vs05-b", "hb", &[0.9, 0.1, 0.0], "model");
    store_emb(&storage, "vs05-c", "hc", &[0.0, 0.0, 1.0], "model");

    let results = storage.search_vector(&[1.0, 0.0, 0.0], 10).unwrap();

    // A should be first (exact match, sim≈1.0).
    assert!(!results.is_empty(), "should have results");
    assert_eq!(results[0].0.id, "vs05-a", "exact match should rank first");

    // B should be second.
    if results.len() >= 2 {
        assert_eq!(results[1].0.id, "vs05-b");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-06: search_vector filters zero-norm query
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_06_zero_norm_query_returns_empty() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("vs06");
    storage.create(&mem).unwrap();
    store_emb(&storage, "vs06", "h6", &[1.0, 0.0, 0.0], "model");

    let results = storage.search_vector(&[0.0, 0.0, 0.0], 10).unwrap();
    assert!(results.is_empty(), "zero-norm query should return empty");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-07: search_vector skips dimension mismatches
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_07_dimension_mismatch_skipped() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem1 = make_memory("vs07-3d");
    let mem2 = make_memory("vs07-5d");
    storage.create(&mem1).unwrap();
    storage.create(&mem2).unwrap();

    store_emb(&storage, "vs07-3d", "h3d", &[1.0, 0.0, 0.0], "model");
    store_emb(&storage, "vs07-5d", "h5d", &[1.0, 0.0, 0.0, 0.0, 0.0], "model");

    // Search with 3D query.
    let results = storage.search_vector(&[1.0, 0.0, 0.0], 10).unwrap();
    assert_eq!(results.len(), 1, "should only return 3D match");
    assert_eq!(results[0].0.id, "vs07-3d");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-08: search_vector respects limit
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_08_search_vector_limit() {
    let storage = StorageEngine::open_in_memory().unwrap();

    for i in 0..20 {
        let mem = make_memory(&format!("vs08-{i}"));
        storage.create(&mem).unwrap();
        // All similar vectors.
        let v = vec![1.0f32, 0.1 * i as f32, 0.0];
        store_emb(&storage, &format!("vs08-{i}"), &format!("h08-{i}"), &v, "model");
    }

    let results = storage.search_vector(&[1.0, 0.0, 0.0], 5).unwrap();
    assert_eq!(results.len(), 5, "should return exactly 5");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-09: search_vector only returns positive similarity
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_09_negative_similarity_filtered() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("vs09");
    storage.create(&mem).unwrap();
    store_emb(&storage, "vs09", "h9", &[-1.0, 0.0, 0.0], "model");

    let results = storage.search_vector(&[1.0, 0.0, 0.0], 10).unwrap();
    // Cosine similarity of [1,0,0] and [-1,0,0] is -1.0 → should be filtered.
    assert!(results.is_empty(), "negative similarity should be filtered");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-10: bytes_to_f32_vec roundtrip fidelity
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_10_bytes_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("vs10");
    storage.create(&mem).unwrap();

    let original: Vec<f32> = (0..128).map(|i| i as f32 * 0.01 + 0.001).collect();
    store_emb(&storage, "vs10", "h10", &original, "model");

    // Read back the embedding blob and verify.
    let (blob, dims): (Vec<u8>, i32) = storage.pool().writer.with_conn_sync(|conn| {
        Ok(conn.query_row(
            "SELECT embedding, dimensions FROM memory_embeddings WHERE content_hash = 'h10'",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i32>(1)?)),
        ).unwrap())
    }).unwrap();

    assert_eq!(dims, 128);
    let restored: Vec<f32> = blob
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    assert_eq!(original, restored, "bytes roundtrip should be exact");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-11: embedding_model_info tracks model version
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_11_model_name_tracked() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("vs11");
    storage.create(&mem).unwrap();

    store_emb(&storage, "vs11", "h11", &[1.0, 0.0], "text-embedding-3-small");

    let model: String = storage.pool().writer.with_conn_sync(|conn| {
        Ok(conn.query_row(
            "SELECT model_name FROM memory_embeddings WHERE content_hash = 'h11'",
            [],
            |row| row.get(0),
        ).unwrap())
    }).unwrap();
    assert_eq!(model, "text-embedding-3-small");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VS-12: search_vector fetches full BaseMemory with links
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vs_12_search_vector_full_memory() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("vs12");
    mem.linked_patterns = vec![PatternLink {
        pattern_id: "p1".into(),
        pattern_name: "pat1".into(),
    }];
    storage.create(&mem).unwrap();

    store_emb(&storage, "vs12", "h12", &[1.0, 0.0, 0.0], "model");

    let results = storage.search_vector(&[1.0, 0.0, 0.0], 10).unwrap();
    assert_eq!(results.len(), 1);
    assert!(!results[0].0.linked_patterns.is_empty(), "should load links");
}

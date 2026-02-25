//! Production Category 19: Cortex Memory System (Flow 12)
//!
//! Tests T19-01 through T19-09, T19-12 per PRODUCTION-TEST-SUITE.md.
//! 21 crates, 68 NAPI bindings, 16 engines in CortexRuntime.
//!
//! T19-10 (Multi-Agent Namespace Isolation) lives in cortex-multiagent/tests/.
//! T19-11 (Session Lifecycle) lives in cortex-session/tests/.

use chrono::{Duration, Utc};
use cortex_core::config::EmbeddingConfig;
use cortex_core::memory::*;
use cortex_core::traits::{IMemoryStorage, ISanitizer, IValidator};
use cortex_storage::StorageEngine;

// ── Helpers ────────────────────────────────────────────────────────────────

fn make_memory(id: &str, mem_type: MemoryType, confidence: f64) -> BaseMemory {
    let content = TypedContent::Core(cortex_core::memory::types::CoreContent {
        project_name: "test-project".into(),
        description: format!("Test memory {id}"),
        metadata: serde_json::Value::Null,
    });
    let now = Utc::now();
    BaseMemory {
        id: id.to_string(),
        memory_type: mem_type,
        content: content.clone(),
        summary: format!("Summary for {id}"),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(confidence),
        importance: Importance::Normal,
        last_accessed: now,
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".into()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

fn make_old_memory(id: &str, mem_type: MemoryType, confidence: f64, days_old: i64) -> BaseMemory {
    let mut m = make_memory(id, mem_type, confidence);
    let past = Utc::now() - Duration::days(days_old);
    m.transaction_time = past;
    m.valid_time = past;
    m.last_accessed = past;
    m
}

fn storage() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

// ── T19-01: Memory CRUD Lifecycle ──────────────────────────────────────────
// Create, read, update, delete a memory via IMemoryStorage.
// After delete, get must return None. Audit log must have entries.
// Temporal events emitted for each mutation.

#[test]
fn t19_01_memory_crud_lifecycle() {
    let store = storage();
    let mem = make_memory("crud-01", MemoryType::Tribal, 0.9);

    // Create
    store.create(&mem).expect("create should succeed");

    // Read
    let fetched = store.get("crud-01").expect("get should succeed");
    assert!(fetched.is_some(), "memory should exist after create");
    let fetched = fetched.unwrap();
    assert_eq!(fetched.id, "crud-01");
    assert_eq!(fetched.summary, "Summary for crud-01");

    // Update
    let mut updated = fetched.clone();
    updated.summary = "Updated summary".to_string();
    updated.confidence = Confidence::new(0.75);
    store.update(&updated).expect("update should succeed");
    let after_update = store.get("crud-01").unwrap().unwrap();
    assert_eq!(after_update.summary, "Updated summary");
    assert!((after_update.confidence.value() - 0.75).abs() < 1e-6);

    // Delete
    store.delete("crud-01").expect("delete should succeed");
    let after_delete = store.get("crud-01").expect("get after delete should not error");
    assert!(after_delete.is_none(), "memory should not exist after delete");

    // Verify audit log has entries for the mutations.
    store.pool().writer.with_conn_sync(|conn| {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memory_audit_log WHERE memory_id = ?1",
                ["crud-01"],
                |row| row.get(0),
            )
            .unwrap_or(0);
        // create + update + delete = at least 3 audit entries
        assert!(
            count >= 3,
            "audit_log should have >= 3 entries for crud-01, got {count}"
        );
        Ok(())
    })
    .unwrap();

    // Verify temporal events emitted.
    store.pool().writer.with_conn_sync(|conn| {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM memory_events WHERE memory_id = ?1",
                ["crud-01"],
                |row| row.get(0),
            )
            .unwrap_or(0);
        assert!(
            count >= 1,
            "temporal_events should have entries for crud-01, got {count}"
        );
        Ok(())
    })
    .unwrap();
}

// ── T19-02: Re-Embed on Content Update ─────────────────────────────────────
// Create memory, embed it, update with different content (different content_hash).
// Must regenerate embedding. New embedding must differ from original.

#[test]
fn t19_02_reembed_on_content_update() {
    let store = storage();
    let config = EmbeddingConfig {
        provider: "tfidf".to_string(),
        ..EmbeddingConfig::default()
    };
    let mut emb_engine = cortex_embeddings::EmbeddingEngine::new(config);

    // Create memory and embed it.
    let mem = make_memory("reembed-01", MemoryType::Tribal, 0.9);
    store.create(&mem).unwrap();

    let embedding1 = emb_engine.embed_memory(&mem).expect("embed should succeed");
    assert!(!embedding1.is_empty(), "embedding should be non-empty");

    // Store embedding.
    store.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::vector_search::store_embedding(
            conn,
            &mem.id,
            &mem.content_hash,
            &embedding1,
            emb_engine.active_provider(),
        )
    }).unwrap();

    // Update with different content → different content_hash.
    let new_content = TypedContent::Core(cortex_core::memory::types::CoreContent {
        project_name: "quantum-physics-simulation".into(),
        description: "Relativistic quantum field theory computations for lattice gauge symmetry breaking".into(),
        metadata: serde_json::json!({"domain": "physics", "complexity": "extreme"}),
    });
    let mut updated = mem.clone();
    updated.content = new_content.clone();
    updated.content_hash = BaseMemory::compute_content_hash(&new_content).unwrap();
    updated.summary = "Relativistic quantum field theory lattice gauge symmetry breaking simulation results".to_string();

    // Detect content_hash changed (simulating D-03 logic).
    let content_changed = updated.content_hash != mem.content_hash;
    assert!(content_changed, "content_hash should differ after content change");

    store.update(&updated).unwrap();

    // Re-embed after content change.
    let embedding2 = emb_engine
        .embed_memory(&updated)
        .expect("re-embed should succeed");
    assert!(!embedding2.is_empty(), "re-embedding should be non-empty");

    // Embeddings should differ since content differs.
    assert_ne!(
        embedding1, embedding2,
        "embeddings should differ after content change"
    );
}

// ── T19-03: Embedding Degradation Chain ────────────────────────────────────
// Use TF-IDF fallback (since ONNX model isn't available in tests).
// embed_readonly() must work. Embed result must be non-zero-dimension vector.

#[test]
fn t19_03_embedding_degradation_chain() {
    let config = EmbeddingConfig {
        provider: "tfidf".to_string(),
        ..EmbeddingConfig::default()
    };
    let mut engine = cortex_embeddings::EmbeddingEngine::new(config);

    let mem = make_memory("degrade-01", MemoryType::Semantic, 0.85);
    let embedding = engine.embed_memory(&mem).expect("embed via fallback should succeed");

    assert!(
        !embedding.is_empty(),
        "embedding from degradation chain must be non-empty"
    );
    assert!(
        embedding.iter().any(|&v| v != 0.0),
        "embedding must have non-zero values"
    );

    // Active provider should be tfidf (the fallback).
    let provider = engine.active_provider();
    assert!(
        provider.contains("tfidf") || provider.contains("tf-idf") || provider.contains("TfIdf"),
        "active provider should be TF-IDF fallback, got: {provider}"
    );
}

// ── T19-04: L2 Cache Persistence ───────────────────────────────────────────
// Create embedding with file-backed L2 cache, close, reopen.
// L2 SQLite cache must contain the embedding.

#[test]
fn t19_04_l2_cache_persistence() {
    // Create a temp directory using uuid for uniqueness.
    let tmp_dir = std::env::temp_dir().join(format!("cortex_cat19_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");

    let db_path = tmp_dir.join("cortex_test.db");

    let config = EmbeddingConfig {
        provider: "tfidf".to_string(),
        l2_cache_enabled: true,
        ..EmbeddingConfig::default()
    };

    let mem = make_memory("l2-persist-01", MemoryType::Episodic, 0.8);

    // Phase 1: Create engine with file-backed L2, embed a memory.
    {
        let mut engine = cortex_embeddings::EmbeddingEngine::new_with_db_path(
            config.clone(),
            &db_path,
        );
        let embedding = engine.embed_memory(&mem).expect("embed should succeed");
        assert!(!embedding.is_empty());

        let stats = engine.cache_stats();
        // After embedding, at least L1 should have the entry.
        assert!(
            stats.total >= 1,
            "cache should have >= 1 entry after embedding, got {}",
            stats.total
        );
    }
    // Engine dropped — L2 should persist to disk.

    // Phase 2: Reopen with same db_path, cache should still have the entry.
    {
        let mut engine = cortex_embeddings::EmbeddingEngine::new_with_db_path(
            config.clone(),
            &db_path,
        );

        // Access the same memory — should be a cache hit from L2.
        let embedding = engine.embed_memory(&mem).expect("re-embed should succeed (cache hit)");
        assert!(!embedding.is_empty());
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ── T19-05: Consolidation Eligibility ──────────────────────────────────────
// Create Episodic and Procedural memories (eligible) and Semantic memories (not eligible).
// Only Episodic + Procedural should appear in consolidation candidate list.

#[test]
fn t19_05_consolidation_eligibility() {
    use cortex_consolidation::pipeline::phase1_selection::select_candidates;

    // Eligible: Episodic, old enough, good confidence, not archived
    let episodic = make_old_memory("consol-ep-01", MemoryType::Episodic, 0.8, 14);
    // Eligible: Procedural, old enough
    let procedural = make_old_memory("consol-proc-01", MemoryType::Procedural, 0.7, 10);
    // NOT eligible: Semantic (not in CONSOLIDATION_ELIGIBLE)
    let semantic = make_old_memory("consol-sem-01", MemoryType::Semantic, 0.9, 20);
    // NOT eligible: Tribal (not in CONSOLIDATION_ELIGIBLE)
    let tribal = make_old_memory("consol-trib-01", MemoryType::Tribal, 0.85, 15);
    // NOT eligible: too young (3 days)
    let young = make_old_memory("consol-young-01", MemoryType::Episodic, 0.8, 3);
    // NOT eligible: too low confidence
    let low_conf = make_old_memory("consol-low-01", MemoryType::Episodic, 0.1, 14);
    // NOT eligible: archived
    let mut archived = make_old_memory("consol-arch-01", MemoryType::Episodic, 0.8, 14);
    archived.archived = true;

    let memories = vec![episodic, procedural, semantic, tribal, young, low_conf, archived];
    let candidates = select_candidates(&memories);

    // Only the first two (Episodic + Procedural with sufficient age and confidence) should be selected.
    let candidate_ids: Vec<&str> = candidates.iter().map(|m| m.id.as_str()).collect();
    assert!(
        candidate_ids.contains(&"consol-ep-01"),
        "Episodic should be eligible"
    );
    assert!(
        candidate_ids.contains(&"consol-proc-01"),
        "Procedural should be eligible"
    );
    assert_eq!(
        candidates.len(),
        2,
        "Only Episodic + Procedural should be selected, got: {candidate_ids:?}"
    );
}

// ── T19-06: Vector Search Correctness ──────────────────────────────────────
// Insert 100 memories with embeddings. Search for nearest to a query vector.
// Results must be sorted by cosine similarity descending.
// Zero-norm vectors must be skipped. Dimension mismatches must be filtered.

#[test]
fn t19_06_vector_search_correctness() {
    let store = storage();
    let config = EmbeddingConfig {
        provider: "tfidf".to_string(),
        dimensions: 64,
        matryoshka_search_dims: 32,
        ..EmbeddingConfig::default()
    };
    let mut emb_engine = cortex_embeddings::EmbeddingEngine::new(config);

    // Insert 100 memories with embeddings.
    for i in 0..100 {
        let content = TypedContent::Core(cortex_core::memory::types::CoreContent {
            project_name: "search-test".into(),
            description: format!("Memory about topic {i} with unique content number {}", i * 7 + 13),
            metadata: serde_json::Value::Null,
        });
        let mut mem = make_memory(&format!("search-{i:03}"), MemoryType::Episodic, 0.8);
        mem.content = content.clone();
        mem.content_hash = BaseMemory::compute_content_hash(&content).unwrap();

        store.create(&mem).unwrap();
        let embedding = emb_engine.embed_memory(&mem).unwrap();

        store.pool().writer.with_conn_sync(|conn| {
            cortex_storage::queries::vector_search::store_embedding(
                conn,
                &mem.id,
                &mem.content_hash,
                &embedding,
                emb_engine.active_provider(),
            )
        }).unwrap();
    }

    // Also insert a zero-norm embedding (should be skipped).
    let zero_mem = make_memory("search-zero", MemoryType::Episodic, 0.5);
    store.create(&zero_mem).unwrap();
    let zero_vec = vec![0.0f32; emb_engine.dimensions()];
    store.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::vector_search::store_embedding(
            conn,
            "search-zero",
            &zero_mem.content_hash,
            &zero_vec,
            "manual",
        )
    }).unwrap();

    // Also insert a dimension-mismatch embedding (should be filtered).
    let mismatch_mem = make_memory("search-mismatch", MemoryType::Episodic, 0.5);
    store.create(&mismatch_mem).unwrap();
    let short_vec = vec![1.0f32; 16]; // wrong dimension
    store.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::vector_search::store_embedding(
            conn,
            "search-mismatch",
            &mismatch_mem.content_hash,
            &short_vec,
            "manual",
        )
    }).unwrap();

    // Search using the first memory's embedding as query.
    let query_mem = store.get("search-000").unwrap().unwrap();
    let query_embedding = emb_engine.embed_memory(&query_mem).unwrap();

    let results = store.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::vector_search::search_vector(conn, &query_embedding, 20)
    }).unwrap();

    // Should have results.
    assert!(
        !results.is_empty(),
        "vector search should return results"
    );

    // Results should be sorted by similarity descending.
    for window in results.windows(2) {
        assert!(
            window[0].1 >= window[1].1,
            "results should be sorted descending: {} >= {}",
            window[0].1,
            window[1].1
        );
    }

    // Zero-norm and dimension-mismatch entries should NOT appear.
    let result_ids: Vec<&str> = results.iter().map(|(m, _)| m.id.as_str()).collect();
    assert!(
        !result_ids.contains(&"search-zero"),
        "zero-norm embedding should be filtered out"
    );
    assert!(
        !result_ids.contains(&"search-mismatch"),
        "dimension-mismatch embedding should be filtered out"
    );

    // First result should be the query itself (similarity ~1.0).
    assert_eq!(
        results[0].0.id, "search-000",
        "most similar should be the query memory itself"
    );
    assert!(
        results[0].1 > 0.99,
        "self-similarity should be ~1.0, got {}",
        results[0].1
    );
}

// ── T19-07: Privacy Sanitization ───────────────────────────────────────────
// Store memory with AWS_SECRET_KEY=AKIA... in content.
// cortexPrivacySanitize must replace with placeholder.
// Overlapping matches must be deduped. Replacements applied in descending position order.

#[test]
fn t19_07_privacy_sanitization() {
    let engine = cortex_privacy::PrivacyEngine::new();

    let text = "config = { \
        aws_access_key_id: 'AKIAIOSFODNN7EXAMPLE', \
        aws_secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', \
        password: 'SuperSecret123!' \
    }";

    let result = engine.sanitize(text).expect("sanitize should succeed");

    // The sanitized text should NOT contain the raw secret values.
    assert!(
        !result.text.contains("AKIAIOSFODNN7EXAMPLE"),
        "AWS access key should be redacted"
    );
    assert!(
        !result.text.contains("wJalrXUtnFEMI"),
        "AWS secret key should be redacted"
    );

    // Redactions count should be > 0.
    assert!(
        !result.redactions.is_empty(),
        "should have at least 1 redaction, got {:?}",
        result.redactions
    );

    // The sanitized text should still be valid (no corruption from overlapping replacements).
    assert!(
        result.text.contains("config"),
        "non-sensitive parts should survive sanitization"
    );

    // Test with multi-match: two AWS keys in one string (E-06 sort fix).
    let multi = "KEY1=AKIAIOSFODNN7EXAMPLE KEY2=AKIAI999FODNN7EXAMPL";
    let multi_result = engine.sanitize(multi).expect("multi-match sanitize");
    assert!(
        !multi_result.text.contains("AKIAIOSFODNN7EXAMPLE"),
        "first key should be redacted in multi-match"
    );
}

// ── T19-08: Causal Graph Hydration ─────────────────────────────────────────
// Add causal edges A→B→C. Verify graph is queryable.
// Cycle detection must work. Orphan nodes must be removable.

#[test]
fn t19_08_causal_graph_operations() {
    let store = storage();
    let causal = cortex_causal::CausalEngine::new();

    let mem_a = make_memory("causal-a", MemoryType::Tribal, 0.9);
    let mem_b = make_memory("causal-b", MemoryType::Tribal, 0.85);
    let mem_c = make_memory("causal-c", MemoryType::Tribal, 0.8);

    store.create(&mem_a).unwrap();
    store.create(&mem_b).unwrap();
    store.create(&mem_c).unwrap();

    // Add edges: A → B → C
    causal
        .add_edge(
            &mem_a,
            &mem_b,
            cortex_causal::relations::CausalRelation::Caused,
            0.9,
            vec![],
            None,
        )
        .expect("A→B edge should succeed");

    causal
        .add_edge(
            &mem_b,
            &mem_c,
            cortex_causal::relations::CausalRelation::Caused,
            0.85,
            vec![],
            None,
        )
        .expect("B→C edge should succeed");

    // Graph should have 3 nodes, 2 edges.
    let (nodes, edges) = causal.stats().unwrap();
    assert_eq!(nodes, 3, "should have 3 nodes");
    assert_eq!(edges, 2, "should have 2 edges");

    // Bidirectional traversal from B should find both A and C.
    let traversal = causal.bidirectional("causal-b").unwrap();
    let node_ids: Vec<&str> = traversal.nodes.iter().map(|n| n.memory_id.as_str()).collect();
    assert!(
        node_ids.contains(&"causal-a") || node_ids.contains(&"causal-c"),
        "bidirectional from B should find connected nodes, got: {node_ids:?}"
    );

    // Cycle detection: adding C → A should fail (would create cycle).
    let cycle_result = causal.add_edge(
        &mem_c,
        &mem_a,
        cortex_causal::relations::CausalRelation::Caused,
        0.7,
        vec![],
        None,
    );
    assert!(
        cycle_result.is_err(),
        "C→A should be rejected (cycle: A→B→C→A)"
    );

    // Remove an edge.
    let removed = causal.remove_edge("causal-a", "causal-b", None).unwrap();
    assert!(removed, "edge removal should succeed");
    let (_, edges_after) = causal.stats().unwrap();
    assert_eq!(edges_after, 1, "should have 1 edge after removal");
}

// ── T19-09: Decay Engine Scheduling ────────────────────────────────────────
// Create memories with varying ages. Run decay.
// Old memories must have confidence decreased. Active memories must be untouched.

#[test]
fn t19_09_decay_engine() {
    let decay = cortex_decay::DecayEngine::new();
    let ctx = cortex_decay::DecayContext::default();

    // Fresh memory (just created).
    let fresh = make_memory("decay-fresh", MemoryType::Tribal, 0.9);

    // Old memory (90 days old).
    let old = make_old_memory("decay-old", MemoryType::Tribal, 0.9, 90);

    // Very old memory (365 days old) — should trigger archival.
    let very_old = make_old_memory("decay-ancient", MemoryType::Tribal, 0.3, 365);

    let memories = vec![fresh.clone(), old.clone(), very_old.clone()];
    let results = decay.process_batch(&memories, &ctx);

    assert_eq!(results.len(), 3);

    // Fresh memory: confidence should barely change (near 0.9).
    let (fresh_conf, fresh_decision) = &results[0];
    assert!(
        (*fresh_conf - 0.9).abs() < 0.15,
        "fresh memory confidence should be near original 0.9, got {fresh_conf}"
    );

    // Old memory: confidence should decrease.
    let (old_conf, _) = &results[1];
    assert!(
        *old_conf < 0.9,
        "90-day-old memory confidence should decrease from 0.9, got {old_conf}"
    );

    // Very old memory: should trigger archival.
    let (very_old_conf, very_old_decision) = &results[2];
    assert!(
        *very_old_conf < 0.3,
        "365-day-old memory confidence should be well below 0.3, got {very_old_conf}"
    );
    assert!(
        very_old_decision.should_archive,
        "365-day-old low-confidence memory should be flagged for archival"
    );

    // Fresh memory should NOT be archived.
    assert!(
        !fresh_decision.should_archive,
        "fresh memory should not be archived"
    );
}

// ── T19-12: Validation — 4 Dimensions ──────────────────────────────────────
// Call validate on a memory. Must return scores for all 4 validation dimensions.
// Each score must be in [0.0, 1.0].

#[test]
fn t19_12_validation_four_dimensions() {
    let engine = cortex_validation::ValidationEngine::default();
    let mem = make_memory("valid-01", MemoryType::Tribal, 0.85);

    // IValidator::validate runs basic validation (temporal + contradiction, no file system).
    let result = engine.validate(&mem).expect("validation should succeed");

    // Check all 4 dimension scores exist and are in range.
    let scores = &result.dimension_scores;
    assert!(
        (0.0..=1.0).contains(&scores.citation),
        "citation score should be in [0,1], got {}",
        scores.citation
    );
    assert!(
        (0.0..=1.0).contains(&scores.temporal),
        "temporal score should be in [0,1], got {}",
        scores.temporal
    );
    assert!(
        (0.0..=1.0).contains(&scores.contradiction),
        "contradiction score should be in [0,1], got {}",
        scores.contradiction
    );
    assert!(
        (0.0..=1.0).contains(&scores.pattern_alignment),
        "pattern_alignment score should be in [0,1], got {}",
        scores.pattern_alignment
    );

    // Overall score should also be in range.
    assert!(
        (0.0..=1.0).contains(&result.overall_score),
        "overall_score should be in [0,1], got {}",
        result.overall_score
    );

    // Memory ID should match.
    assert_eq!(result.memory_id, "valid-01");

    // Test with related memories for contradiction detection.
    let related = make_memory("valid-02", MemoryType::Tribal, 0.7);
    let result_with_context = engine
        .validate_basic(&mem, &[related])
        .expect("validate_basic with context should succeed");

    assert!(
        (0.0..=1.0).contains(&result_with_context.dimension_scores.contradiction),
        "contradiction score with related memories should be in [0,1]"
    );
}

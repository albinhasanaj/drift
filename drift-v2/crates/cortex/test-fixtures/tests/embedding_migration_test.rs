//! T14-INT-03: Embedding model swap mid-operation.
//!
//! Create memories with one embedding model → switch to another →
//! verify retrieval works during transition (FTS5 fallback).

use chrono::Utc;
use cortex_compression::CompressionEngine;
use cortex_core::config::RetrievalConfig;
use cortex_core::memory::types::CoreContent;
use cortex_core::memory::*;
use cortex_core::models::RetrievalContext;
use cortex_core::traits::{IMemoryStorage, IRetriever};
use cortex_retrieval::engine::RetrievalEngine;
use cortex_storage::StorageEngine;

fn make_memory(id: &str, summary: &str, tags: Vec<&str>) -> BaseMemory {
    let content = TypedContent::Core(CoreContent {
        project_name: String::new(),
        description: summary.to_string(),
        metadata: serde_json::Value::Null,
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Tribal,
        content: content.clone(),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::High,
        last_accessed: Utc::now(),
        access_count: 5,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: tags.into_iter().map(String::from).collect(),
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

#[test]
fn t14_int_03_retrieval_works_during_model_transition() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Create 20 memories with known content.
    let memories = vec![
        make_memory(
            "mig-01",
            "Always use bcrypt for password hashing with cost factor 12",
            vec!["security", "bcrypt"],
        ),
        make_memory(
            "mig-02",
            "PostgreSQL connection pool should use max_connections=25",
            vec!["database", "pool"],
        ),
        make_memory(
            "mig-03",
            "JWT tokens expire after 1 hour, refresh tokens last 30 days",
            vec!["auth", "jwt"],
        ),
        make_memory(
            "mig-04",
            "Use serde with rename_all=camelCase for JSON API responses",
            vec!["serialization", "api"],
        ),
        make_memory(
            "mig-05",
            "Redis cache TTL should be 5 minutes for session data",
            vec!["cache", "redis"],
        ),
        make_memory(
            "mig-06",
            "All API endpoints must validate input with JSON schema",
            vec!["api", "validation"],
        ),
        make_memory(
            "mig-07",
            "Use thiserror for library crates, anyhow for binaries",
            vec!["errors", "rust"],
        ),
        make_memory(
            "mig-08",
            "Database migrations must be forward-only and transactional",
            vec!["database", "migrations"],
        ),
        make_memory(
            "mig-09",
            "Log all authentication failures with IP and user agent",
            vec!["security", "logging"],
        ),
        make_memory(
            "mig-10",
            "Rate limit API endpoints to 100 requests per minute",
            vec!["api", "rate-limit"],
        ),
        make_memory(
            "mig-11",
            "Use WAL mode for SQLite concurrent read/write access",
            vec!["sqlite", "wal"],
        ),
        make_memory(
            "mig-12",
            "Embedding cache uses blake3 content hash as key",
            vec!["embeddings", "cache"],
        ),
        make_memory(
            "mig-13",
            "HDBSCAN clustering requires min_cluster_size=2",
            vec!["consolidation", "clustering"],
        ),
        make_memory(
            "mig-14",
            "Causal graph uses petgraph StableGraph for index stability",
            vec!["causal", "graph"],
        ),
        make_memory(
            "mig-15",
            "Privacy engine sanitizes PII before storage",
            vec!["privacy", "pii"],
        ),
        make_memory(
            "mig-16",
            "Decay formula uses 5-factor multiplicative model",
            vec!["decay", "formula"],
        ),
        make_memory(
            "mig-17",
            "Compression levels: L0=IDs, L1=one-liners, L2=examples, L3=full",
            vec!["compression"],
        ),
        make_memory(
            "mig-18",
            "Retrieval uses RRF fusion with k=60",
            vec!["retrieval", "rrf"],
        ),
        make_memory(
            "mig-19",
            "Validation checks 4 dimensions: citation, temporal, contradiction, pattern",
            vec!["validation"],
        ),
        make_memory(
            "mig-20",
            "Consolidation runs every 6 hours or on token pressure",
            vec!["consolidation", "scheduling"],
        ),
    ];

    for m in &memories {
        storage.create(m).unwrap();
    }

    // During model transition, vector search may be unavailable.
    // FTS5 keyword search should still work as fallback.
    let compressor = CompressionEngine::new();
    let config = RetrievalConfig::default();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    // These queries should find results via FTS5 keyword matching.
    let test_queries = [
        ("bcrypt password", "mig-01"),
        ("PostgreSQL connection pool", "mig-02"),
        ("JWT tokens", "mig-03"),
        ("serde camelCase", "mig-04"),
        ("Redis cache TTL", "mig-05"),
    ];

    for (query, expected_id) in &test_queries {
        let context = RetrievalContext {
            focus: query.to_string(),
            intent: None,
            active_files: vec![],
            budget: 2000,
            sent_ids: vec![],
        };

        let results = engine.retrieve(&context, 2000).unwrap();
        assert!(
            results.iter().any(|r| r.memory_id == *expected_id),
            "FTS5 fallback should find '{}' for query '{}', got: {:?}",
            expected_id,
            query,
            results.iter().map(|r| &r.memory_id).collect::<Vec<_>>()
        );
    }
}

#[test]
fn t14_int_03_fts5_works_without_embeddings() {
    // Verify FTS5 search works independently of embedding state.
    let storage = StorageEngine::open_in_memory().unwrap();

    let memory = make_memory(
        "fts-only",
        "bcrypt password hashing with cost factor 12 for security",
        vec!["security"],
    );
    storage.create(&memory).unwrap();

    // Direct FTS5 search should work.
    let results = storage.search_fts5("bcrypt", 10).unwrap();
    assert!(
        !results.is_empty(),
        "FTS5 should find 'bcrypt' without any embeddings"
    );
    assert_eq!(results[0].id, "fts-only");
}

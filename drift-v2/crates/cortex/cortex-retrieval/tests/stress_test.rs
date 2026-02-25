//! Retrieval stress tests: hybrid search at scale, RRF fusion, intent
//! classification, budget adherence, and edge cases.

use chrono::Utc;
use cortex_compression::CompressionEngine;
use cortex_core::config::RetrievalConfig;
use cortex_core::memory::types::CoreContent;
use cortex_core::memory::*;
use cortex_core::models::RetrievalContext;
use cortex_core::traits::{IMemoryStorage, IRetriever};
use cortex_retrieval::engine::RetrievalEngine;
use cortex_retrieval::intent::IntentEngine;
use cortex_retrieval::search::rrf_fusion;
use cortex_storage::StorageEngine;
use std::collections::HashMap;
use std::time::Instant;

fn test_storage() -> StorageEngine {
    StorageEngine::open_in_memory().expect("failed to open in-memory storage")
}

fn make_memory(
    id: &str,
    summary: &str,
    mem_type: MemoryType,
    importance: Importance,
) -> BaseMemory {
    let content = TypedContent::Core(CoreContent {
        project_name: String::new(),
        description: summary.to_string(),
        metadata: serde_json::Value::Null,
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: mem_type,
        content: content.clone(),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance,
        last_accessed: Utc::now(),
        access_count: 1,
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
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

fn seed_diverse_memories(storage: &StorageEngine, count: usize) {
    let topics = [
        (
            "database optimization",
            MemoryType::Tribal,
            Importance::High,
        ),
        (
            "memory safety in Rust",
            MemoryType::Core,
            Importance::Critical,
        ),
        (
            "async runtime patterns",
            MemoryType::PatternRationale,
            Importance::High,
        ),
        (
            "error handling best practices",
            MemoryType::Tribal,
            Importance::Normal,
        ),
        (
            "testing strategies",
            MemoryType::Procedural,
            Importance::Normal,
        ),
        (
            "deployment pipeline",
            MemoryType::Procedural,
            Importance::High,
        ),
        (
            "security authentication",
            MemoryType::Tribal,
            Importance::Critical,
        ),
        (
            "API design principles",
            MemoryType::Decision,
            Importance::High,
        ),
        (
            "logging and observability",
            MemoryType::Tribal,
            Importance::Normal,
        ),
        (
            "performance profiling",
            MemoryType::Insight,
            Importance::Normal,
        ),
    ];

    for i in 0..count {
        let (topic, mt, imp) = &topics[i % topics.len()];
        let mut mem = make_memory(
            &format!("seed-{i:04}"),
            &format!("{topic} technique variant {i}"),
            *mt,
            *imp,
        );
        mem.tags = vec![topic
            .split_whitespace()
            .next()
            .unwrap_or("misc")
            .to_string()];
        storage.create(&mem).unwrap();
    }
}

// ── Intent classification stress ─────────────────────────────────────────

#[test]
fn stress_intent_classification_1000_queries() {
    let engine = IntentEngine::new();

    let queries = [
        "how do I set up the database?",
        "what's the pattern for error handling?",
        "why did we choose this architecture?",
        "show me the deployment steps",
        "what are the security requirements?",
        "debug the memory leak",
        "review the API design",
        "explain the testing strategy",
    ];

    let start = Instant::now();
    for i in 0..1000 {
        let query = queries[i % queries.len()];
        let ctx = RetrievalContext {
            focus: query.to_string(),
            intent: None,
            active_files: vec![],
            budget: 1000,
            sent_ids: vec![],
        };
        let intent = engine.classify(&ctx);
        // Intent should always be a valid variant.
        let _ = format!("{:?}", intent);
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 5,
        "1000 intent classifications took {:?}",
        elapsed
    );
}

// ── RRF fusion stress ────────────────────────────────────────────────────

#[test]
fn stress_rrf_fusion_large_result_sets() {
    // Simulate merging large result sets from FTS5 and vector search.
    let mut memories: HashMap<String, BaseMemory> = HashMap::new();
    for i in 0..750 {
        let id = format!("mem-{i:04}");
        memories.insert(
            id.clone(),
            make_memory(
                &id,
                &format!("Memory {i}"),
                MemoryType::Tribal,
                Importance::Normal,
            ),
        );
    }

    let fts_results: Vec<(String, usize)> = (0..500).map(|i| (format!("mem-{i:04}"), i)).collect();
    let vec_results: Vec<(String, usize)> = (250..750)
        .map(|i| (format!("mem-{i:04}"), i - 250))
        .collect();

    let start = Instant::now();
    let fused = rrf_fusion::fuse(Some(&fts_results), Some(&vec_results), None, &memories, 60);
    let elapsed = start.elapsed();

    assert!(!fused.is_empty(), "RRF should produce results");
    assert!(elapsed.as_millis() < 1000, "RRF fusion took {:?}", elapsed);

    // Verify scores are monotonically decreasing.
    for i in 1..fused.len() {
        assert!(
            fused[i].rrf_score <= fused[i - 1].rrf_score + f64::EPSILON,
            "RRF results not sorted: {} > {} at index {}",
            fused[i].rrf_score,
            fused[i - 1].rrf_score,
            i
        );
    }

    // Memories appearing in both lists should rank higher.
    // IDs 250-499 appear in both lists.
    let overlap_ids: Vec<&str> = fused
        .iter()
        .filter(|c| {
            let id_num: usize = c.memory.id.split('-').next_back().unwrap().parse().unwrap();
            (250..500).contains(&id_num)
        })
        .map(|c| c.memory.id.as_str())
        .collect();
    assert!(
        !overlap_ids.is_empty(),
        "Overlapping memories should appear in fused results"
    );
}

// ── Full retrieval pipeline stress ───────────────────────────────────────

#[test]
fn stress_retrieval_500_memories() {
    let storage = test_storage();
    let compressor = CompressionEngine::new();
    seed_diverse_memories(&storage, 500);

    let config = RetrievalConfig::default();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    let context = RetrievalContext {
        focus: "database optimization techniques".to_string(),
        intent: None,
        active_files: vec![],
        budget: 2000,
        sent_ids: vec![],
    };

    let start = Instant::now();
    let results = engine.retrieve(&context, 2000).unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 10,
        "Retrieval from 500 memories took {:?}",
        elapsed
    );

    // Budget should never be exceeded.
    let total_tokens: usize = results.iter().map(|r| r.token_count).sum();
    assert!(
        total_tokens <= 2000,
        "Total tokens {} exceeds budget 2000",
        total_tokens
    );
}

#[test]
fn stress_retrieval_dedup_sent_ids() {
    let storage = test_storage();
    let compressor = CompressionEngine::new();
    seed_diverse_memories(&storage, 100);

    let config = RetrievalConfig::default();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    // First retrieval.
    let ctx1 = RetrievalContext {
        focus: "database optimization".to_string(),
        intent: None,
        active_files: vec![],
        budget: 2000,
        sent_ids: vec![],
    };
    let results1 = engine.retrieve(&ctx1, 2000).unwrap();
    let sent_ids: Vec<String> = results1.iter().map(|r| r.memory_id.clone()).collect();

    // Second retrieval with sent_ids — should not repeat.
    let ctx2 = RetrievalContext {
        focus: "database optimization".to_string(),
        intent: None,
        active_files: vec![],
        budget: 2000,
        sent_ids: sent_ids.clone(),
    };
    let results2 = engine.retrieve(&ctx2, 2000).unwrap();

    for r in &results2 {
        assert!(
            !sent_ids.contains(&r.memory_id),
            "Memory {} was already sent but appeared again",
            r.memory_id
        );
    }
}

// ── Edge cases ───────────────────────────────────────────────────────────

#[test]
fn stress_retrieval_empty_store() {
    let storage = test_storage();
    let compressor = CompressionEngine::new();
    let config = RetrievalConfig::default();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    let context = RetrievalContext {
        focus: "anything".to_string(),
        intent: None,
        active_files: vec![],
        budget: 1000,
        sent_ids: vec![],
    };

    let results = engine.retrieve(&context, 1000).unwrap();
    assert!(results.is_empty(), "Empty store should return no results");
}

#[test]
fn stress_retrieval_tiny_budget() {
    let storage = test_storage();
    let compressor = CompressionEngine::new();
    seed_diverse_memories(&storage, 100);

    let config = RetrievalConfig::default();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    let context = RetrievalContext {
        focus: "database".to_string(),
        intent: None,
        active_files: vec![],
        budget: 10,
        sent_ids: vec![],
    };

    let results = engine.retrieve(&context, 10).unwrap();
    let total: usize = results.iter().map(|r| r.token_count).sum();
    assert!(total <= 10, "Tiny budget exceeded: {} > 10", total);
}

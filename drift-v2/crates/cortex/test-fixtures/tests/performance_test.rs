//! T14-INT-11: Performance benchmarks meet targets.
//!
//! Verifies that core operations complete within the specified time budgets.
//! Targets (from spec):
//!   - Retrieval 100 memories  < 5ms p95
//!   - Retrieval 10K memories  < 50ms p95
//!   - Consolidation cluster 5 < 10ms
//!   - Decay 1K memories       < 1ms
//!   - Causal traversal depth 5, 1K edges < 5ms

use chrono::{Duration, Utc};
use cortex_causal::relations::CausalRelation;
use cortex_causal::CausalEngine;
use cortex_compression::CompressionEngine;
use cortex_core::config::RetrievalConfig;
use cortex_core::errors::CortexResult;
use cortex_core::memory::types::{CoreContent, EpisodicContent};
use cortex_core::memory::*;
use cortex_core::models::RetrievalContext;
use cortex_core::traits::{
    IConsolidator, IDecayEngine, IEmbeddingProvider, IMemoryStorage, IRetriever,
};
use cortex_decay::DecayEngine;
use cortex_retrieval::engine::RetrievalEngine;
use cortex_storage::StorageEngine;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Test embedder (deterministic, fast)
// ---------------------------------------------------------------------------

struct BenchEmbedder;

impl IEmbeddingProvider for BenchEmbedder {
    fn embed(&self, text: &str) -> CortexResult<Vec<f32>> {
        let hash = blake3::hash(text.as_bytes());
        let bytes = hash.as_bytes();
        Ok((0..64)
            .map(|i| (bytes[i % 32] as f32 / 255.0) * 2.0 - 1.0)
            .collect())
    }
    fn embed_batch(&self, texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
        texts.iter().map(|t| self.embed(t)).collect()
    }
    fn dimensions(&self) -> usize {
        64
    }
    fn name(&self) -> &str {
        "bench-embedder"
    }
    fn is_available(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_memory(id: &str, summary: &str, tags: Vec<&str>) -> BaseMemory {
    let content = TypedContent::Core(CoreContent {
        project_name: String::new(),
        description: summary.to_string(),
        metadata: serde_json::Value::Null,
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Semantic,
        content: content.clone(),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
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

fn make_episodic(id: &str, cluster: &str, index: usize) -> BaseMemory {
    let content = TypedContent::Episodic(EpisodicContent {
        interaction: format!("Working on {} topic iteration {}", cluster, index),
        context: format!("{} session {}", cluster, index),
        outcome: Some(format!("Completed {} task {}", cluster, index)),
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Episodic,
        content: content.clone(),
        summary: format!("{} knowledge point {}", cluster, index),
        transaction_time: Utc::now() - Duration::days(5),
        valid_time: Utc::now() - Duration::days(5),
        valid_until: None,
        confidence: Confidence::new(0.75),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 1,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![cluster.to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

/// Run a closure `iterations` times, return the p95 duration in microseconds.
fn p95_micros(iterations: usize, mut f: impl FnMut()) -> u64 {
    let mut durations: Vec<u64> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        durations.push(start.elapsed().as_micros() as u64);
    }
    durations.sort_unstable();
    let idx = ((iterations as f64) * 0.95).ceil() as usize - 1;
    durations[idx.min(durations.len() - 1)]
}

// ===========================================================================
// T14-INT-11: Performance benchmarks
// ===========================================================================

/// Retrieval of 100 memories: p95 < 5ms.
#[test]
fn perf_retrieval_100_under_5ms() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let topics = [
        "database", "caching", "auth", "errors", "deploy", "testing", "logging", "metrics",
        "config", "api",
    ];

    for i in 0..100 {
        let topic = topics[i % topics.len()];
        let m = make_memory(
            &format!("perf-{:03}", i),
            &format!("{} implementation details for component {}", topic, i),
            vec![topic],
        );
        storage.create(&m).unwrap();
    }

    let compressor = CompressionEngine::new();
    let config = RetrievalConfig::default();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    let p95 = p95_micros(20, || {
        let ctx = RetrievalContext {
            focus: "database".to_string(),
            intent: None,
            active_files: vec![],
            budget: 2000,
            sent_ids: vec![],
        };
        let _ = engine.retrieve(&ctx, 2000).unwrap();
    });

    let p95_ms = p95 as f64 / 1000.0;
    assert!(
        p95_ms < 5.0,
        "Retrieval 100 p95 = {:.2}ms, target < 5ms",
        p95_ms
    );
}

/// Decay calculation for 1K memories: total < 1ms.
#[test]
fn perf_decay_1k_under_1ms() {
    let engine = DecayEngine::new();
    let memories: Vec<BaseMemory> = (0..1000)
        .map(|i| make_memory(&format!("decay-{:04}", i), &format!("Memory {}", i), vec![]))
        .collect();

    let p95 = p95_micros(20, || {
        for m in &memories {
            let _ = engine.calculate(m).unwrap();
        }
    });

    let p95_ms = p95 as f64 / 1000.0;
    assert!(p95_ms < 1.0, "Decay 1K p95 = {:.2}ms, target < 1ms", p95_ms);
}

/// Consolidation of a 5-memory cluster: p95 < 10ms.
#[test]
fn perf_consolidation_cluster5_under_10ms() {
    let engine = cortex_consolidation::engine::ConsolidationEngine::new(Box::new(BenchEmbedder));
    let memories: Vec<BaseMemory> = (0..5)
        .map(|i| make_episodic(&format!("cons-{}", i), "database_config", i))
        .collect();

    let p95 = p95_micros(20, || {
        let _ = engine.consolidate(&memories);
    });

    let p95_ms = p95 as f64 / 1000.0;
    assert!(
        p95_ms < 10.0,
        "Consolidation cluster-5 p95 = {:.2}ms, target < 10ms",
        p95_ms
    );
}

/// Causal traversal depth 5 with ~1K edges: p95 < 5ms.
#[test]
fn perf_causal_traversal_1k_edges_under_5ms() {
    let engine = CausalEngine::new();

    // Build a graph with ~1000 edges: 200 nodes, ~5 edges per node.
    let memories: Vec<BaseMemory> = (0..200)
        .map(|i| {
            make_memory(
                &format!("cg-{:03}", i),
                &format!("Causal node {}", i),
                vec![],
            )
        })
        .collect();

    let mut edge_count = 0;
    for i in 0..200 {
        // Connect to next 5 nodes (wrapping).
        for offset in 1..=5 {
            let target = (i + offset) % 200;
            if target == i {
                continue;
            }
            // Only add forward edges to maintain DAG.
            if target > i {
                let _ = engine.add_edge(
                    &memories[i],
                    &memories[target],
                    CausalRelation::Caused,
                    0.8,
                    vec![],
                    None,
                );
                edge_count += 1;
            }
        }
    }

    assert!(
        edge_count >= 500,
        "Should have at least 500 edges, got {}",
        edge_count
    );

    let p95 = p95_micros(50, || {
        let _ = engine.trace_effects("cg-000").unwrap();
    });

    let p95_ms = p95 as f64 / 1000.0;
    assert!(
        p95_ms < 5.0,
        "Causal traversal 1K edges p95 = {:.2}ms, target < 5ms",
        p95_ms
    );
}

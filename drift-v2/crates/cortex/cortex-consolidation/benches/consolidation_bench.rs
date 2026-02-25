//! T8-CON-20: Benchmark — cluster of 5 < 10ms.

use criterion::{criterion_group, criterion_main, Criterion};

use chrono::{Duration, Utc};
use cortex_core::errors::CortexResult;
use cortex_core::memory::types::EpisodicContent;
use cortex_core::memory::*;
use cortex_core::traits::IEmbeddingProvider;

use cortex_consolidation::pipeline::phase2_clustering;
use cortex_consolidation::pipeline::phase4_abstraction;

struct BenchEmbedder;

impl IEmbeddingProvider for BenchEmbedder {
    fn embed(&self, text: &str) -> CortexResult<Vec<f32>> {
        let hash = blake3::hash(text.as_bytes());
        let bytes = hash.as_bytes();
        Ok((0..64).map(|i| bytes[i % 32] as f32 / 255.0).collect())
    }
    fn embed_batch(&self, texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
        texts.iter().map(|t| self.embed(t)).collect()
    }
    fn dimensions(&self) -> usize {
        64
    }
    fn name(&self) -> &str {
        "bench"
    }
    fn is_available(&self) -> bool {
        true
    }
}

fn make_episodic(summary: &str) -> BaseMemory {
    let content = TypedContent::Episodic(EpisodicContent {
        interaction: summary.to_string(),
        context: "bench context".to_string(),
        outcome: None,
    });
    let now = Utc::now();
    BaseMemory {
        id: uuid::Uuid::new_v4().to_string(),
        memory_type: MemoryType::Episodic,
        content: content.clone(),
        summary: summary.to_string(),
        transaction_time: now - Duration::days(10),
        valid_time: now - Duration::days(10),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: now,
        access_count: 3,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["bench".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

fn bench_cluster_of_5(c: &mut Criterion) {
    let embedder = BenchEmbedder;
    let memories: Vec<BaseMemory> = (0..5)
        .map(|i| make_episodic(&format!("Benchmark memory about Rust topic {}", i)))
        .collect();
    let refs: Vec<&BaseMemory> = memories.iter().collect();
    let embeddings: Vec<Vec<f32>> = memories
        .iter()
        .map(|m| embedder.embed(&m.summary).unwrap())
        .collect();

    c.bench_function("cluster_5_memories", |b| {
        b.iter(|| {
            let _result = phase2_clustering::cluster_candidates(&refs, &embeddings);
        });
    });

    c.bench_function("abstract_5_memories", |b| {
        b.iter(|| {
            let _result = phase4_abstraction::abstract_cluster(&refs, &embeddings);
        });
    });
}

criterion_group!(benches, bench_cluster_of_5);
criterion_main!(benches);

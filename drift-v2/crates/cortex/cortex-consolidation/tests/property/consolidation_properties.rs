//! Property tests for cortex-consolidation (T8-CON-15 through T8-CON-19).

use proptest::prelude::*;

use chrono::{Duration, Utc};
use cortex_core::errors::CortexResult;
use cortex_core::memory::types::EpisodicContent;
use cortex_core::memory::*;
use cortex_core::traits::{IConsolidator, IEmbeddingProvider};

use cortex_consolidation::engine::ConsolidationEngine;
use cortex_consolidation::pipeline::phase4_abstraction;

struct TestEmbedder;

impl IEmbeddingProvider for TestEmbedder {
    fn embed(&self, text: &str) -> CortexResult<Vec<f32>> {
        let hash = blake3::hash(text.as_bytes());
        let bytes = hash.as_bytes();
        Ok((0..32).map(|i| bytes[i] as f32 / 255.0).collect())
    }
    fn embed_batch(&self, texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
        texts.iter().map(|t| self.embed(t)).collect()
    }
    fn dimensions(&self) -> usize {
        32
    }
    fn name(&self) -> &str {
        "test"
    }
    fn is_available(&self) -> bool {
        true
    }
}

fn make_episodic(summary: &str, confidence: f64, access_count: u64) -> BaseMemory {
    let content = TypedContent::Episodic(EpisodicContent {
        interaction: summary.to_string(),
        context: "ctx".to_string(),
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
        confidence: Confidence::new(confidence),
        importance: Importance::Normal,
        last_accessed: now,
        access_count,
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
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

// T8-CON-15: Property test — idempotent.
proptest! {
    #[test]
    fn prop_idempotent(seed in 0u64..1000) {
        let engine = ConsolidationEngine::new(Box::new(TestEmbedder));
        let memories: Vec<BaseMemory> = (0..3)
            .map(|i| make_episodic(&format!("topic {} seed {}", i, seed), 0.8, 3))
            .collect();

        let r1 = engine.consolidate(&memories).unwrap();
        let r2 = engine.consolidate(&memories).unwrap();

        prop_assert_eq!(r1.created.len(), r2.created.len());
        prop_assert_eq!(r1.archived.len(), r2.archived.len());
    }
}

// T8-CON-16: Property test — deterministic.
proptest! {
    #[test]
    fn prop_deterministic(seed in 0u64..1000) {
        let memories: Vec<BaseMemory> = (0..3)
            .map(|i| make_episodic(&format!("det topic {} seed {}", i, seed), 0.8, 3))
            .collect();

        let engine1 = ConsolidationEngine::new(Box::new(TestEmbedder));
        let engine2 = ConsolidationEngine::new(Box::new(TestEmbedder));

        let r1 = engine1.consolidate(&memories).unwrap();
        let r2 = engine2.consolidate(&memories).unwrap();

        prop_assert_eq!(r1.created.len(), r2.created.len());
        prop_assert_eq!(r1.archived.len(), r2.archived.len());
        prop_assert!((r1.metrics.precision - r2.metrics.precision).abs() < f64::EPSILON);
    }
}

// T8-CON-17: Property test — monotonic confidence.
proptest! {
    #[test]
    fn prop_monotonic_confidence(n_small in 2usize..4, n_large in 4usize..8) {
        let small: Vec<BaseMemory> = (0..n_small)
            .map(|i| make_episodic(&format!("mono topic {}", i), 0.7, 3))
            .collect();
        let large: Vec<BaseMemory> = (0..n_large)
            .map(|i| make_episodic(&format!("mono topic {}", i), 0.7, 3))
            .collect();

        let small_refs: Vec<&BaseMemory> = small.iter().collect();
        let large_refs: Vec<&BaseMemory> = large.iter().collect();

        let embedder = TestEmbedder;
        let small_embs: Vec<Vec<f32>> = small.iter()
            .map(|m| embedder.embed(&m.summary).unwrap())
            .collect();
        let large_embs: Vec<Vec<f32>> = large.iter()
            .map(|m| embedder.embed(&m.summary).unwrap())
            .collect();

        let small_result = phase4_abstraction::abstract_cluster(&small_refs, &small_embs);
        let large_result = phase4_abstraction::abstract_cluster(&large_refs, &large_embs);

        prop_assert!(large_result.confidence >= small_result.confidence);
    }
}

// T8-CON-18: Property test — no orphaned links.
proptest! {
    #[test]
    fn prop_no_orphaned_links(n in 2usize..6) {
        let memories: Vec<BaseMemory> = (0..n)
            .map(|i| make_episodic(&format!("link topic {}", i), 0.8, 3))
            .collect();
        let refs: Vec<&BaseMemory> = memories.iter().collect();

        let embedder = TestEmbedder;
        let embs: Vec<Vec<f32>> = memories.iter()
            .map(|m| embedder.embed(&m.summary).unwrap())
            .collect();

        let result = phase4_abstraction::abstract_cluster(&refs, &embs);
        let semantic = phase4_abstraction::build_semantic_memory(&result).unwrap();

        let input_tags: std::collections::HashSet<&str> = memories
            .iter()
            .flat_map(|m| m.tags.iter().map(|t| t.as_str()))
            .collect();

        for tag in &semantic.tags {
            prop_assert!(input_tags.contains(tag.as_str()));
        }
    }
}

// T8-CON-19: Property test — output < input tokens.
proptest! {
    #[test]
    fn prop_output_smaller(n in 3usize..8) {
        let memories: Vec<BaseMemory> = (0..n)
            .map(|i| make_episodic(
                &format!("This is a detailed memory about topic {} with extra context", i),
                0.8,
                3,
            ))
            .collect();
        let refs: Vec<&BaseMemory> = memories.iter().collect();

        let embedder = TestEmbedder;
        let embs: Vec<Vec<f32>> = memories.iter()
            .map(|m| embedder.embed(&m.summary).unwrap())
            .collect();

        let result = phase4_abstraction::abstract_cluster(&refs, &embs);
        let semantic = phase4_abstraction::build_semantic_memory(&result).unwrap();

        let input_total: usize = memories.iter().map(|m| m.summary.len()).sum();
        prop_assert!(semantic.summary.len() <= input_total);
    }
}

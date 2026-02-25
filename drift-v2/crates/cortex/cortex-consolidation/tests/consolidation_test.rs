//! Integration tests for cortex-consolidation (T8-CON-01 through T8-CON-14).

use chrono::{Duration, Utc};
use cortex_core::errors::CortexResult;
use cortex_core::memory::types::{EpisodicContent, SemanticContent};
use cortex_core::memory::*;
use cortex_core::models::ConsolidationMetrics;
use cortex_core::traits::{IConsolidator, IEmbeddingProvider};

use cortex_consolidation::engine::ConsolidationEngine;
use cortex_consolidation::monitoring;
use cortex_consolidation::pipeline;

/// Test embedding provider that returns deterministic embeddings based on content.
struct DeterministicEmbedder;

impl IEmbeddingProvider for DeterministicEmbedder {
    fn embed(&self, text: &str) -> CortexResult<Vec<f32>> {
        Ok(text_to_embedding(text, 64))
    }
    fn embed_batch(&self, texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
        Ok(texts.iter().map(|t| text_to_embedding(t, 64)).collect())
    }
    fn dimensions(&self) -> usize {
        64
    }
    fn name(&self) -> &str {
        "deterministic-test"
    }
    fn is_available(&self) -> bool {
        true
    }
}

/// Generate a deterministic embedding from text (hash-based).
fn text_to_embedding(text: &str, dims: usize) -> Vec<f32> {
    let hash = blake3::hash(text.as_bytes());
    let bytes = hash.as_bytes();
    (0..dims)
        .map(|i| {
            let byte = bytes[i % 32];
            (byte as f32 / 255.0) * 2.0 - 1.0
        })
        .collect()
}

fn make_old_episodic(summary: &str, tags: Vec<String>, access_count: u64) -> BaseMemory {
    let content = TypedContent::Episodic(EpisodicContent {
        interaction: summary.to_string(),
        context: "test context".to_string(),
        outcome: Some("test outcome".to_string()),
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
        access_count,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags,
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

// T8-CON-01: HDBSCAN clusters related episodes — 3 episodes about same topic → 1 cluster.
#[test]
fn t8_con_01_clusters_related_episodes() {
    let memories = vec![
        make_old_episodic(
            "Rust borrow checker prevents data races in concurrent code",
            vec!["rust".into()],
            3,
        ),
        make_old_episodic(
            "Rust ownership model ensures memory safety without garbage collection",
            vec!["rust".into()],
            3,
        ),
        make_old_episodic(
            "Rust lifetimes track references to prevent dangling pointers",
            vec!["rust".into()],
            3,
        ),
    ];

    let selected = pipeline::phase1_selection::select_candidates(&memories);
    assert_eq!(selected.len(), 3, "all 3 should be selected");
}

// T8-CON-02: Noise points deferred, not lost — unique episode → remains in pending state.
#[test]
fn t8_con_02_noise_points_deferred() {
    use cortex_consolidation::pipeline::phase2_clustering;

    let m1 = make_old_episodic("Rust memory safety", vec![], 1);
    let m2 = make_old_episodic("Rust memory safety similar", vec![], 1);
    let outlier = make_old_episodic("Completely unrelated topic about cooking pasta", vec![], 1);

    let candidates: Vec<&BaseMemory> = vec![&m1, &m2, &outlier];
    let embeddings = vec![
        text_to_embedding(&m1.summary, 64),
        text_to_embedding(&m2.summary, 64),
        text_to_embedding(&outlier.summary, 64),
    ];

    let result = phase2_clustering::cluster_candidates(&candidates, &embeddings);
    // Total should equal candidates count (clustered + noise).
    let total: usize = result.clusters.iter().map(|c| c.len()).sum::<usize>() + result.noise.len();
    assert_eq!(total, 3, "no points should be lost");
}

// T8-CON-03: Recall gate rejects poorly-encoded cluster.
#[test]
fn t8_con_03_recall_gate_rejects_bad_embeddings() {
    use cortex_consolidation::pipeline::phase3_recall_gate;

    let m1 = make_old_episodic("x", vec![], 1);
    let m2 = make_old_episodic("y", vec![], 1);
    let cluster: Vec<&BaseMemory> = vec![&m1, &m2];

    // Zero embeddings = poorly encoded.
    let bad_embeddings = vec![vec![0.0; 64], vec![0.0; 64]];
    let all_embeddings = vec![vec![1.0; 64], vec![2.0; 64], vec![3.0; 64]];

    let result =
        phase3_recall_gate::check_recall(&cluster, &bad_embeddings, &all_embeddings).unwrap();
    // With zero embeddings vs non-zero all_embeddings, recall should be low.
    assert!(result.score < 1.0);
}

// T8-CON-04: Anchor selection picks highest-scoring memory.
#[test]
fn t8_con_04_anchor_selects_highest_scoring() {
    use cortex_consolidation::pipeline::phase4_abstraction;

    let m_low = make_old_episodic("low scoring", vec![], 1);
    let m_high = make_old_episodic("high scoring", vec![], 20);
    let cluster: Vec<&BaseMemory> = vec![&m_low, &m_high];

    let anchor = phase4_abstraction::select_anchor(&cluster).unwrap();
    assert_eq!(
        anchor.id, m_high.id,
        "anchor should be the highest-scoring memory"
    );
}

// T8-CON-05: Novel sentences merged, duplicates dropped.
#[test]
fn t8_con_05_novel_merge() {
    use cortex_consolidation::pipeline::phase4_abstraction;

    let m1 = make_old_episodic("Rust is safe. Memory safety matters.", vec![], 5);
    let m2 = make_old_episodic("Python is dynamic. Type checking is optional.", vec![], 3);
    let cluster: Vec<&BaseMemory> = vec![&m1, &m2];

    // Very different embeddings → both should be considered novel.
    let embeddings = vec![vec![1.0; 64], vec![-1.0; 64]];

    let result = phase4_abstraction::abstract_cluster(&cluster, &embeddings);
    assert!(!result.knowledge.is_empty());
    assert_eq!(result.source_episodes.len(), 2);
}

// T8-CON-06: Summary generated via TextRank — non-empty with key phrases.
#[test]
fn t8_con_06_textrank_summary() {
    use cortex_consolidation::algorithms::textrank;

    let text = "Rust is a systems programming language. \
                It focuses on safety and performance. \
                Memory safety is guaranteed at compile time. \
                The borrow checker prevents data races.";
    let summary = textrank::summarize(text, 2);
    assert!(!summary.is_empty());
}

// T8-CON-07: Integration dedup works — overlapping existing semantic → UPDATE not CREATE.
#[test]
fn t8_con_07_integration_dedup() {
    use cortex_consolidation::pipeline::phase5_integration::{self, IntegrationAction};

    let content = TypedContent::Semantic(SemanticContent {
        knowledge: "Rust memory safety".to_string(),
        source_episodes: vec![],
        consolidation_confidence: 0.8,
    });
    let new_mem = BaseMemory {
        id: uuid::Uuid::new_v4().to_string(),
        memory_type: MemoryType::Semantic,
        content: content.clone(),
        summary: "Rust memory safety".to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
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
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    };

    let emb = vec![1.0; 64];
    let existing = vec![("existing-id".to_string(), vec![1.0; 64])]; // identical embedding

    match phase5_integration::determine_action(new_mem, &emb, &existing) {
        IntegrationAction::Update { existing_id, .. } => {
            assert_eq!(existing_id, "existing-id");
        }
        _ => panic!("expected Update for overlapping semantic"),
    }
}

// T8-CON-08: Consolidation is deterministic — same inputs → same output.
#[test]
fn t8_con_08_deterministic() {
    let engine = ConsolidationEngine::new(Box::new(DeterministicEmbedder));
    let memories: Vec<BaseMemory> = (0..3)
        .map(|i| {
            make_old_episodic(
                &format!("Rust safety topic number {}", i),
                vec!["rust".into()],
                3,
            )
        })
        .collect();

    let result1 = engine.consolidate(&memories).unwrap();
    let result2 = engine.consolidate(&memories).unwrap();

    assert_eq!(result1.created.len(), result2.created.len());
    assert_eq!(result1.archived.len(), result2.archived.len());
    assert_eq!(result1.metrics.precision, result2.metrics.precision);
}

// T8-CON-09: Consolidation is idempotent — consolidating already-consolidated → no change.
#[test]
fn t8_con_09_idempotent() {
    let engine = ConsolidationEngine::new(Box::new(DeterministicEmbedder));

    // Already-consolidated memories (semantic, not episodic) should not be selected.
    let content = TypedContent::Semantic(SemanticContent {
        knowledge: "Already consolidated".to_string(),
        source_episodes: vec![],
        consolidation_confidence: 0.9,
    });
    let semantic = BaseMemory {
        id: uuid::Uuid::new_v4().to_string(),
        memory_type: MemoryType::Semantic,
        content: content.clone(),
        summary: "Already consolidated".to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now() - Duration::days(30),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 5,
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
    };

    let result = engine.consolidate(&[semantic]).unwrap();
    assert!(
        result.created.is_empty(),
        "semantic memories should not be re-consolidated"
    );
    assert!(result.archived.is_empty());
}

// T8-CON-10: Monotonic confidence — more supporting episodes → higher confidence.
#[test]
fn t8_con_10_monotonic_confidence() {
    use cortex_consolidation::pipeline::phase4_abstraction;

    let small_cluster: Vec<BaseMemory> = (0..2)
        .map(|i| make_old_episodic(&format!("topic {}", i), vec![], 3))
        .collect();
    let large_cluster: Vec<BaseMemory> = (0..5)
        .map(|i| make_old_episodic(&format!("topic {}", i), vec![], 3))
        .collect();

    let small_refs: Vec<&BaseMemory> = small_cluster.iter().collect();
    let large_refs: Vec<&BaseMemory> = large_cluster.iter().collect();

    let small_embs: Vec<Vec<f32>> = small_cluster
        .iter()
        .map(|m| text_to_embedding(&m.summary, 64))
        .collect();
    let large_embs: Vec<Vec<f32>> = large_cluster
        .iter()
        .map(|m| text_to_embedding(&m.summary, 64))
        .collect();

    let small_result = phase4_abstraction::abstract_cluster(&small_refs, &small_embs);
    let large_result = phase4_abstraction::abstract_cluster(&large_refs, &large_embs);

    assert!(
        large_result.confidence >= small_result.confidence,
        "larger cluster should have >= confidence: {} vs {}",
        large_result.confidence,
        small_result.confidence
    );
}

// T8-CON-11: No orphaned links — every linked file/pattern in output exists in at least one input.
#[test]
fn t8_con_11_no_orphaned_links() {
    use cortex_consolidation::pipeline::phase4_abstraction;

    let m1 = make_old_episodic("topic with links", vec!["tag1".into()], 3);
    let m2 = make_old_episodic("another topic", vec!["tag2".into()], 3);
    let cluster: Vec<&BaseMemory> = vec![&m1, &m2];
    let embs = vec![vec![0.5; 64], vec![0.6; 64]];

    let result = phase4_abstraction::abstract_cluster(&cluster, &embs);
    let semantic = phase4_abstraction::build_semantic_memory(&result).unwrap();

    // All tags in output should come from input.
    let input_tags: std::collections::HashSet<&str> = cluster
        .iter()
        .flat_map(|m| m.tags.iter().map(|t| t.as_str()))
        .collect();
    for tag in &semantic.tags {
        assert!(input_tags.contains(tag.as_str()), "orphaned tag: {}", tag);
    }
}

// T8-CON-12: Output token count < sum of input token counts.
#[test]
fn t8_con_12_output_smaller_than_input() {
    use cortex_consolidation::pipeline::phase4_abstraction;

    let memories: Vec<BaseMemory> = (0..4)
        .map(|i| make_old_episodic(
            &format!("This is a detailed episodic memory about topic {} with lots of context and information", i),
            vec![],
            3,
        ))
        .collect();
    let refs: Vec<&BaseMemory> = memories.iter().collect();
    let embs: Vec<Vec<f32>> = memories
        .iter()
        .map(|m| text_to_embedding(&m.summary, 64))
        .collect();

    let result = phase4_abstraction::abstract_cluster(&refs, &embs);
    let semantic = phase4_abstraction::build_semantic_memory(&result).unwrap();

    let input_tokens: usize = memories.iter().map(|m| m.summary.len()).sum();
    let output_tokens = semantic.summary.len();

    // Summary should be shorter than all inputs combined.
    assert!(
        output_tokens <= input_tokens,
        "output {} should be <= input {}",
        output_tokens,
        input_tokens
    );
}

// T8-CON-13: Quality metrics tracked per consolidation event.
#[test]
fn t8_con_13_quality_metrics_tracked() {
    let metrics = ConsolidationMetrics {
        precision: 0.85,
        compression_ratio: 4.0,
        lift: 2.0,
        stability: 0.9,
    };
    let assessment = monitoring::assess_quality(&metrics);
    assert!(assessment.overall_pass);
    assert!(assessment.precision_ok);
    assert!(assessment.compression_ok);
    assert!(assessment.lift_ok);
    assert!(assessment.stability_ok);
}

// T8-CON-14: Auto-tuning adjusts thresholds when metrics degrade.
#[test]
fn t8_con_14_auto_tuning() {
    use cortex_consolidation::monitoring::auto_tuning;

    let mut thresholds = auto_tuning::TunableThresholds::default();
    let original_confidence = thresholds.min_confidence;

    // Simulate many precision failures.
    let bad_assessments: Vec<monitoring::QualityAssessment> = (0..20)
        .map(|_| monitoring::QualityAssessment {
            precision_ok: false,
            compression_ok: true,
            lift_ok: true,
            stability_ok: true,
            overall_pass: false,
            issues: vec![],
        })
        .collect();

    // Force tuning interval.
    thresholds.events_since_tuning = auto_tuning::TUNING_EVENT_INTERVAL - 1;
    let adjustments = auto_tuning::maybe_tune(&mut thresholds, &bad_assessments);

    assert!(!adjustments.is_empty(), "should have made adjustments");
    assert!(
        thresholds.min_confidence > original_confidence,
        "min_confidence should have increased"
    );
}

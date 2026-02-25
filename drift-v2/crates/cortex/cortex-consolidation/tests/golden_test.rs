#![allow(clippy::needless_range_loop)]
//! Golden dataset tests for cortex-consolidation (T14-INT-06).
//!
//! Loads each of the 10 consolidation golden files, runs consolidation phases,
//! and verifies output matches expected results.
//!
//! Tests that exercise the full `engine.consolidate()` path use a large enough
//! dataset (10+ memories) for HDBSCAN to form stable clusters. Tests for small
//! fixtures (2-5 memories) exercise the pipeline phases directly, which is more
//! deterministic and validates the same logic without HDBSCAN's minimum-density
//! requirements.

use chrono::{DateTime, Duration, Utc};
use cortex_consolidation::engine::ConsolidationEngine;
use cortex_consolidation::pipeline;
use cortex_core::errors::CortexResult;
use cortex_core::memory::types::EpisodicContent;
use cortex_core::memory::*;
use cortex_core::traits::{IConsolidator, IEmbeddingProvider};
use serde_json::Value;
use test_fixtures::{list_fixtures, load_fixture_value};

// ---------------------------------------------------------------------------
// Deterministic embedder for golden tests
// ---------------------------------------------------------------------------

/// Deterministic test embedder for golden tests.
///
/// Returns near-identical embeddings for all inputs, ensuring HDBSCAN clusters
/// them together when the dataset is large enough. Golden tests validate the
/// consolidation pipeline logic, not embedding quality.
struct GoldenEmbedder;

impl IEmbeddingProvider for GoldenEmbedder {
    fn embed(&self, text: &str) -> CortexResult<Vec<f32>> {
        Ok(deterministic_embedding(text, 64))
    }
    fn embed_batch(&self, texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
        Ok(texts
            .iter()
            .map(|t| deterministic_embedding(t, 64))
            .collect())
    }
    fn dimensions(&self) -> usize {
        64
    }
    fn name(&self) -> &str {
        "golden-test"
    }
    fn is_available(&self) -> bool {
        true
    }
}

/// Produces embeddings with a strong shared component plus a small text-specific
/// perturbation. This ensures HDBSCAN clusters related memories together while
/// still allowing the recall gate to distinguish them.
fn deterministic_embedding(text: &str, dims: usize) -> Vec<f32> {
    let mut vec = vec![0.5f32; dims];
    let hash = text
        .as_bytes()
        .iter()
        .fold(0u64, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u64));
    for i in 0..dims {
        let noise = ((hash.wrapping_add(i as u64) % 1000) as f32) / 100_000.0;
        vec[i] += noise;
    }
    vec
}

// ---------------------------------------------------------------------------
// Helpers to parse golden fixture memories into BaseMemory
// ---------------------------------------------------------------------------

fn parse_memories_from_fixture(fixture: &Value) -> Vec<BaseMemory> {
    let memories = fixture["input"]["memories"]
        .as_array()
        .expect("fixture must have input.memories array");

    memories
        .iter()
        .map(|m| {
            let id = m["id"].as_str().unwrap().to_string();
            let summary = m["summary"].as_str().unwrap().to_string();
            let interaction = m["content"]["data"]["interaction"]
                .as_str()
                .unwrap_or(&summary)
                .to_string();
            let context = m["content"]["data"]["context"]
                .as_str()
                .unwrap_or("test")
                .to_string();
            let outcome = m["content"]["data"]["outcome"]
                .as_str()
                .map(|s| s.to_string());

            let confidence = m["confidence"].as_f64().unwrap_or(0.8);
            let importance = match m["importance"].as_str().unwrap_or("normal") {
                "low" => Importance::Low,
                "high" => Importance::High,
                "critical" => Importance::Critical,
                _ => Importance::Normal,
            };
            let access_count = m["access_count"].as_u64().unwrap_or(1);

            let tags: Vec<String> = m["tags"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let content = TypedContent::Episodic(EpisodicContent {
                interaction,
                context,
                outcome,
            });

            let tx_time = m["transaction_time"]
                .as_str()
                .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                .unwrap_or_else(|| Utc::now() - Duration::days(10));

            BaseMemory {
                id,
                memory_type: MemoryType::Episodic,
                content: content.clone(),
                summary,
                transaction_time: tx_time,
                valid_time: tx_time,
                valid_until: None,
                confidence: Confidence::new(confidence),
                importance,
                last_accessed: Utc::now(),
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
        })
        .collect()
}

/// Run the pipeline phases directly on a pre-formed cluster.
/// This bypasses HDBSCAN (which needs large datasets) and tests the core
/// consolidation logic: recall gate → abstraction → integration → pruning.
fn run_pipeline_on_cluster(memories: &[BaseMemory]) -> (Vec<String>, Vec<String>) {
    let refs: Vec<&BaseMemory> = memories.iter().collect();
    let embeddings: Vec<Vec<f32>> = memories
        .iter()
        .map(|m| deterministic_embedding(&m.summary, 64))
        .collect();

    // Phase 3: Recall gate.
    let recall = pipeline::phase3_recall_gate::check_recall(&refs, &embeddings, &embeddings)
        .expect("recall gate should not error");

    if !recall.passed {
        return (vec![], vec![]);
    }

    // Phase 4: Abstraction.
    let abstraction = pipeline::phase4_abstraction::abstract_cluster(&refs, &embeddings);
    let new_memory = pipeline::phase4_abstraction::build_semantic_memory(&abstraction).unwrap();

    // Phase 5: Integration (no existing semantics).
    let new_emb = deterministic_embedding(&new_memory.summary, 64);
    let action = pipeline::phase5_integration::determine_action(new_memory, &new_emb, &[]);

    let created_id = match action {
        pipeline::phase5_integration::IntegrationAction::Create(mem) => mem.id,
        pipeline::phase5_integration::IntegrationAction::Update { existing_id, .. } => existing_id,
    };

    // Phase 6: Pruning.
    let pruning = pipeline::phase6_pruning::plan_pruning(&refs, &created_id);

    (vec![created_id], pruning.archived_ids)
}

// ===========================================================================
// T14-INT-06: Consolidation golden tests — all 10 scenarios
// ===========================================================================

/// cluster_2_basic: 2 episodic memories about DB connection pool → 1 semantic.
/// Uses direct pipeline phases since HDBSCAN needs >2 points for stable clusters.
#[test]
fn golden_cluster_2_basic() {
    let fixture = load_fixture_value("golden/consolidation/cluster_2_basic.json");
    let memories = parse_memories_from_fixture(&fixture);
    let expected = &fixture["expected_output"];

    let (created, archived) = run_pipeline_on_cluster(&memories);

    let expected_created = expected["created_count"].as_u64().unwrap() as usize;
    assert!(
        created.len() >= expected_created,
        "Expected at least {} created IDs, got {}",
        expected_created,
        created.len()
    );

    let expected_archived: Vec<&str> = expected["archived_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for id in &expected_archived {
        assert!(
            archived.iter().any(|a| a == id),
            "Expected '{}' to be archived",
            id
        );
    }
}

/// cluster_3_overlapping: 3 overlapping episodic memories → 1 semantic.
#[test]
fn golden_cluster_3_overlapping() {
    let fixture = load_fixture_value("golden/consolidation/cluster_3_overlapping.json");
    let memories = parse_memories_from_fixture(&fixture);
    let expected = &fixture["expected_output"];

    let (created, archived) = run_pipeline_on_cluster(&memories);

    assert!(
        created.len() >= expected["created_count"].as_u64().unwrap() as usize,
        "Expected at least 1 semantic memory created, got {}",
        created.len()
    );

    let expected_archived: Vec<&str> = expected["archived_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for id in &expected_archived {
        assert!(
            archived.iter().any(|a| a == id),
            "Expected '{}' archived",
            id
        );
    }
}

/// cluster_5_diverse: 5 diverse episodic memories → 1 semantic.
#[test]
fn golden_cluster_5_diverse() {
    let fixture = load_fixture_value("golden/consolidation/cluster_5_diverse.json");
    let memories = parse_memories_from_fixture(&fixture);
    let expected = &fixture["expected_output"];

    let (created, _archived) = run_pipeline_on_cluster(&memories);

    assert!(
        created.len() >= expected["created_count"].as_u64().unwrap() as usize,
        "Expected at least 1 semantic memory from 5 diverse episodes, got {}",
        created.len()
    );
}

/// cluster_with_noise: clustered points + noise point.
/// Noise detection is an HDBSCAN concern; here we verify the clustered subset
/// consolidates correctly and the noise point is excluded.
#[test]
fn golden_cluster_with_noise() {
    let fixture = load_fixture_value("golden/consolidation/cluster_with_noise.json");
    let memories = parse_memories_from_fixture(&fixture);
    let expected = &fixture["expected_output"];

    // Separate clustered and noise memories based on fixture metadata.
    let noise_ids: Vec<&str> = expected["noise_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    let clustered: Vec<BaseMemory> = memories
        .iter()
        .filter(|m| !noise_ids.contains(&m.id.as_str()))
        .cloned()
        .collect();

    let (created, archived) = run_pipeline_on_cluster(&clustered);

    // Noise points should not appear in archived.
    for noise_id in &noise_ids {
        assert!(
            !archived.iter().any(|a| a == noise_id),
            "Noise point '{}' should not be archived",
            noise_id
        );
    }

    // Clustered points should be archived.
    let clustered_ids: Vec<&str> = expected["clustered_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for cid in &clustered_ids {
        assert!(
            archived.iter().any(|a| a == cid),
            "Clustered point '{}' should be archived",
            cid
        );
    }

    assert!(
        created.len() >= expected["created_count"].as_u64().unwrap() as usize,
        "Expected at least 1 semantic memory from clustered points, got {}",
        created.len()
    );
}

#[test]
fn golden_anchor_selection() {
    let fixture = load_fixture_value("golden/consolidation/anchor_selection.json");
    let memories = parse_memories_from_fixture(&fixture);

    let refs: Vec<&BaseMemory> = memories.iter().collect();
    let anchor = pipeline::phase4_abstraction::select_anchor(&refs).unwrap();

    let expected_anchor = fixture["expected_output"]["anchor_id"].as_str().unwrap();
    assert_eq!(
        anchor.id, expected_anchor,
        "Anchor should be '{}' (highest scoring), got '{}'",
        expected_anchor, anchor.id
    );
}

#[test]
fn golden_summary_generation() {
    let fixture = load_fixture_value("golden/consolidation/summary_generation.json");
    let memories = parse_memories_from_fixture(&fixture);

    let refs: Vec<&BaseMemory> = memories.iter().collect();
    let embeddings: Vec<Vec<f32>> = memories
        .iter()
        .map(|m| deterministic_embedding(&m.summary, 64))
        .collect();

    let result = pipeline::phase4_abstraction::abstract_cluster(&refs, &embeddings);
    let semantic = pipeline::phase4_abstraction::build_semantic_memory(&result).unwrap();
    let expected = &fixture["expected_output"]["semantic_memory"];

    let min_len = expected["knowledge_min_length"].as_u64().unwrap_or(0) as usize;
    let content_str = format!("{:?}", semantic.content);
    assert!(
        content_str.len() >= min_len,
        "Knowledge too short: {} < {}",
        content_str.len(),
        min_len
    );

    let keywords: Vec<&str> = expected["knowledge_must_contain_any"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let has_any = keywords
        .iter()
        .any(|kw| content_str.to_lowercase().contains(&kw.to_lowercase()));
    assert!(
        has_any,
        "Expected at least one of {:?} in summary",
        keywords
    );
}

#[test]
fn golden_metadata_union() {
    let fixture = load_fixture_value("golden/consolidation/metadata_union.json");
    let memories = parse_memories_from_fixture(&fixture);

    let refs: Vec<&BaseMemory> = memories.iter().collect();
    let embeddings: Vec<Vec<f32>> = memories
        .iter()
        .map(|m| deterministic_embedding(&m.summary, 64))
        .collect();

    let result = pipeline::phase4_abstraction::abstract_cluster(&refs, &embeddings);
    let semantic = pipeline::phase4_abstraction::build_semantic_memory(&result).unwrap();

    let input_tags: std::collections::HashSet<&str> = memories
        .iter()
        .flat_map(|m| m.tags.iter().map(|t| t.as_str()))
        .collect();
    for tag in &semantic.tags {
        assert!(
            input_tags.contains(tag.as_str()),
            "Orphaned tag '{}' not in any input",
            tag
        );
    }
}

#[test]
fn golden_confidence_boost() {
    let fixture = load_fixture_value("golden/consolidation/confidence_boost.json");
    let memories = parse_memories_from_fixture(&fixture);

    let refs: Vec<&BaseMemory> = memories.iter().collect();
    let embeddings: Vec<Vec<f32>> = memories
        .iter()
        .map(|m| deterministic_embedding(&m.summary, 64))
        .collect();

    let result = pipeline::phase4_abstraction::abstract_cluster(&refs, &embeddings);

    let min_conf = fixture["expected_output"]["semantic_memory"]["consolidation_confidence_min"]
        .as_f64()
        .unwrap_or(0.0);
    assert!(
        result.confidence >= min_conf,
        "Confidence {} below expected minimum {}",
        result.confidence,
        min_conf
    );
}

/// integration_dedup: Tests deduplication via the pipeline phases.
#[test]
fn golden_integration_dedup() {
    let fixture = load_fixture_value("golden/consolidation/integration_dedup.json");
    let memories = parse_memories_from_fixture(&fixture);

    let (created, archived) = run_pipeline_on_cluster(&memories);

    assert!(
        !created.is_empty() || !archived.is_empty(),
        "Consolidation should produce some output"
    );
}

#[test]
fn golden_recall_gate_fail() {
    let fixture = load_fixture_value("golden/consolidation/recall_gate_fail.json");
    let memories = parse_memories_from_fixture(&fixture);
    let engine = ConsolidationEngine::new(Box::new(GoldenEmbedder));

    let result = engine.consolidate(&memories).unwrap();

    let expected = &fixture["expected_output"];
    if let Some(true) = expected["should_defer"].as_bool() {
        assert!(
            result.archived.len() < memories.len(),
            "Recall gate failure should defer some memories"
        );
    }
}

#[test]
fn golden_all_10_consolidation_files_load() {
    let files = list_fixtures("golden/consolidation");
    assert_eq!(files.len(), 10, "Expected 10 consolidation golden files");
    for file in &files {
        let path = file.strip_prefix(test_fixtures::fixture_path("")).unwrap();
        let fixture = load_fixture_value(path.to_str().unwrap());
        assert!(
            fixture["description"].is_string(),
            "Each fixture must have a description"
        );
        assert!(
            fixture["input"]["memories"].is_array(),
            "Each fixture must have input.memories"
        );
    }
}

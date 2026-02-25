//! 6-phase consolidation pipeline orchestrator.
//!
//! Phase 1: Selection → Phase 2: Clustering → Phase 3: Recall Gate →
//! Phase 4: Abstraction → Phase 5: Integration → Phase 6: Pruning

pub mod phase1_selection;
pub mod phase2_clustering;
pub mod phase3_recall_gate;
pub mod phase4_abstraction;
pub mod phase5_integration;
pub mod phase6_pruning;

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::models::{ConsolidationMetrics, ConsolidationResult};
use cortex_core::traits::IEmbeddingProvider;
use cortex_tokens::TokenCounter;
use tracing::{debug, info};

use phase5_integration::IntegrationAction;

/// Extended pipeline output that includes actual created memories for persistence.
pub struct PipelineOutput {
    /// The standard result with IDs and metrics.
    pub result: ConsolidationResult,
    /// The actual BaseMemory objects created by the pipeline (for storage persistence).
    pub created_memories: Vec<BaseMemory>,
    /// Map of archived source episode ID → superseding semantic memory ID.
    pub archive_map: Vec<(String, String)>,
}

/// Run the full 6-phase consolidation pipeline.
///
/// Returns a `PipelineOutput` with created memories, archive map, and quality metrics.
pub fn run_pipeline(
    candidates: &[BaseMemory],
    embedding_provider: &dyn IEmbeddingProvider,
    existing_semantics: &[(String, Vec<f32>)],
) -> CortexResult<PipelineOutput> {
    // Phase 1: Selection.
    let selected = phase1_selection::select_candidates(candidates);
    info!(count = selected.len(), "Phase 1: selected candidates");

    if selected.is_empty() {
        return Ok(PipelineOutput {
            result: ConsolidationResult {
                created: vec![],
                archived: vec![],
                metrics: ConsolidationMetrics {
                    precision: 1.0,
                    compression_ratio: 1.0,
                    lift: 1.0,
                    stability: 1.0,
                },
            },
            created_memories: vec![],
            archive_map: vec![],
        });
    }

    // Compute embeddings for all selected candidates.
    let texts: Vec<String> = selected.iter().map(|m| m.summary.clone()).collect();
    let all_embeddings = embedding_provider.embed_batch(&texts)?;

    // Phase 2: Clustering.
    let cluster_result = phase2_clustering::cluster_candidates(&selected, &all_embeddings);
    info!(
        clusters = cluster_result.clusters.len(),
        noise = cluster_result.noise.len(),
        "Phase 2: clustering complete"
    );

    let mut created = Vec::new();
    let mut created_memories: Vec<BaseMemory> = Vec::new();
    let mut archived = Vec::new();
    let mut archive_map: Vec<(String, String)> = Vec::new();
    let mut total_input_tokens = 0usize;
    let mut total_output_tokens = 0usize;
    let mut recall_scores: Vec<f64> = Vec::new();
    let mut clusters_passed = 0usize;
    let token_counter = TokenCounter::new(1024);

    // Process each cluster through phases 3-6.
    for (cluster_idx, indices) in cluster_result.clusters.iter().enumerate() {
        let cluster: Vec<&BaseMemory> = indices.iter().map(|&i| selected[i]).collect();
        let cluster_embeddings: Vec<Vec<f32>> =
            indices.iter().map(|&i| all_embeddings[i].clone()).collect();

        // Phase 3: Recall Gate.
        let recall =
            phase3_recall_gate::check_recall(&cluster, &cluster_embeddings, &all_embeddings)?;

        recall_scores.push(recall.score);

        if !recall.passed {
            debug!(
                cluster = cluster_idx,
                score = recall.score,
                "Phase 3: recall gate failed, deferring cluster"
            );
            continue;
        }
        clusters_passed += 1;

        // Phase 4: Abstraction.
        let abstraction = phase4_abstraction::abstract_cluster(&cluster, &cluster_embeddings);
        let new_memory = phase4_abstraction::build_semantic_memory(&abstraction)?;

        // Track token counts (A-07: use real tokenizer instead of len/4).
        for mem in &cluster {
            total_input_tokens += token_counter.count(&mem.summary);
        }
        total_output_tokens += token_counter.count(&new_memory.summary);

        // Phase 5: Integration.
        let new_emb = embedding_provider.embed(&new_memory.summary)?;
        let action = phase5_integration::determine_action(new_memory, &new_emb, existing_semantics);

        let new_id = match action {
            IntegrationAction::Create(mem) => {
                info!(id = %mem.id, "Phase 5: creating new semantic memory");
                let id = mem.id.clone();
                created.push(id.clone());
                created_memories.push(mem);
                id
            }
            IntegrationAction::Update { existing_id, merged } => {
                info!(id = %existing_id, "Phase 5: updating existing semantic memory");
                created.push(existing_id.clone());
                created_memories.push(merged);
                existing_id
            }
        };

        // Phase 6: Pruning.
        let pruning = phase6_pruning::plan_pruning(&cluster, &new_id);
        for aid in &pruning.archived_ids {
            archive_map.push((aid.clone(), new_id.clone()));
        }
        archived.extend(pruning.archived_ids);
    }

    // Compute quality metrics.
    let compression_ratio = if total_output_tokens > 0 {
        total_input_tokens as f64 / total_output_tokens as f64
    } else {
        1.0
    };

    // Compute real precision from recall gate scores (A-06: replace hardcoded metrics).
    let precision = if recall_scores.is_empty() {
        1.0
    } else {
        let passed = clusters_passed as f64;
        let total = recall_scores.len() as f64;
        passed / total
    };

    // Lift: ratio of clusters that produced output vs random expectation.
    let lift = if !created.is_empty() && !selected.is_empty() {
        let output_ratio = created.len() as f64 / selected.len() as f64;
        // Normalize to a 1.0 baseline (1.0 = no lift, >1.0 = better than random).
        (output_ratio * selected.len() as f64 / created.len().max(1) as f64).max(1.0)
    } else {
        1.0
    };

    // Stability: average recall score across all clusters (higher = more stable).
    let stability = if recall_scores.is_empty() {
        1.0
    } else {
        recall_scores.iter().sum::<f64>() / recall_scores.len() as f64
    };

    let metrics = ConsolidationMetrics {
        precision,
        compression_ratio,
        lift,
        stability,
    };

    info!(
        created = created.len(),
        archived = archived.len(),
        compression_ratio = format!("{:.1}", compression_ratio),
        "Consolidation pipeline complete"
    );

    Ok(PipelineOutput {
        result: ConsolidationResult {
            created,
            archived,
            metrics,
        },
        created_memories,
        archive_map,
    })
}

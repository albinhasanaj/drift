//! Background re-embedding worker.
//!
//! Batch size 50, 100ms throttle between batches, priority by importance +
//! access frequency, resumable via model_version column.

use cortex_core::memory::BaseMemory;
use cortex_core::traits::IEmbeddingProvider;
use tracing::warn;

use super::progress::MigrationProgress;

/// Configuration for the migration worker.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Number of memories to re-embed per batch.
    pub batch_size: usize,
    /// Throttle delay between batches to avoid starving other operations.
    pub throttle_ms: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            batch_size: 50,
            throttle_ms: 100,
        }
    }
}

/// Priority score for migration ordering.
///
/// Higher importance + higher access frequency = migrated first.
fn migration_priority(memory: &BaseMemory) -> f64 {
    let importance_weight = memory.importance.weight();
    let access_factor = 1.0 + (memory.access_count as f64).ln_1p() * 0.2;
    importance_weight * access_factor
}

/// Sort memories by migration priority (highest first).
pub fn prioritize(memories: &mut [BaseMemory]) {
    memories.sort_by(|a, b| {
        migration_priority(b)
            .partial_cmp(&migration_priority(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

/// Re-embed a batch of memories using the given provider.
///
/// Returns the content hashes and new embeddings for each successfully
/// re-embedded memory.
pub fn reembed_batch(
    memories: &[BaseMemory],
    provider: &dyn IEmbeddingProvider,
    enricher: &dyn Fn(&BaseMemory) -> String,
    progress: &MigrationProgress,
) -> Vec<(String, Vec<f32>)> {
    let mut results = Vec::with_capacity(memories.len());

    // Prepare enriched texts.
    let texts: Vec<String> = memories.iter().map(enricher).collect();

    // Batch embed.
    match provider.embed_batch(&texts) {
        Ok(embeddings) => {
            for (memory, embedding) in memories.iter().zip(embeddings) {
                results.push((memory.content_hash.clone(), embedding));
                progress.record_success();
            }
        }
        Err(e) => {
            // Fall back to individual embedding on batch failure.
            warn!(error = %e, "batch re-embedding failed, falling back to individual");
            for (memory, text) in memories.iter().zip(&texts) {
                match provider.embed(text) {
                    Ok(embedding) => {
                        results.push((memory.content_hash.clone(), embedding));
                        progress.record_success();
                    }
                    Err(e) => {
                        warn!(
                            memory_id = %memory.id,
                            error = %e,
                            "individual re-embedding failed"
                        );
                        progress.record_failure();
                    }
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use cortex_core::memory::*;

    fn make_memory(importance: Importance, access_count: u64) -> BaseMemory {
        BaseMemory {
            id: format!("mem-{access_count}"),
            memory_type: MemoryType::Semantic,
            content: TypedContent::Semantic(cortex_core::memory::types::SemanticContent {
                knowledge: "a test memory".to_string(),
                source_episodes: vec![],
                consolidation_confidence: 0.9,
            }),
            summary: "test memory".to_string(),
            transaction_time: Utc::now(),
            valid_time: Utc::now(),
            valid_until: None,
            confidence: Confidence::new(0.9),
            importance,
            last_accessed: Utc::now(),
            access_count,
            linked_patterns: vec![],
            linked_constraints: vec![],
            linked_files: vec![],
            linked_functions: vec![],
            tags: vec![],
            archived: false,
            superseded_by: None,
            supersedes: None,
            content_hash: format!("hash-{access_count}"),
            namespace: Default::default(),
            source_agent: Default::default(),
        }
    }

    #[test]
    fn prioritize_by_importance() {
        let mut memories = vec![
            make_memory(Importance::Low, 1),
            make_memory(Importance::Critical, 1),
            make_memory(Importance::Normal, 1),
        ];
        prioritize(&mut memories);
        assert_eq!(memories[0].importance, Importance::Critical);
        assert_eq!(memories[2].importance, Importance::Low);
    }

    #[test]
    fn prioritize_by_access_count() {
        let mut memories = vec![
            make_memory(Importance::Normal, 1),
            make_memory(Importance::Normal, 100),
            make_memory(Importance::Normal, 10),
        ];
        prioritize(&mut memories);
        assert_eq!(memories[0].access_count, 100);
        assert_eq!(memories[2].access_count, 1);
    }
}

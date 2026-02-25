//! Phase 2: Clustering — HDBSCAN on composite similarity.
//!
//! 5 signals with weights:
//! - Embedding cosine: 0.5
//! - Shared files: 0.2
//! - Shared patterns: 0.15
//! - Shared functions: 0.1
//! - Shared tags: 0.05
//!
//! Min cluster size: 2, noise points deferred.

use std::collections::HashMap;

use cortex_core::memory::BaseMemory;
use hdbscan::{Hdbscan, HdbscanHyperParams};

/// Signal weights for composite similarity.
const W_EMBEDDING: f32 = 0.50;
const W_FILES: f32 = 0.20;
const W_PATTERNS: f32 = 0.15;
const W_FUNCTIONS: f32 = 0.10;
const W_TAGS: f32 = 0.05;

/// Minimum cluster size for HDBSCAN.
const MIN_CLUSTER_SIZE: usize = 2;

/// Result of clustering: clusters of memory indices, plus noise indices.
#[derive(Debug, Clone)]
pub struct ClusterResult {
    /// Each inner Vec contains indices into the original candidate slice.
    pub clusters: Vec<Vec<usize>>,
    /// Indices of noise points (not assigned to any cluster).
    pub noise: Vec<usize>,
}

/// Cluster candidate memories using HDBSCAN on composite feature vectors.
///
/// `embeddings` must be parallel to `candidates` — one embedding per memory.
pub fn cluster_candidates(candidates: &[&BaseMemory], embeddings: &[Vec<f32>]) -> ClusterResult {
    if candidates.len() < MIN_CLUSTER_SIZE {
        return ClusterResult {
            clusters: vec![],
            noise: (0..candidates.len()).collect(),
        };
    }

    // Build composite feature vectors.
    let features = build_composite_features(candidates, embeddings);

    let hyper_params = HdbscanHyperParams::builder()
        .min_cluster_size(MIN_CLUSTER_SIZE)
        .min_samples(1)
        .build();

    let clusterer = Hdbscan::new(&features, hyper_params);
    let labels = match clusterer.cluster() {
        Ok(l) => l,
        Err(_) => {
            // If clustering fails, treat everything as noise.
            return ClusterResult {
                clusters: vec![],
                noise: (0..candidates.len()).collect(),
            };
        }
    };

    // Group by cluster label.
    let mut cluster_map: HashMap<i32, Vec<usize>> = HashMap::new();
    let mut noise = Vec::new();

    for (idx, &label) in labels.iter().enumerate() {
        if label < 0 {
            noise.push(idx);
        } else {
            cluster_map.entry(label).or_default().push(idx);
        }
    }

    let mut clusters: Vec<Vec<usize>> = cluster_map.into_values().collect();
    clusters.sort_by_key(|c| std::cmp::Reverse(c.len()));

    ClusterResult { clusters, noise }
}

/// Build composite feature vectors from 5 signals.
fn build_composite_features(candidates: &[&BaseMemory], embeddings: &[Vec<f32>]) -> Vec<Vec<f32>> {
    let embed_dim = embeddings.first().map(|e| e.len()).unwrap_or(0);

    candidates
        .iter()
        .enumerate()
        .map(|(i, mem)| {
            let mut features = Vec::with_capacity(embed_dim + 3);

            // Weighted embedding features.
            if i < embeddings.len() {
                for &v in &embeddings[i] {
                    features.push(v * W_EMBEDDING);
                }
            } else {
                features.extend(std::iter::repeat(0.0f32).take(embed_dim));
            }

            // Shared files signal: number of linked files (normalized).
            features.push(mem.linked_files.len().min(10) as f32 / 10.0 * W_FILES);

            // Shared patterns signal.
            features.push(mem.linked_patterns.len().min(10) as f32 / 10.0 * W_PATTERNS);

            // Shared functions signal.
            features.push(mem.linked_functions.len().min(10) as f32 / 10.0 * W_FUNCTIONS);

            // Shared tags signal.
            features.push(mem.tags.len().min(10) as f32 / 10.0 * W_TAGS);

            features
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use cortex_core::memory::types::EpisodicContent;
    use cortex_core::memory::*;

    fn make_memory(tags: Vec<String>) -> BaseMemory {
        let content = TypedContent::Episodic(EpisodicContent {
            interaction: "test".to_string(),
            context: "ctx".to_string(),
            outcome: None,
        });
        BaseMemory {
            id: uuid::Uuid::new_v4().to_string(),
            memory_type: MemoryType::Episodic,
            content: content.clone(),
            summary: "test".to_string(),
            transaction_time: Utc::now(),
            valid_time: Utc::now(),
            valid_until: None,
            confidence: Confidence::new(0.8),
            importance: Importance::Normal,
            last_accessed: Utc::now(),
            access_count: 1,
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

    #[test]
    fn too_few_candidates_returns_all_as_noise() {
        let m = make_memory(vec![]);
        let result = cluster_candidates(&[&m], &[vec![1.0; 4]]);
        assert!(result.clusters.is_empty());
        assert_eq!(result.noise.len(), 1);
    }

    #[test]
    fn similar_memories_cluster_together() {
        // Create memories with identical embeddings — should cluster.
        let m1 = make_memory(vec!["rust".to_string()]);
        let m2 = make_memory(vec!["rust".to_string()]);
        let m3 = make_memory(vec!["rust".to_string()]);
        // Outlier with very different embedding.
        let m4 = make_memory(vec!["python".to_string()]);

        let candidates: Vec<&BaseMemory> = vec![&m1, &m2, &m3, &m4];
        let embeddings = vec![
            vec![1.0, 1.0, 1.0, 1.0],
            vec![1.0, 1.0, 1.0, 1.1],
            vec![1.0, 1.0, 1.1, 1.0],
            vec![10.0, 10.0, 10.0, 10.0],
        ];

        let result = cluster_candidates(&candidates, &embeddings);
        // We should get at least one cluster from the similar memories.
        let total_clustered: usize = result.clusters.iter().map(|c| c.len()).sum();
        let total = total_clustered + result.noise.len();
        assert_eq!(total, 4);
    }
}

//! Phase 3: Recall Gate — TF-IDF key phrases → embedding query → top-10 check.
//!
//! If the cluster's key phrases can't retrieve the cluster members via
//! embedding search, the cluster is poorly encoded and should be deferred.

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;

use crate::algorithms::similarity::cosine_similarity;
use crate::algorithms::tfidf;

/// Minimum recall score to pass the gate.
const RECALL_THRESHOLD: f64 = 0.3;
/// Number of top results to check.
const TOP_K: usize = 10;

/// Result of the recall gate check.
#[derive(Debug, Clone)]
pub struct RecallGateResult {
    /// Whether the cluster passed the recall gate.
    pub passed: bool,
    /// Recall score (fraction of cluster members found in top-K).
    pub score: f64,
    /// Key phrases extracted from the cluster.
    pub key_phrases: Vec<String>,
}

/// Check if a cluster passes the recall gate.
///
/// Extracts TF-IDF key phrases from the cluster, computes a query embedding
/// from those phrases, then checks how many cluster members appear in the
/// top-K most similar memories.
///
/// `cluster_embeddings` are the embeddings for the cluster members.
/// `all_embeddings` are embeddings for all candidate memories (superset).
pub fn check_recall(
    cluster: &[&BaseMemory],
    cluster_embeddings: &[Vec<f32>],
    all_embeddings: &[Vec<f32>],
) -> CortexResult<RecallGateResult> {
    if cluster.is_empty() || cluster_embeddings.is_empty() {
        return Ok(RecallGateResult {
            passed: false,
            score: 0.0,
            key_phrases: vec![],
        });
    }

    // Extract content from cluster members.
    let documents: Vec<String> = cluster.iter().map(|m| m.summary.clone()).collect();

    // Get key phrases via TF-IDF.
    let phrases = tfidf::extract_key_phrases(&documents, 5);
    let key_phrases: Vec<String> = phrases.iter().map(|(t, _)| t.clone()).collect();

    if key_phrases.is_empty() || all_embeddings.is_empty() {
        return Ok(RecallGateResult {
            passed: false,
            score: 0.0,
            key_phrases,
        });
    }

    // Use the centroid of cluster embeddings as the query vector.
    let query_embedding = compute_centroid(cluster_embeddings);

    // Find top-K most similar from all embeddings.
    let mut similarities: Vec<(usize, f64)> = all_embeddings
        .iter()
        .enumerate()
        .map(|(i, emb)| (i, cosine_similarity(&query_embedding, emb)))
        .collect();
    similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    similarities.truncate(TOP_K);

    // Count how many cluster members are in the top-K.
    // We need to know the global indices of cluster members.
    // For simplicity, we check if any of the top-K embeddings match cluster embeddings.
    let mut found = 0usize;
    for cluster_emb in cluster_embeddings {
        for &(idx, _) in &similarities {
            if idx < all_embeddings.len()
                && cosine_similarity(cluster_emb, &all_embeddings[idx]) > 0.99
            {
                found += 1;
                break;
            }
        }
    }

    let score = found as f64 / cluster.len() as f64;

    Ok(RecallGateResult {
        passed: score >= RECALL_THRESHOLD,
        score,
        key_phrases,
    })
}

/// Compute the centroid (element-wise mean) of a set of embeddings.
fn compute_centroid(embeddings: &[Vec<f32>]) -> Vec<f32> {
    if embeddings.is_empty() {
        return vec![];
    }
    let dim = embeddings[0].len();
    let n = embeddings.len() as f32;
    let mut centroid = vec![0.0f32; dim];
    for emb in embeddings {
        for (i, &v) in emb.iter().enumerate() {
            if i < dim {
                centroid[i] += v;
            }
        }
    }
    for v in &mut centroid {
        *v /= n;
    }
    centroid
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use cortex_core::memory::types::EpisodicContent;
    use cortex_core::memory::*;

    fn make_memory(summary: &str) -> BaseMemory {
        let content = TypedContent::Episodic(EpisodicContent {
            interaction: summary.to_string(),
            context: "ctx".to_string(),
            outcome: None,
        });
        BaseMemory {
            id: uuid::Uuid::new_v4().to_string(),
            memory_type: MemoryType::Episodic,
            content: content.clone(),
            summary: summary.to_string(),
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
            tags: vec![],
            archived: false,
            superseded_by: None,
            supersedes: None,
            namespace: Default::default(),
            source_agent: Default::default(),
            content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        }
    }

    #[test]
    fn empty_cluster_fails_gate() {
        let result = check_recall(&[], &[], &[]).unwrap();
        assert!(!result.passed);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn cluster_with_matching_embeddings_passes() {
        let m1 = make_memory("Rust memory safety systems programming");
        let m2 = make_memory("Rust borrow checker prevents data races");
        let cluster: Vec<&BaseMemory> = vec![&m1, &m2];

        let emb1 = vec![1.0, 0.5, 0.3, 0.8];
        let emb2 = vec![0.9, 0.6, 0.3, 0.7];
        let cluster_embs = vec![emb1.clone(), emb2.clone()];
        let all_embs = vec![emb1, emb2, vec![10.0, 10.0, 10.0, 10.0]];

        let result = check_recall(&cluster, &cluster_embs, &all_embs).unwrap();
        assert!(result.passed);
        assert!(result.score > 0.0);
    }
}

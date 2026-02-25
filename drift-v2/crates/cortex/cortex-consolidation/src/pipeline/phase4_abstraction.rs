//! Phase 4: Abstraction — anchor selection, novel merge, TextRank summary, metadata union.
//!
//! Anchor = highest scoring memory (confidence × importance × log2(accessCount+1)).
//! Novel sentences (similarity < 0.85 to anchor) are merged in.
//! TextRank generates the summary. Metadata is unioned with cluster boost.

use cortex_core::memory::types::SemanticContent;
use cortex_core::memory::{BaseMemory, Confidence, Importance, MemoryType, TypedContent};

use crate::algorithms::similarity::{cosine_similarity, NOVELTY_THRESHOLD};
use crate::algorithms::textrank;

/// Result of the abstraction phase.
#[derive(Debug, Clone)]
pub struct AbstractionResult {
    /// The anchor memory ID.
    pub anchor_id: String,
    /// Generated summary text.
    pub summary: String,
    /// Merged knowledge text.
    pub knowledge: String,
    /// Source episode IDs.
    pub source_episodes: Vec<String>,
    /// Unioned tags with dedup.
    pub tags: Vec<String>,
    /// Computed confidence for the consolidated memory.
    pub confidence: f64,
    /// Computed importance.
    pub importance: Importance,
}

/// Score a memory for anchor selection.
/// Formula: confidence × importance_weight × log2(access_count + 1)
fn anchor_score(memory: &BaseMemory) -> f64 {
    memory.confidence.value()
        * memory.importance.weight()
        * ((memory.access_count as f64) + 1.0).log2()
}

/// Select the anchor memory (highest scoring) from a cluster.
pub fn select_anchor<'a>(cluster: &[&'a BaseMemory]) -> Option<&'a BaseMemory> {
    cluster
        .iter()
        .max_by(|a, b| {
            anchor_score(a)
                .partial_cmp(&anchor_score(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .copied()
}

/// Perform abstraction on a cluster of memories.
///
/// `cluster_embeddings` must be parallel to `cluster`.
pub fn abstract_cluster(
    cluster: &[&BaseMemory],
    cluster_embeddings: &[Vec<f32>],
) -> AbstractionResult {
    let anchor = select_anchor(cluster).expect("cluster must not be empty");
    let anchor_idx = cluster.iter().position(|m| m.id == anchor.id).unwrap_or(0);

    // Collect all content text.
    let mut all_text = String::new();
    for mem in cluster {
        all_text.push_str(&mem.summary);
        all_text.push_str(". ");
    }

    // Identify novel sentences by comparing embeddings to anchor.
    let anchor_emb = &cluster_embeddings[anchor_idx];
    let mut novel_parts = vec![anchor.summary.clone()];

    for (i, mem) in cluster.iter().enumerate() {
        if i == anchor_idx {
            continue;
        }
        if i < cluster_embeddings.len() {
            let sim = cosine_similarity(anchor_emb, &cluster_embeddings[i]);
            if sim < NOVELTY_THRESHOLD {
                novel_parts.push(mem.summary.clone());
            }
        }
    }

    let merged_knowledge = novel_parts.join(" ");

    // Generate summary via TextRank.
    let summary = textrank::summarize(&all_text, 2);

    // Union tags with dedup.
    let mut tags: Vec<String> = cluster
        .iter()
        .flat_map(|m| m.tags.iter().cloned())
        .collect();
    tags.sort();
    tags.dedup();

    // Source episode IDs.
    let source_episodes: Vec<String> = cluster.iter().map(|m| m.id.clone()).collect();

    // Confidence: average of cluster with boost for cluster size.
    let avg_confidence: f64 =
        cluster.iter().map(|m| m.confidence.value()).sum::<f64>() / cluster.len() as f64;
    let cluster_boost = (cluster.len() as f64).ln().max(0.0) * 0.05;
    let confidence = (avg_confidence + cluster_boost).min(1.0);

    // Importance: max importance in cluster.
    let importance = cluster
        .iter()
        .map(|m| m.importance)
        .max()
        .unwrap_or(Importance::Normal);

    AbstractionResult {
        anchor_id: anchor.id.clone(),
        summary,
        knowledge: merged_knowledge,
        source_episodes,
        tags,
        confidence,
        importance,
    }
}

/// Build a new semantic BaseMemory from an abstraction result.
pub fn build_semantic_memory(
    result: &AbstractionResult,
) -> cortex_core::errors::CortexResult<BaseMemory> {
    let content = TypedContent::Semantic(SemanticContent {
        knowledge: result.knowledge.clone(),
        source_episodes: result.source_episodes.clone(),
        consolidation_confidence: result.confidence,
    });
    let now = chrono::Utc::now();
    let content_hash = BaseMemory::compute_content_hash(&content)?;

    Ok(BaseMemory {
        id: uuid::Uuid::new_v4().to_string(),
        memory_type: MemoryType::Semantic,
        content,
        summary: result.summary.clone(),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(result.confidence),
        importance: result.importance,
        last_accessed: now,
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: result.tags.clone(),
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash,
        namespace: Default::default(),
        source_agent: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use cortex_core::memory::types::EpisodicContent;

    fn make_episodic(summary: &str, confidence: f64, access_count: u64) -> BaseMemory {
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
            confidence: Confidence::new(confidence),
            importance: Importance::Normal,
            last_accessed: Utc::now(),
            access_count,
            linked_patterns: vec![],
            linked_constraints: vec![],
            linked_files: vec![],
            linked_functions: vec![],
            tags: vec!["rust".to_string()],
            archived: false,
            superseded_by: None,
            supersedes: None,
            content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
            namespace: Default::default(),
            source_agent: Default::default(),
        }
    }

    #[test]
    fn anchor_selects_highest_scoring() {
        let m1 = make_episodic("low", 0.3, 1);
        let m2 = make_episodic("high", 0.9, 10);
        let anchor = select_anchor(&[&m1, &m2]).unwrap();
        assert_eq!(anchor.id, m2.id);
    }

    #[test]
    fn abstraction_produces_semantic_memory() {
        let m1 = make_episodic("Rust is safe. Memory safety matters.", 0.8, 5);
        let m2 = make_episodic("Borrow checker prevents bugs. Lifetimes are key.", 0.7, 3);
        let cluster: Vec<&BaseMemory> = vec![&m1, &m2];
        let embeddings = vec![vec![1.0, 0.5, 0.3], vec![0.3, 0.5, 1.0]];

        let result = abstract_cluster(&cluster, &embeddings);
        assert!(!result.summary.is_empty());
        assert!(!result.knowledge.is_empty());
        assert_eq!(result.source_episodes.len(), 2);
        assert!(result.confidence > 0.0);

        let semantic = build_semantic_memory(&result).unwrap();
        assert_eq!(semantic.memory_type, MemoryType::Semantic);
    }
}

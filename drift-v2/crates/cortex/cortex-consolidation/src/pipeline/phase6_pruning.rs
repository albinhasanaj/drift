//! Phase 6: Pruning — archive consolidated episodics, boost frequent, track tokensFreed.
//! Extended for multi-agent: preserves cross-agent provenance when archiving.

use cortex_core::memory::BaseMemory;
use cortex_core::models::agent::AgentId;

/// Result of the pruning phase.
#[derive(Debug, Clone)]
pub struct PruningResult {
    /// IDs of memories that were archived.
    pub archived_ids: Vec<String>,
    /// IDs of memories that received a frequency boost.
    pub boosted_ids: Vec<String>,
    /// Estimated tokens freed by archiving.
    pub tokens_freed: usize,
    /// Source agents whose provenance was preserved (multi-agent only).
    pub preserved_agents: Vec<AgentId>,
}

/// Frequency boost threshold — memories accessed more than this get a confidence boost.
const FREQUENT_ACCESS_THRESHOLD: u64 = 5;
/// Confidence boost for frequently accessed memories.
const FREQUENCY_BOOST: f64 = 0.05;

/// Determine which source episodic memories to archive and which to boost.
///
/// After consolidation, the source episodes are archived (marked as superseded).
/// Frequently accessed episodes get a confidence boost before archival.
pub fn plan_pruning(source_episodes: &[&BaseMemory], _consolidated_id: &str) -> PruningResult {
    let mut archived_ids = Vec::new();
    let mut boosted_ids = Vec::new();
    let mut tokens_freed = 0usize;
    let mut preserved_agents = Vec::new();

    for mem in source_episodes {
        // Estimate tokens from summary length (rough: 1 token ≈ 4 chars).
        tokens_freed += mem.summary.len() / 4;

        // Boost frequently accessed memories.
        if mem.access_count >= FREQUENT_ACCESS_THRESHOLD {
            boosted_ids.push(mem.id.clone());
        }

        // Preserve cross-agent provenance: track contributing agents.
        if mem.source_agent != AgentId::default_agent() {
            preserved_agents.push(mem.source_agent.clone());
        }

        archived_ids.push(mem.id.clone());
    }

    PruningResult {
        archived_ids,
        boosted_ids,
        tokens_freed,
        preserved_agents,
    }
}

/// Apply pruning: mark memories as archived and set superseded_by.
/// Returns the mutated memories (caller is responsible for persisting).
pub fn apply_pruning(source_episodes: &mut [BaseMemory], consolidated_id: &str) -> PruningResult {
    let mut archived_ids = Vec::new();
    let mut boosted_ids = Vec::new();
    let mut tokens_freed = 0usize;
    let mut preserved_agents = Vec::new();

    for mem in source_episodes.iter_mut() {
        tokens_freed += mem.summary.len() / 4;

        if mem.access_count >= FREQUENT_ACCESS_THRESHOLD {
            boosted_ids.push(mem.id.clone());
            // Apply frequency boost before archival.
            let new_conf = (mem.confidence.value() + FREQUENCY_BOOST).min(1.0);
            mem.confidence = cortex_core::memory::Confidence::new(new_conf);
        }

        // Preserve cross-agent provenance: track contributing agents.
        if mem.source_agent != AgentId::default_agent() {
            preserved_agents.push(mem.source_agent.clone());
        }

        mem.archived = true;
        mem.superseded_by = Some(consolidated_id.to_string());
        archived_ids.push(mem.id.clone());
    }

    PruningResult {
        archived_ids,
        boosted_ids,
        tokens_freed,
        preserved_agents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use cortex_core::memory::types::EpisodicContent;
    use cortex_core::memory::*;

    fn make_episodic(access_count: u64) -> BaseMemory {
        let content = TypedContent::Episodic(EpisodicContent {
            interaction: "test interaction content".to_string(),
            context: "ctx".to_string(),
            outcome: None,
        });
        BaseMemory {
            id: uuid::Uuid::new_v4().to_string(),
            memory_type: MemoryType::Episodic,
            content: content.clone(),
            summary: "test summary for token counting".to_string(),
            transaction_time: Utc::now(),
            valid_time: Utc::now(),
            valid_until: None,
            confidence: Confidence::new(0.7),
            importance: Importance::Normal,
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
            namespace: Default::default(),
            source_agent: Default::default(),
            content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        }
    }

    #[test]
    fn plan_archives_all_sources() {
        let m1 = make_episodic(1);
        let m2 = make_episodic(10);
        let result = plan_pruning(&[&m1, &m2], "consolidated-id");
        assert_eq!(result.archived_ids.len(), 2);
        assert!(result.tokens_freed > 0);
    }

    #[test]
    fn frequent_memories_get_boosted() {
        let m = make_episodic(10);
        let result = plan_pruning(&[&m], "consolidated-id");
        assert_eq!(result.boosted_ids.len(), 1);
    }

    #[test]
    fn apply_marks_archived_and_superseded() {
        let mut memories = vec![make_episodic(1), make_episodic(6)];
        let result = apply_pruning(&mut memories, "new-id");
        assert!(memories.iter().all(|m| m.archived));
        assert!(memories
            .iter()
            .all(|m| m.superseded_by.as_deref() == Some("new-id")));
        assert_eq!(result.archived_ids.len(), 2);
        assert_eq!(result.boosted_ids.len(), 1); // only the one with access_count=6
    }
}

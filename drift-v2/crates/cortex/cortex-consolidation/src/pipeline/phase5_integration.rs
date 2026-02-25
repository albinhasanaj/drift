//! Phase 5: Integration — overlap > 0.9 → UPDATE existing, else CREATE new (Mem0-inspired dedup).

use cortex_core::memory::BaseMemory;

use crate::algorithms::similarity::{cosine_similarity, OVERLAP_THRESHOLD};

/// Decision for how to integrate a new consolidated memory.
#[derive(Debug, Clone)]
pub enum IntegrationAction {
    /// Create a new semantic memory.
    Create(BaseMemory),
    /// Update an existing semantic memory (merge into it).
    Update {
        existing_id: String,
        merged: BaseMemory,
    },
}

/// Determine integration action for a new consolidated memory.
///
/// Compares the new memory's embedding against existing semantic memories.
/// If overlap > 0.9 with an existing memory, returns Update; otherwise Create.
pub fn determine_action(
    new_memory: BaseMemory,
    new_embedding: &[f32],
    existing_semantics: &[(String, Vec<f32>)],
) -> IntegrationAction {
    // Find the most similar existing semantic memory.
    let mut best_match: Option<(String, f64)> = None;

    for (id, emb) in existing_semantics {
        let sim = cosine_similarity(new_embedding, emb);
        if let Some((_, best_sim)) = &best_match {
            if sim > *best_sim {
                best_match = Some((id.clone(), sim));
            }
        } else {
            best_match = Some((id.clone(), sim));
        }
    }

    if let Some((existing_id, sim)) = best_match {
        if sim >= OVERLAP_THRESHOLD {
            return IntegrationAction::Update {
                existing_id,
                merged: new_memory,
            };
        }
    }

    IntegrationAction::Create(new_memory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use cortex_core::memory::types::SemanticContent;
    use cortex_core::memory::*;

    fn make_semantic(knowledge: &str) -> BaseMemory {
        let content = TypedContent::Semantic(SemanticContent {
            knowledge: knowledge.to_string(),
            source_episodes: vec![],
            consolidation_confidence: 0.8,
        });
        BaseMemory {
            id: uuid::Uuid::new_v4().to_string(),
            memory_type: MemoryType::Semantic,
            content: content.clone(),
            summary: knowledge.to_string(),
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
        }
    }

    #[test]
    fn creates_when_no_overlap() {
        let new_mem = make_semantic("new knowledge");
        let new_emb = vec![1.0, 0.0, 0.0];
        let existing = vec![("old-id".to_string(), vec![0.0, 1.0, 0.0])];

        match determine_action(new_mem, &new_emb, &existing) {
            IntegrationAction::Create(_) => {}
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn updates_when_high_overlap() {
        let new_mem = make_semantic("very similar knowledge");
        let new_emb = vec![1.0, 0.5, 0.3];
        let existing = vec![("old-id".to_string(), vec![1.0, 0.5, 0.3])];

        match determine_action(new_mem, &new_emb, &existing) {
            IntegrationAction::Update { existing_id, .. } => {
                assert_eq!(existing_id, "old-id");
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn creates_when_no_existing() {
        let new_mem = make_semantic("brand new");
        let new_emb = vec![1.0, 0.0];

        match determine_action(new_mem, &new_emb, &[]) {
            IntegrationAction::Create(_) => {}
            _ => panic!("expected Create"),
        }
    }
}

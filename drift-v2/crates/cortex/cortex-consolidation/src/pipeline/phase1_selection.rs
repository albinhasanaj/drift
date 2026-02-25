//! Phase 1: Selection — episodic memories, age > 7d, pending, confidence > 0.3.

use chrono::{Duration, Utc};
use cortex_core::memory::{BaseMemory, MemoryType};

/// Minimum age in days for a memory to be eligible for consolidation.
pub const MIN_AGE_DAYS: i64 = 7;
/// Minimum confidence for consolidation eligibility.
pub const MIN_CONFIDENCE: f64 = 0.3;

/// Memory types eligible for consolidation.
/// Episodic memories are the primary consolidation target.
/// Procedural memories (how-to knowledge) can also benefit from consolidation
/// when multiple overlapping procedures exist.
const CONSOLIDATION_ELIGIBLE: &[MemoryType] = &[
    MemoryType::Episodic,
    MemoryType::Procedural,
];

/// Select memories eligible for consolidation.
///
/// Criteria:
/// - Memory type is Episodic or Procedural
/// - Age > 7 days (based on valid_time)
/// - Confidence > 0.3
/// - Not archived
/// - Not already superseded
pub fn select_candidates(memories: &[BaseMemory]) -> Vec<&BaseMemory> {
    let cutoff = Utc::now() - Duration::days(MIN_AGE_DAYS);

    memories
        .iter()
        .filter(|m| {
            CONSOLIDATION_ELIGIBLE.contains(&m.memory_type)
                && m.valid_time < cutoff
                && m.confidence.value() > MIN_CONFIDENCE
                && !m.archived
                && m.superseded_by.is_none()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use cortex_core::memory::types::EpisodicContent;
    use cortex_core::memory::{Confidence, Importance, TypedContent};

    fn make_episodic(days_old: i64, confidence: f64, archived: bool) -> BaseMemory {
        let content = TypedContent::Episodic(EpisodicContent {
            interaction: "test interaction".to_string(),
            context: "test context".to_string(),
            outcome: None,
        });
        let now = Utc::now();
        BaseMemory {
            id: uuid::Uuid::new_v4().to_string(),
            memory_type: MemoryType::Episodic,
            content: content.clone(),
            summary: "test".to_string(),
            transaction_time: now - Duration::days(days_old),
            valid_time: now - Duration::days(days_old),
            valid_until: None,
            confidence: Confidence::new(confidence),
            importance: Importance::Normal,
            last_accessed: now,
            access_count: 1,
            linked_patterns: vec![],
            linked_constraints: vec![],
            linked_files: vec![],
            linked_functions: vec![],
            tags: vec![],
            archived,
            superseded_by: None,
            supersedes: None,
            namespace: Default::default(),
            source_agent: Default::default(),
            content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        }
    }

    #[test]
    fn selects_eligible_episodic_memories() {
        let memories = vec![
            make_episodic(10, 0.8, false), // eligible
            make_episodic(3, 0.8, false),  // too young
            make_episodic(10, 0.1, false), // too low confidence
            make_episodic(10, 0.8, true),  // archived
        ];
        let candidates = select_candidates(&memories);
        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn excludes_non_episodic() {
        let mut m = make_episodic(10, 0.8, false);
        m.memory_type = MemoryType::Semantic;
        let memories = [m];
        let candidates = select_candidates(&memories);
        assert!(candidates.is_empty());
    }
}

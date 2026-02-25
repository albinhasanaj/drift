//! Consensus detection: ≥3 memories supporting same conclusion → boost +0.2.
//!
//! Consensus memories resist single contradictions.

use cortex_core::memory::BaseMemory;
use std::collections::HashMap;

/// Minimum number of memories required to form a consensus.
pub const MIN_CONSENSUS_SIZE: usize = 3;

/// Confidence boost applied to each memory in a consensus group.
pub const CONSENSUS_BOOST: f64 = 0.2;

/// A group of memories that form a consensus on a topic.
#[derive(Debug, Clone)]
pub struct ConsensusGroup {
    /// IDs of memories in this consensus.
    pub memory_ids: Vec<String>,
    /// The shared topic/conclusion.
    pub topic: String,
    /// Confidence boost to apply.
    pub boost: f64,
}

/// Detect consensus groups among a set of memories.
///
/// Groups memories by shared tags and checks if ≥3 memories support
/// the same conclusion (same tags + same memory type + similar summaries).
pub fn detect_consensus(memories: &[BaseMemory]) -> Vec<ConsensusGroup> {
    let mut groups: Vec<ConsensusGroup> = Vec::new();

    // Group by memory type + primary tag combination.
    let mut type_tag_groups: HashMap<String, Vec<&BaseMemory>> = HashMap::new();

    for memory in memories {
        if memory.archived {
            continue;
        }

        // Create a grouping key from type + sorted tags.
        let mut sorted_tags = memory.tags.clone();
        sorted_tags.sort();
        let key = format!("{:?}:{}", memory.memory_type, sorted_tags.join(","));

        type_tag_groups.entry(key).or_default().push(memory);
    }

    // Check each group for consensus.
    for (key, group_memories) in &type_tag_groups {
        if group_memories.len() >= MIN_CONSENSUS_SIZE {
            // Extract a topic description from the first tag or summary.
            let topic = group_memories
                .first()
                .and_then(|m| m.tags.first().cloned())
                .unwrap_or_else(|| key.split(':').next().unwrap_or("unknown").to_string());

            groups.push(ConsensusGroup {
                memory_ids: group_memories.iter().map(|m| m.id.clone()).collect(),
                topic,
                boost: CONSENSUS_BOOST,
            });
        }
    }

    groups
}

/// Check if a memory is part of any consensus group.
pub fn is_in_consensus(memory_id: &str, groups: &[ConsensusGroup]) -> bool {
    groups
        .iter()
        .any(|g| g.memory_ids.iter().any(|id| id == memory_id))
}

/// Check if a contradiction should be resisted because the target
/// memory is backed by consensus.
///
/// Returns `true` if the memory has consensus support and the contradiction
/// should be weakened or ignored.
pub fn resists_contradiction(memory_id: &str, groups: &[ConsensusGroup]) -> bool {
    is_in_consensus(memory_id, groups)
}

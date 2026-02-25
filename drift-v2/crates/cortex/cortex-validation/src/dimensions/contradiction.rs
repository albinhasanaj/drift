//! Contradiction validation dimension.
//!
//! Runs the contradiction detector against related memories and checks
//! consensus support. Consensus memories resist single contradictions.

use cortex_core::memory::BaseMemory;
use cortex_core::models::{Contradiction, HealingAction, HealingActionType};

use crate::contradiction::consensus;
use crate::contradiction::detection;
use crate::contradiction::SimilarityFn;

/// Result of contradiction validation for a single memory.
#[derive(Debug, Clone)]
pub struct ContradictionValidationResult {
    /// Score from 0.0 (heavily contradicted) to 1.0 (no contradictions).
    pub score: f64,
    /// Detected contradictions involving this memory.
    pub contradictions: Vec<Contradiction>,
    /// Whether this memory has consensus support.
    pub has_consensus: bool,
    /// Healing actions needed.
    pub healing_actions: Vec<HealingAction>,
}

/// Validate a memory for contradictions against a set of related memories.
///
/// `memory`: the memory being validated.
/// `related`: other memories to check against (pre-filtered by caller).
/// `all_memories`: full set for consensus detection.
/// `similarity_fn`: optional embedding similarity lookup.
pub fn validate(
    memory: &BaseMemory,
    related: &[BaseMemory],
    all_memories: &[BaseMemory],
    similarity_fn: Option<&SimilarityFn<'_>>,
) -> ContradictionValidationResult {
    let mut contradictions = Vec::new();
    let mut healing_actions = Vec::new();

    // Run detection against each related memory.
    for other in related {
        if other.id == memory.id {
            continue;
        }

        let sim = similarity_fn.and_then(|f| f(&memory.id, &other.id));

        if let Some(c) = detection::detect_all(memory, other, sim) {
            contradictions.push(c);
        }
    }

    // Check consensus support.
    let consensus_groups = consensus::detect_consensus(all_memories);
    let has_consensus = consensus::is_in_consensus(&memory.id, &consensus_groups);

    // If memory has consensus support, single contradictions are weakened.
    let effective_contradictions = if has_consensus {
        contradictions
            .iter()
            .filter(|c| {
                // Only keep contradictions where the opposing memory also has consensus.
                c.memory_ids
                    .iter()
                    .filter(|id| *id != &memory.id)
                    .any(|id| consensus::is_in_consensus(id, &consensus_groups))
            })
            .cloned()
            .collect::<Vec<_>>()
    } else {
        contradictions.clone()
    };

    // Compute score.
    let score = if effective_contradictions.is_empty() {
        1.0
    } else {
        // Each contradiction reduces the score.
        let penalty: f64 = effective_contradictions
            .iter()
            .map(|c| c.confidence_delta.abs())
            .sum();
        (1.0 - penalty).max(0.0)
    };

    // Generate healing actions.
    for c in &effective_contradictions {
        healing_actions.push(HealingAction {
            action_type: HealingActionType::ConfidenceAdjust,
            description: format!("Contradiction detected: {}", c.description),
            applied: false,
        });
    }

    if score < 0.15 {
        healing_actions.push(HealingAction {
            action_type: HealingActionType::Archival,
            description: "Heavily contradicted memory — candidate for archival".into(),
            applied: false,
        });
    } else if !effective_contradictions.is_empty() {
        healing_actions.push(HealingAction {
            action_type: HealingActionType::HumanReviewFlag,
            description: format!(
                "{} contradiction(s) detected — review recommended",
                effective_contradictions.len()
            ),
            applied: false,
        });
    }

    ContradictionValidationResult {
        score,
        contradictions,
        has_consensus,
        healing_actions,
    }
}

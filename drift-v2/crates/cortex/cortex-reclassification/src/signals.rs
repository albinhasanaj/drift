//! 5 reclassification signals with weighted scoring.
//!
//! | Signal                    | Weight | Logic                                    |
//! |---------------------------|--------|------------------------------------------|
//! | Access frequency (30-day) | 0.35   | > 20/month → upgrade candidate           |
//! | Retrieval rank (30-day)   | 0.25   | Consistently top-5 → important           |
//! | Linked entity count       | 0.15   | ≥ 3 active links → structurally important|
//! | Contradiction involvement | 0.10   | Frequently "wins" → authoritative        |
//! | User feedback             | 0.15   | Explicitly confirmed → boost             |

use serde::{Deserialize, Serialize};

/// Weights for the 5 reclassification signals.
pub const WEIGHT_ACCESS_FREQUENCY: f64 = 0.35;
pub const WEIGHT_RETRIEVAL_RANK: f64 = 0.25;
pub const WEIGHT_LINKED_ENTITIES: f64 = 0.15;
pub const WEIGHT_CONTRADICTION: f64 = 0.10;
pub const WEIGHT_USER_FEEDBACK: f64 = 0.15;

/// Raw signal data for a single memory's reclassification evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReclassificationSignals {
    /// Number of accesses in the last 30 days.
    pub access_count_30d: u64,
    /// Average retrieval rank in the last 30 days (lower = better, 1 = top).
    /// None if the memory was never retrieved.
    pub avg_retrieval_rank_30d: Option<f64>,
    /// Number of active linked entities (relationships, patterns, files).
    pub linked_entity_count: u64,
    /// Number of contradictions this memory has "won" (was kept as authoritative).
    pub contradiction_wins: u64,
    /// User feedback score: positive confirmations minus negative.
    /// Normalized to 0.0–1.0 where 0.5 = neutral.
    pub user_feedback_score: f64,
}

impl ReclassificationSignals {
    /// Compute the composite reclassification score (0.0–1.0).
    pub fn composite_score(&self) -> f64 {
        let access_score = normalize_access(self.access_count_30d);
        let rank_score = normalize_rank(self.avg_retrieval_rank_30d);
        let entity_score = normalize_entities(self.linked_entity_count);
        let contradiction_score = normalize_contradictions(self.contradiction_wins);
        let feedback_score = self.user_feedback_score.clamp(0.0, 1.0);

        let composite = access_score * WEIGHT_ACCESS_FREQUENCY
            + rank_score * WEIGHT_RETRIEVAL_RANK
            + entity_score * WEIGHT_LINKED_ENTITIES
            + contradiction_score * WEIGHT_CONTRADICTION
            + feedback_score * WEIGHT_USER_FEEDBACK;

        composite.clamp(0.0, 1.0)
    }
}

/// Normalize access count to 0.0–1.0.
/// 0 accesses → 0.0, 20+ accesses → 1.0.
fn normalize_access(count: u64) -> f64 {
    (count as f64 / 20.0).min(1.0)
}

/// Normalize retrieval rank to 0.0–1.0.
/// Rank 1 → 1.0, rank 5 → 0.5, rank 10+ → 0.0.
fn normalize_rank(avg_rank: Option<f64>) -> f64 {
    match avg_rank {
        Some(rank) if rank > 0.0 => (1.0 - (rank - 1.0) / 9.0).clamp(0.0, 1.0),
        _ => 0.0,
    }
}

/// Normalize linked entity count to 0.0–1.0.
/// 0 → 0.0, 3+ → 1.0.
fn normalize_entities(count: u64) -> f64 {
    (count as f64 / 3.0).min(1.0)
}

/// Normalize contradiction wins to 0.0–1.0.
/// 0 → 0.0, 5+ → 1.0.
fn normalize_contradictions(wins: u64) -> f64 {
    (wins as f64 / 5.0).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_score_all_max() {
        let signals = ReclassificationSignals {
            access_count_30d: 100,
            avg_retrieval_rank_30d: Some(1.0),
            linked_entity_count: 10,
            contradiction_wins: 10,
            user_feedback_score: 1.0,
        };
        let score = signals.composite_score();
        assert!(
            (score - 1.0).abs() < f64::EPSILON,
            "All max signals should give 1.0, got {}",
            score
        );
    }

    #[test]
    fn composite_score_all_zero() {
        let signals = ReclassificationSignals {
            access_count_30d: 0,
            avg_retrieval_rank_30d: None,
            linked_entity_count: 0,
            contradiction_wins: 0,
            user_feedback_score: 0.0,
        };
        let score = signals.composite_score();
        assert!(
            (score - 0.0).abs() < f64::EPSILON,
            "All zero signals should give 0.0, got {}",
            score
        );
    }

    #[test]
    fn composite_score_weights_sum_to_one() {
        let total = WEIGHT_ACCESS_FREQUENCY
            + WEIGHT_RETRIEVAL_RANK
            + WEIGHT_LINKED_ENTITIES
            + WEIGHT_CONTRADICTION
            + WEIGHT_USER_FEEDBACK;
        assert!(
            (total - 1.0).abs() < f64::EPSILON,
            "Weights should sum to 1.0, got {}",
            total
        );
    }
}

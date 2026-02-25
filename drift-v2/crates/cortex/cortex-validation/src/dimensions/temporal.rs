//! Temporal validation: validUntil expiry, age vs expected lifetime.
//!
//! Checks whether a memory has expired or is approaching the end of
//! its expected lifetime based on its type's half-life.

use chrono::{DateTime, Utc};
use cortex_core::memory::half_lives::half_life_days;
use cortex_core::memory::BaseMemory;
use cortex_core::models::{HealingAction, HealingActionType};

/// Result of temporal validation for a single memory.
#[derive(Debug, Clone)]
pub struct TemporalValidationResult {
    /// Score from 0.0 (expired/stale) to 1.0 (fresh).
    pub score: f64,
    /// Healing actions needed.
    pub healing_actions: Vec<HealingAction>,
    /// Whether the memory has explicitly expired (validUntil in the past).
    pub expired: bool,
    /// Ratio of age to expected lifetime (>1.0 means past expected lifetime).
    pub age_ratio: f64,
    /// Whether referenced memories are temporally consistent.
    pub temporally_consistent: bool,
}

/// Validate temporal aspects of a memory.
///
/// `now`: current timestamp (injectable for testing).
pub fn validate(memory: &BaseMemory, now: DateTime<Utc>) -> TemporalValidationResult {
    let mut healing_actions = Vec::new();

    // Check explicit expiry.
    let expired = memory.valid_until.is_some_and(|until| until < now);

    if expired {
        healing_actions.push(HealingAction {
            action_type: HealingActionType::Archival,
            description: format!(
                "Memory expired at {}",
                memory.valid_until.unwrap().format("%Y-%m-%d")
            ),
            applied: false,
        });
    }

    // Compute age ratio against expected half-life.
    let age_days = (now - memory.valid_time).num_days().max(0) as f64;
    let expected_days = half_life_days(memory.memory_type);

    let age_ratio = match expected_days {
        None => 0.0, // Infinite half-life types never age out.
        Some(0) => f64::INFINITY,
        Some(d) => age_days / d as f64,
    };

    // Score: 1.0 when fresh, decays as age approaches and exceeds half-life.
    // Using exponential decay: score = 2^(-age/half_life)
    let age_score = match expected_days {
        None => 1.0,
        Some(0) => 0.0,
        Some(d) => 2.0_f64.powf(-age_days / d as f64),
    };

    // If expired, score is 0.
    let score = if expired { 0.0 } else { age_score };

    // Flag memories approaching end of life.
    if age_ratio > 0.8 && age_ratio.is_finite() && !expired {
        let exp = expected_days.unwrap_or(0) as f64;
        healing_actions.push(HealingAction {
            action_type: HealingActionType::HumanReviewFlag,
            description: format!(
                "Memory at {:.0}% of expected lifetime ({:.0} of {:.0} days)",
                age_ratio * 100.0,
                age_days,
                exp
            ),
            applied: false,
        });
    }

    // Flag very old memories for confidence adjustment.
    if age_ratio > 1.5 && age_ratio.is_finite() && !expired {
        healing_actions.push(HealingAction {
            action_type: HealingActionType::ConfidenceAdjust,
            description: format!(
                "Memory significantly past expected lifetime ({:.1}x)",
                age_ratio
            ),
            applied: false,
        });
    }

    TemporalValidationResult {
        score,
        healing_actions,
        expired,
        age_ratio,
        temporally_consistent: true,
    }
}

/// Validate temporal aspects of a memory including temporal consistency of references.
///
/// Referenced memories (via supersedes, linked_patterns, etc.) must have existed
/// when the referencing memory was created. This is a temporal consistency check.
///
/// `now`: current timestamp (injectable for testing).
/// `reference_creation_times`: map of referenced memory IDs to their creation times.
pub fn validate_with_references(
    memory: &BaseMemory,
    now: DateTime<Utc>,
    reference_creation_times: &dyn Fn(&str) -> Option<DateTime<Utc>>,
) -> TemporalValidationResult {
    let mut base_result = validate(memory, now);
    let memory_created_at = memory.transaction_time;

    let mut inconsistent_refs = Vec::new();

    // Check supersedes reference.
    if let Some(ref supersedes_id) = memory.supersedes {
        if let Some(ref_created) = reference_creation_times(supersedes_id) {
            if ref_created > memory_created_at {
                inconsistent_refs.push(supersedes_id.clone());
            }
        }
    }

    // Check superseded_by reference.
    if let Some(ref superseded_by_id) = memory.superseded_by {
        if let Some(ref_created) = reference_creation_times(superseded_by_id) {
            if ref_created > memory_created_at {
                inconsistent_refs.push(superseded_by_id.clone());
            }
        }
    }

    if !inconsistent_refs.is_empty() {
        base_result.temporally_consistent = false;
        // Apply a penalty but don't zero out the score.
        let penalty = 0.1 * inconsistent_refs.len() as f64;
        base_result.score = (base_result.score - penalty).max(0.0);
        base_result.healing_actions.push(HealingAction {
            action_type: HealingActionType::HumanReviewFlag,
            description: format!(
                "Temporal inconsistency: {} referenced memories were created after this memory",
                inconsistent_refs.len()
            ),
            applied: false,
        });
    }

    base_result
}

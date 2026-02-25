//! Pattern alignment validation.
//!
//! Checks whether linked patterns still exist and whether their
//! confidence has changed significantly. Removed patterns → flag.

use cortex_core::memory::BaseMemory;
use cortex_core::models::{HealingAction, HealingActionType};

/// Result of pattern alignment validation.
#[derive(Debug, Clone)]
pub struct PatternAlignmentResult {
    /// Score from 0.0 (all patterns missing/changed) to 1.0 (all aligned).
    pub score: f64,
    /// Healing actions needed.
    pub healing_actions: Vec<HealingAction>,
    /// Details per pattern link.
    pub details: Vec<PatternDetail>,
}

/// Validation detail for a single pattern link.
#[derive(Debug, Clone)]
pub struct PatternDetail {
    pub pattern_id: String,
    pub pattern_name: String,
    pub exists: bool,
    pub confidence_changed: bool,
}

/// Information about a pattern's current state.
pub struct PatternInfo {
    pub exists: bool,
    /// Current confidence of the pattern memory (if it exists).
    pub confidence: Option<f64>,
}

/// Validate pattern alignment for a memory.
///
/// `pattern_checker`: callback that returns the current state of a pattern.
pub fn validate(
    memory: &BaseMemory,
    pattern_checker: &dyn Fn(&str) -> PatternInfo,
) -> PatternAlignmentResult {
    if memory.linked_patterns.is_empty() {
        return PatternAlignmentResult {
            score: 1.0,
            healing_actions: vec![],
            details: vec![],
        };
    }

    let mut valid_count = 0;
    let mut total_count = 0;
    let mut healing_actions = Vec::new();
    let mut details = Vec::new();

    for pattern_link in &memory.linked_patterns {
        total_count += 1;
        let info = pattern_checker(&pattern_link.pattern_id);

        if !info.exists {
            // Pattern was removed.
            healing_actions.push(HealingAction {
                action_type: HealingActionType::HumanReviewFlag,
                description: format!(
                    "Linked pattern '{}' no longer exists",
                    pattern_link.pattern_name
                ),
                applied: false,
            });

            details.push(PatternDetail {
                pattern_id: pattern_link.pattern_id.clone(),
                pattern_name: pattern_link.pattern_name.clone(),
                exists: false,
                confidence_changed: false,
            });
            continue;
        }

        // Check if pattern confidence changed significantly.
        let confidence_changed = info.confidence.is_some_and(|c| {
            // Significant change = more than 0.3 drop.
            let memory_conf = memory.confidence.value();
            (memory_conf - c).abs() > 0.3
        });

        if confidence_changed {
            healing_actions.push(HealingAction {
                action_type: HealingActionType::ConfidenceAdjust,
                description: format!(
                    "Pattern '{}' confidence changed significantly",
                    pattern_link.pattern_name
                ),
                applied: false,
            });
        } else {
            valid_count += 1;
        }

        details.push(PatternDetail {
            pattern_id: pattern_link.pattern_id.clone(),
            pattern_name: pattern_link.pattern_name.clone(),
            exists: true,
            confidence_changed,
        });
    }

    let score = if total_count > 0 {
        valid_count as f64 / total_count as f64
    } else {
        1.0
    };

    PatternAlignmentResult {
        score,
        healing_actions,
        details,
    }
}

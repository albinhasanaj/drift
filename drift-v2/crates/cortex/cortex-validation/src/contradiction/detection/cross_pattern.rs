//! Same pattern, opposing content detection.
//!
//! Detects when two memories reference the same pattern but contain
//! opposing guidance or conclusions.

use cortex_core::memory::BaseMemory;
use cortex_core::models::{Contradiction, ContradictionType, DetectionStrategy};

/// Opposing sentiment indicators.
const POSITIVE_INDICATORS: &[&str] = &[
    "good",
    "recommended",
    "prefer",
    "use",
    "adopt",
    "enable",
    "best practice",
    "should",
    "correct",
    "proper",
    "ideal",
    "effective",
];

const NEGATIVE_INDICATORS: &[&str] = &[
    "bad",
    "avoid",
    "don't",
    "disable",
    "anti-pattern",
    "deprecated",
    "shouldn't",
    "incorrect",
    "improper",
    "harmful",
    "ineffective",
];

/// Detect cross-pattern contradictions.
///
/// Two memories linked to the same pattern but with opposing sentiment
/// about that pattern indicate a contradiction.
pub fn detect(a: &BaseMemory, b: &BaseMemory) -> Option<Contradiction> {
    // Find shared patterns.
    let shared_patterns: Vec<&str> = a
        .linked_patterns
        .iter()
        .filter(|ap| {
            b.linked_patterns
                .iter()
                .any(|bp| bp.pattern_id == ap.pattern_id)
        })
        .map(|p| p.pattern_name.as_str())
        .collect();

    if shared_patterns.is_empty() {
        return None;
    }

    // Check if the memories have opposing sentiment about the shared pattern.
    let a_lower = a.summary.to_lowercase();
    let b_lower = b.summary.to_lowercase();

    let a_positive = POSITIVE_INDICATORS.iter().any(|w| a_lower.contains(w));
    let a_negative = NEGATIVE_INDICATORS.iter().any(|w| a_lower.contains(w));
    let b_positive = POSITIVE_INDICATORS.iter().any(|w| b_lower.contains(w));
    let b_negative = NEGATIVE_INDICATORS.iter().any(|w| b_lower.contains(w));

    let opposing = (a_positive && b_negative) || (a_negative && b_positive);

    if opposing {
        Some(Contradiction {
            contradiction_type: ContradictionType::Direct,
            memory_ids: vec![a.id.clone(), b.id.clone()],
            confidence_delta: -0.3,
            description: format!(
                "Cross-pattern contradiction on [{}]: '{}' vs '{}'",
                shared_patterns.join(", "),
                a.summary,
                b.summary
            ),
            detected_by: DetectionStrategy::CrossPattern,
        })
    } else {
        None
    }
}

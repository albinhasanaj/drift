//! Feedback contradiction detection.
//!
//! Detects when user feedback contradicts an existing memory,
//! e.g., a correction that opposes a stored pattern or decision.

use cortex_core::memory::base::TypedContent;
use cortex_core::memory::BaseMemory;
use cortex_core::models::{Contradiction, ContradictionType, DetectionStrategy};

/// Negative feedback keywords that indicate contradiction.
const NEGATIVE_KEYWORDS: &[&str] = &[
    "wrong",
    "incorrect",
    "outdated",
    "deprecated",
    "no longer",
    "don't",
    "shouldn't",
    "bad practice",
    "anti-pattern",
    "broken",
    "invalid",
    "obsolete",
    "mistake",
    "error",
];

/// Detect feedback contradictions.
///
/// A feedback memory whose content contains negative sentiment about a topic
/// that overlaps with another memory indicates a contradiction.
pub fn detect(a: &BaseMemory, b: &BaseMemory) -> Option<Contradiction> {
    // Check if either memory is feedback type.
    let (feedback_mem, target_mem, feedback_text) = match (&a.content, &b.content) {
        (TypedContent::Feedback(fb), _) => (a, b, &fb.feedback),
        (_, TypedContent::Feedback(fb)) => (b, a, &fb.feedback),
        _ => return None,
    };

    let feedback_lower = feedback_text.to_lowercase();

    // Check if the feedback is negative.
    let is_negative = NEGATIVE_KEYWORDS
        .iter()
        .any(|kw| feedback_lower.contains(kw));

    if !is_negative {
        return None;
    }

    // Check if the feedback relates to the target memory via tags or summary overlap.
    let relates_to_target = has_topic_overlap(feedback_mem, target_mem);

    if relates_to_target {
        Some(Contradiction {
            contradiction_type: ContradictionType::Direct,
            memory_ids: vec![target_mem.id.clone(), feedback_mem.id.clone()],
            confidence_delta: -0.3,
            description: format!(
                "Negative feedback on '{}': {}",
                target_mem.summary, feedback_text
            ),
            detected_by: DetectionStrategy::Feedback,
        })
    } else {
        None
    }
}

/// Check if two memories share enough tags or summary words to be about the same topic.
fn has_topic_overlap(a: &BaseMemory, b: &BaseMemory) -> bool {
    // Tag overlap.
    let tag_overlap = a.tags.iter().any(|t| b.tags.contains(t));
    if tag_overlap {
        return true;
    }

    // Summary word overlap (at least 2 significant words in common).
    let a_lower = a.summary.to_lowercase();
    let b_lower = b.summary.to_lowercase();
    let a_words: Vec<&str> = a_lower.split_whitespace().filter(|w| w.len() > 3).collect();
    let overlap = a_words.iter().filter(|w| b_lower.contains(**w)).count();
    overlap >= 2
}

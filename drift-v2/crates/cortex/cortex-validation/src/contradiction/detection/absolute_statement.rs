//! "always"/"never" absolute statement conflict detection.

use cortex_core::memory::BaseMemory;
use cortex_core::models::{Contradiction, ContradictionType, DetectionStrategy};
use regex::Regex;
use std::sync::LazyLock;

/// Regex for absolute positive statements.
static ALWAYS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(always|must always|every time|without exception|invariably|in all cases)\b")
        .unwrap()
});

/// Regex for absolute negative statements.
static NEVER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(never|must never|under no circumstances|at no point|in no case|must not ever)\b",
    )
    .unwrap()
});

/// Extract the subject/topic from text near an absolute keyword.
/// Returns a lowercased snippet around the match for comparison.
fn extract_topic(text: &str, mat: &regex::Match) -> String {
    let start = mat.end();
    let remaining = &text[start..];
    // Take up to 60 chars after the keyword as the "topic".
    let topic: String = remaining.chars().take(60).collect();
    topic.trim().to_lowercase()
}

/// Detect contradictions between absolute statements.
///
/// "Always use X" vs "Never use X" on the same topic = direct contradiction.
pub fn detect(a: &BaseMemory, b: &BaseMemory) -> Option<Contradiction> {
    let a_text = &a.summary;
    let b_text = &b.summary;

    // Check: A says "always" and B says "never" (or vice versa) about similar topics.
    if let (Some(a_match), Some(b_match)) = (ALWAYS_RE.find(a_text), NEVER_RE.find(b_text)) {
        let a_topic = extract_topic(a_text, &a_match);
        let b_topic = extract_topic(b_text, &b_match);
        if topics_overlap(&a_topic, &b_topic) {
            return Some(Contradiction {
                contradiction_type: ContradictionType::Direct,
                memory_ids: vec![a.id.clone(), b.id.clone()],
                confidence_delta: -0.3,
                description: format!(
                    "Absolute statement conflict: '{}' vs '{}'",
                    a.summary, b.summary
                ),
                detected_by: DetectionStrategy::AbsoluteStatement,
            });
        }
    }

    // Check the reverse: A says "never" and B says "always".
    if let (Some(a_match), Some(b_match)) = (NEVER_RE.find(a_text), ALWAYS_RE.find(b_text)) {
        let a_topic = extract_topic(a_text, &a_match);
        let b_topic = extract_topic(b_text, &b_match);
        if topics_overlap(&a_topic, &b_topic) {
            return Some(Contradiction {
                contradiction_type: ContradictionType::Direct,
                memory_ids: vec![a.id.clone(), b.id.clone()],
                confidence_delta: -0.3,
                description: format!(
                    "Absolute statement conflict: '{}' vs '{}'",
                    a.summary, b.summary
                ),
                detected_by: DetectionStrategy::AbsoluteStatement,
            });
        }
    }

    None
}

/// Check if two topic snippets have significant word overlap.
fn topics_overlap(a: &str, b: &str) -> bool {
    let a_words: Vec<&str> = a.split_whitespace().filter(|w| w.len() > 2).collect();
    let b_words: Vec<&str> = b.split_whitespace().filter(|w| w.len() > 2).collect();

    if a_words.is_empty() || b_words.is_empty() {
        return false;
    }

    let overlap = a_words.iter().filter(|w| b_words.contains(w)).count();

    let min_len = a_words.len().min(b_words.len());
    // At least 30% word overlap.
    overlap as f64 / min_len as f64 >= 0.3
}

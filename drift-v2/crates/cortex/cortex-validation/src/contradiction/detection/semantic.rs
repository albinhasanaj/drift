//! Semantic contradiction detection via embedding similarity + negation patterns.

use cortex_core::memory::BaseMemory;
use cortex_core::models::{Contradiction, ContradictionType, DetectionStrategy};

/// Negation patterns that indicate semantic opposition.
const NEGATION_PAIRS: &[(&str, &str)] = &[
    ("always", "never"),
    ("must", "must not"),
    ("should", "should not"),
    ("enable", "disable"),
    ("allow", "deny"),
    ("include", "exclude"),
    ("use", "avoid"),
    ("prefer", "avoid"),
    ("recommended", "discouraged"),
    ("required", "forbidden"),
    ("do", "don't"),
    ("can", "cannot"),
    ("safe", "unsafe"),
    ("secure", "insecure"),
    ("correct", "incorrect"),
    ("valid", "invalid"),
];

/// Detect semantic contradictions between a pair of memories.
///
/// Uses negation pattern matching on summaries/content. Embedding similarity
/// is expected to be provided by the caller (the dimension runner) since
/// it requires the embedding engine.
pub fn detect(
    a: &BaseMemory,
    b: &BaseMemory,
    embedding_similarity: Option<f64>,
) -> Option<Contradiction> {
    let a_text = a.summary.to_lowercase();
    let b_text = b.summary.to_lowercase();

    // Check negation patterns.
    let has_negation = NEGATION_PAIRS.iter().any(|(pos, neg)| {
        (a_text.contains(pos) && b_text.contains(neg))
            || (a_text.contains(neg) && b_text.contains(pos))
    });

    // High embedding similarity + negation pattern = strong contradiction signal.
    let sim_threshold = 0.7;
    let is_semantically_similar = embedding_similarity.is_some_and(|s| s >= sim_threshold);

    if has_negation && is_semantically_similar {
        return Some(Contradiction {
            contradiction_type: ContradictionType::Semantic,
            memory_ids: vec![a.id.clone(), b.id.clone()],
            confidence_delta: -0.3,
            description: format!(
                "Semantic contradiction: '{}' vs '{}' (similarity: {:.2})",
                a.summary,
                b.summary,
                embedding_similarity.unwrap_or(0.0)
            ),
            detected_by: DetectionStrategy::Semantic,
        });
    }

    // Negation alone (without embeddings) is a weaker signal.
    if has_negation {
        return Some(Contradiction {
            contradiction_type: ContradictionType::Partial,
            memory_ids: vec![a.id.clone(), b.id.clone()],
            confidence_delta: -0.15,
            description: format!(
                "Possible contradiction (negation pattern): '{}' vs '{}'",
                a.summary, b.summary
            ),
            detected_by: DetectionStrategy::Semantic,
        });
    }

    None
}

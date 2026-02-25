//! Newer memory supersedes older on same topic.

use cortex_core::memory::BaseMemory;
use cortex_core::models::{Contradiction, ContradictionType, DetectionStrategy};

/// Detect temporal supersession: a newer memory on the same topic
/// implicitly contradicts an older one.
///
/// `tag_overlap_threshold`: minimum fraction of shared tags to consider "same topic".
/// `embedding_similarity`: optional cosine similarity between the two memories.
pub fn detect(
    a: &BaseMemory,
    b: &BaseMemory,
    embedding_similarity: Option<f64>,
    tag_overlap_threshold: f64,
) -> Option<Contradiction> {
    // Must be the same memory type.
    if a.memory_type != b.memory_type {
        return None;
    }

    // One must be newer than the other.
    if a.valid_time == b.valid_time {
        return None;
    }

    let (older, newer) = if a.valid_time < b.valid_time {
        (a, b)
    } else {
        (b, a)
    };

    // Check topic similarity via tags.
    let tag_overlap = compute_tag_overlap(older, newer);
    let tags_match = tag_overlap >= tag_overlap_threshold;

    // Check topic similarity via embeddings.
    let embeddings_match = embedding_similarity.is_some_and(|s| s >= 0.8);

    // Check if they reference the same files.
    let files_match = !older.linked_files.is_empty()
        && older.linked_files.iter().any(|f| {
            newer
                .linked_files
                .iter()
                .any(|nf| nf.file_path == f.file_path)
        });

    if tags_match || embeddings_match || files_match {
        // Check if the newer one explicitly supersedes.
        if newer.supersedes.as_deref() == Some(&older.id) {
            return Some(Contradiction {
                contradiction_type: ContradictionType::Supersession,
                memory_ids: vec![older.id.clone(), newer.id.clone()],
                confidence_delta: -0.5,
                description: format!(
                    "Explicit supersession: '{}' superseded by '{}'",
                    older.summary, newer.summary
                ),
                detected_by: DetectionStrategy::TemporalSupersession,
            });
        }

        // Implicit supersession: same topic, newer version.
        return Some(Contradiction {
            contradiction_type: ContradictionType::Supersession,
            memory_ids: vec![older.id.clone(), newer.id.clone()],
            confidence_delta: -0.3,
            description: format!(
                "Temporal supersession: '{}' likely superseded by newer '{}'",
                older.summary, newer.summary
            ),
            detected_by: DetectionStrategy::TemporalSupersession,
        });
    }

    None
}

/// Compute Jaccard overlap of tags between two memories.
fn compute_tag_overlap(a: &BaseMemory, b: &BaseMemory) -> f64 {
    if a.tags.is_empty() && b.tags.is_empty() {
        return 0.0;
    }
    let a_set: std::collections::HashSet<&str> = a.tags.iter().map(|s| s.as_str()).collect();
    let b_set: std::collections::HashSet<&str> = b.tags.iter().map(|s| s.as_str()).collect();
    let intersection = a_set.intersection(&b_set).count();
    let union = a_set.union(&b_set).count();
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

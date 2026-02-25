//! Optional cross-encoder re-ranking.
//!
//! When the `reranker` feature is enabled, uses fastembed's `TextRerank` to
//! re-score the top-K candidates with a cross-encoder model for higher precision.
//! When disabled, passes candidates through unchanged.

use crate::ranking::scorer::ScoredCandidate;

/// Re-rank the top-K scored candidates using a cross-encoder model.
///
/// When the `reranker` feature is enabled and a model is provided, the top `top_k`
/// candidates are re-scored using pairwise query-document relevance from the
/// cross-encoder. Candidates beyond `top_k` are appended unchanged.
///
/// When the feature is disabled or no model is provided, candidates pass through as-is.
#[cfg(feature = "reranker")]
pub fn rerank(
    query: &str,
    candidates: Vec<ScoredCandidate>,
    top_k: usize,
    model: Option<&fastembed::TextRerank>,
) -> Vec<ScoredCandidate> {
    let model = match model {
        Some(m) => m,
        None => return candidates,
    };

    if candidates.is_empty() || query.trim().is_empty() {
        return candidates;
    }

    let rerank_count = top_k.min(candidates.len());
    let (to_rerank, tail) = candidates.split_at(rerank_count);

    // Extract document texts for the cross-encoder.
    let documents: Vec<&str> = to_rerank
        .iter()
        .map(|c| c.memory.summary.as_str())
        .collect();

    // Run cross-encoder reranking. On failure, fall back to original order.
    let reranked = match model.rerank(query, &documents, true, None) {
        Ok(results) => {
            // Map reranked results back to ScoredCandidates.
            let mut reranked_candidates: Vec<ScoredCandidate> = results
                .iter()
                .filter_map(|r| {
                    let idx = r.index;
                    to_rerank.get(idx).map(|original| {
                        let mut candidate = original.clone();
                        // Blend cross-encoder score with original score.
                        // Cross-encoder score is in [0, 1], original score varies.
                        // Use 60/40 blend: cross-encoder dominates but original signal preserved.
                        candidate.score = r.score as f64 * 0.6 + candidate.score * 0.4;
                        candidate
                    })
                })
                .collect();

            // Sort by blended score descending.
            reranked_candidates.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            reranked_candidates
        }
        Err(_) => {
            // Graceful degradation: return original order on model failure.
            to_rerank.to_vec()
        }
    };

    // Append tail candidates that weren't reranked.
    let mut result = reranked;
    result.extend_from_slice(tail);
    result
}

/// No-op passthrough when the `reranker` feature is disabled.
#[cfg(not(feature = "reranker"))]
pub fn rerank(candidates: Vec<ScoredCandidate>, _top_k: usize) -> Vec<ScoredCandidate> {
    candidates
}

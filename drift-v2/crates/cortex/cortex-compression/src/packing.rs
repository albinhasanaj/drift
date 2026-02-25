use cortex_core::memory::{BaseMemory, Importance};
use cortex_core::models::CompressedMemory;
use cortex_tokens::TokenCounter;

use crate::levels::{self, CompressionLevel};

/// Priority-weighted bin-packing result for a single memory.
struct PackCandidate<'a> {
    memory: &'a BaseMemory,
    /// importance_weight × relevance_score (higher = more important to include).
    priority: f64,
    /// Relevance score from retrieval ranking (default 1.0 if not ranked).
    relevance_score: f64,
}

/// Pack a batch of memories into a token budget using priority-weighted bin-packing.
///
/// Algorithm:
/// 1. Sort by `importance.weight() × relevance_score` descending.
/// 2. For each memory, try L3 → L2 → L1 → L0 until it fits remaining budget.
/// 3. Critical memories always get at least L1 (never dropped to L0).
/// 4. Uses actual token counts via `TokenCounter`, not estimates.
pub fn pack_to_budget(
    memories: &[BaseMemory],
    budget: usize,
    counter: &TokenCounter,
    relevance_scores: Option<&[f64]>,
) -> Vec<CompressedMemory> {
    if memories.is_empty() || budget == 0 {
        return Vec::new();
    }

    // Build candidates with priority scores.
    let mut candidates: Vec<PackCandidate> = memories
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let relevance = relevance_scores
                .and_then(|scores| scores.get(i).copied())
                .unwrap_or(1.0);
            PackCandidate {
                memory: m,
                priority: m.importance.weight() * relevance,
                relevance_score: relevance,
            }
        })
        .collect();

    // Sort by priority descending.
    candidates.sort_by(|a, b| {
        b.priority
            .partial_cmp(&a.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut remaining = budget;
    let mut result = Vec::with_capacity(candidates.len());

    for candidate in &candidates {
        if remaining == 0 {
            break;
        }

        let is_critical = candidate.memory.importance == Importance::Critical;
        let min_level = if is_critical {
            CompressionLevel::L1
        } else {
            CompressionLevel::L0
        };

        // Try levels from highest to lowest.
        let mut best: Option<(CompressionLevel, String, usize)> = None;

        for &level in &CompressionLevel::ALL_DESC {
            let text = levels::compress_at_level(candidate.memory, level);
            let tokens = counter.count_cached(&text);

            if tokens <= remaining {
                best = Some((level, text, tokens));
                break;
            }
        }

        // If nothing fits but this is critical, force L1 if it fits, else L0.
        if best.is_none() && is_critical {
            let text = levels::compress_at_level(candidate.memory, min_level);
            let tokens = counter.count_cached(&text);
            if tokens <= remaining {
                best = Some((min_level, text, tokens));
            }
        }

        if let Some((level, text, tokens)) = best {
            remaining -= tokens;
            result.push(CompressedMemory {
                memory_id: candidate.memory.id.clone(),
                memory_type: candidate.memory.memory_type,
                importance: candidate.memory.importance,
                level: level as u8,
                text,
                token_count: tokens,
                relevance_score: candidate.relevance_score,
            });
        }
    }

    result
}

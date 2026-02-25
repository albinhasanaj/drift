//! Priority-weighted bin-packing using cortex-compression.
//!
//! Takes scored candidates and packs them into a token budget,
//! using the compression engine to find the best compression level
//! for each memory.

use cortex_core::errors::CortexResult;
use cortex_core::models::CompressedMemory;
use cortex_core::traits::ICompressor;

use crate::ranking::scorer::ScoredCandidate;

/// Pack scored candidates into a token budget using hierarchical compression.
///
/// Higher-scored candidates get higher compression levels (more detail).
/// Returns compressed memories that fit within the budget, preserving score order.
pub fn pack(
    candidates: &[ScoredCandidate],
    budget: usize,
    compressor: &dyn ICompressor,
) -> CortexResult<Vec<CompressedMemory>> {
    if candidates.is_empty() || budget == 0 {
        return Ok(Vec::new());
    }

    let mut remaining = budget;
    let mut result = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        if remaining == 0 {
            break;
        }

        // Compress to fit remaining budget.
        let mut compressed = compressor.compress_to_fit(&candidate.memory, remaining)?;
        compressed.relevance_score = candidate.score;

        if compressed.token_count <= remaining {
            remaining -= compressed.token_count;
            result.push(compressed);
        }
    }

    Ok(result)
}

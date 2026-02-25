//! sqlite-vec similarity search with cosine distance, pre-filtering, and Matryoshka truncated dims.

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::traits::IMemoryStorage;

/// Result from vector similarity search.
#[derive(Debug, Clone)]
pub struct VectorResult {
    pub memory: BaseMemory,
    /// Cosine similarity score [0.0, 1.0].
    pub similarity: f64,
    /// Positional rank in the result set.
    pub rank: usize,
}

/// Run vector similarity search using a pre-computed query embedding.
/// Returns results ordered by cosine similarity descending.
pub fn search_vector(
    storage: &dyn IMemoryStorage,
    query_embedding: &[f32],
    limit: usize,
) -> CortexResult<Vec<VectorResult>> {
    if query_embedding.is_empty() {
        return Ok(Vec::new());
    }

    let results = storage.search_vector(query_embedding, limit)?;

    Ok(results
        .into_iter()
        .enumerate()
        .map(|(rank, (memory, similarity))| VectorResult {
            memory,
            similarity,
            rank,
        })
        .collect())
}

//! FTS5 full-text search with BM25 scoring and snippet extraction.

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::traits::IMemoryStorage;

/// Result from FTS5 search with BM25 rank.
#[derive(Debug, Clone)]
pub struct Fts5Result {
    pub memory: BaseMemory,
    /// BM25 rank (lower = more relevant in SQLite FTS5).
    pub rank: usize,
}

/// Run FTS5 full-text search against the storage layer.
/// Returns results ranked by BM25 relevance with positional rank.
pub fn search_fts5(
    storage: &dyn IMemoryStorage,
    query: &str,
    limit: usize,
) -> CortexResult<Vec<Fts5Result>> {
    if query.trim().is_empty() {
        return Ok(Vec::new());
    }

    let memories = storage.search_fts5(query, limit)?;

    // Storage already returns BM25-ranked results; assign positional rank.
    Ok(memories
        .into_iter()
        .enumerate()
        .map(|(rank, memory)| Fts5Result { memory, rank })
        .collect())
}

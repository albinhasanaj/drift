//! Reciprocal Rank Fusion: score = Σ 1/(k + rank_i)
//!
//! Combines multiple ranked lists into a single fused ranking without
//! requiring score normalization across different retrieval methods.

use std::collections::HashMap;

use cortex_core::memory::BaseMemory;

/// A candidate after RRF fusion, with per-source rank provenance.
#[derive(Debug, Clone)]
pub struct RrfCandidate {
    pub memory: BaseMemory,
    /// Fused RRF score (higher = more relevant).
    pub rrf_score: f64,
    /// BM25 positional rank from FTS5 search (None if not in FTS5 results).
    pub fts5_rank: Option<usize>,
    /// Positional rank from vector similarity search (None if not in vector results).
    pub vector_rank: Option<usize>,
    /// Positional rank from entity expansion (None if not in entity results).
    pub entity_rank: Option<usize>,
}

/// Fuse labeled ranked result lists using Reciprocal Rank Fusion.
///
/// `k` is the smoothing constant (default 60). Higher k reduces the
/// influence of high-ranking items from any single list.
///
/// Each input is an optional list of (memory_id, rank) pairs from a specific retrieval method.
/// The `memories` map provides the actual BaseMemory objects by ID.
pub fn fuse(
    fts5_list: Option<&Vec<(String, usize)>>,
    vector_list: Option<&Vec<(String, usize)>>,
    entity_list: Option<&Vec<(String, usize)>>,
    memories: &HashMap<String, BaseMemory>,
    k: u32,
) -> Vec<RrfCandidate> {
    let mut scores: HashMap<String, f64> = HashMap::new();
    let mut fts5_ranks: HashMap<String, usize> = HashMap::new();
    let mut vector_ranks: HashMap<String, usize> = HashMap::new();
    let mut entity_ranks: HashMap<String, usize> = HashMap::new();

    if let Some(list) = fts5_list {
        for (memory_id, rank) in list {
            let rrf = 1.0 / (k as f64 + *rank as f64);
            *scores.entry(memory_id.clone()).or_default() += rrf;
            fts5_ranks.insert(memory_id.clone(), *rank);
        }
    }

    if let Some(list) = vector_list {
        for (memory_id, rank) in list {
            let rrf = 1.0 / (k as f64 + *rank as f64);
            *scores.entry(memory_id.clone()).or_default() += rrf;
            vector_ranks.insert(memory_id.clone(), *rank);
        }
    }

    if let Some(list) = entity_list {
        for (memory_id, rank) in list {
            let rrf = 1.0 / (k as f64 + *rank as f64);
            *scores.entry(memory_id.clone()).or_default() += rrf;
            entity_ranks.insert(memory_id.clone(), *rank);
        }
    }

    let mut candidates: Vec<RrfCandidate> = scores
        .into_iter()
        .filter_map(|(id, rrf_score)| {
            memories.get(&id).map(|memory| RrfCandidate {
                memory: memory.clone(),
                rrf_score,
                fts5_rank: fts5_ranks.get(&id).copied(),
                vector_rank: vector_ranks.get(&id).copied(),
                entity_rank: entity_ranks.get(&id).copied(),
            })
        })
        .collect();

    // Sort by RRF score descending (monotonically decreasing).
    candidates.sort_by(|a, b| {
        b.rrf_score
            .partial_cmp(&a.rrf_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    candidates
}

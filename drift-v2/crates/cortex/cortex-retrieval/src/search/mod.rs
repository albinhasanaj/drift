//! HybridSearcher coordinating FTS5 + vector + RRF + entity expansion.

pub mod entity_search;
pub mod fts5_search;
pub mod rrf_fusion;
pub mod vector_search;

use std::collections::HashMap;

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::traits::IMemoryStorage;

use rrf_fusion::RrfCandidate;

/// Hybrid search combining FTS5, vector similarity, and entity expansion
/// via Reciprocal Rank Fusion.
pub struct HybridSearcher<'a> {
    storage: &'a dyn IMemoryStorage,
    /// RRF smoothing constant (default 60).
    rrf_k: u32,
}

impl<'a> HybridSearcher<'a> {
    pub fn new(storage: &'a dyn IMemoryStorage, rrf_k: u32) -> Self {
        Self { storage, rrf_k }
    }

    /// Run hybrid search: FTS5 + vector + entity expansion, fused via RRF.
    ///
    /// Returns candidates sorted by fused RRF score (descending).
    /// `query_embedding` may be `None` if embedding generation failed (graceful degradation).
    pub fn search(
        &self,
        query: &str,
        query_embedding: Option<&[f32]>,
        limit: usize,
    ) -> CortexResult<Vec<RrfCandidate>> {
        if query.trim().is_empty() && query_embedding.is_none() {
            return Ok(Vec::new());
        }

        let candidate_limit = limit * 3; // Over-fetch for fusion.
        let mut fts5_ranked: Option<Vec<(String, usize)>> = None;
        let mut vector_ranked: Option<Vec<(String, usize)>> = None;
        let mut entity_ranked: Option<Vec<(String, usize)>> = None;
        let mut memory_map: HashMap<String, BaseMemory> = HashMap::new();

        // Stage 1a: FTS5 full-text search.
        if !query.trim().is_empty() {
            let fts_results = fts5_search::search_fts5(self.storage, query, candidate_limit)?;
            let ranked: Vec<(String, usize)> = fts_results
                .iter()
                .map(|r| (r.memory.id.clone(), r.rank))
                .collect();
            for r in fts_results {
                memory_map.entry(r.memory.id.clone()).or_insert(r.memory);
            }
            fts5_ranked = Some(ranked);
        }

        // Stage 1b: Vector similarity search.
        if let Some(embedding) = query_embedding {
            let vec_results =
                vector_search::search_vector(self.storage, embedding, candidate_limit)?;
            let ranked: Vec<(String, usize)> = vec_results
                .iter()
                .map(|r| (r.memory.id.clone(), r.rank))
                .collect();
            for r in vec_results {
                memory_map.entry(r.memory.id.clone()).or_insert(r.memory);
            }
            vector_ranked = Some(ranked);
        }

        // Stage 1c: Entity expansion from top FTS5/vector results.
        let seed_memories: Vec<BaseMemory> = memory_map
            .values()
            .take(5) // Use top 5 as seeds.
            .cloned()
            .collect();

        if !seed_memories.is_empty() {
            let entity_results =
                entity_search::expand_entities(self.storage, &seed_memories, candidate_limit)?;
            let ranked: Vec<(String, usize)> = entity_results
                .iter()
                .enumerate()
                .map(|(rank, r)| (r.memory.id.clone(), rank))
                .collect();
            for r in entity_results {
                memory_map.entry(r.memory.id.clone()).or_insert(r.memory);
            }
            entity_ranked = Some(ranked);
        }

        // Stage 2: RRF fusion with labeled source lists.
        let mut candidates = rrf_fusion::fuse(
            fts5_ranked.as_ref(),
            vector_ranked.as_ref(),
            entity_ranked.as_ref(),
            &memory_map,
            self.rrf_k,
        );
        candidates.truncate(limit);

        Ok(candidates)
    }
}

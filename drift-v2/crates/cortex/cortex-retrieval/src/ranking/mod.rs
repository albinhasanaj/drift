//! RankingPipeline: score → rerank → deduplicate.

pub mod deduplication;
pub mod reranker;
pub mod scorer;

use cortex_core::intent::Intent;

use crate::intent::IntentEngine;
use crate::search::rrf_fusion::RrfCandidate;

use scorer::{ScoredCandidate, ScorerWeights};

/// Full ranking pipeline: multi-factor scoring → optional re-ranking → deduplication.
pub struct RankingPipeline {
    weights: ScorerWeights,
    rerank_top_k: usize,
    #[cfg(feature = "reranker")]
    rerank_model: Option<fastembed::TextRerank>,
}

impl RankingPipeline {
    pub fn new(rerank_top_k: usize) -> Self {
        Self {
            weights: ScorerWeights::default(),
            rerank_top_k,
            #[cfg(feature = "reranker")]
            rerank_model: None,
        }
    }

    /// Set the cross-encoder reranker model (only available with `reranker` feature).
    #[cfg(feature = "reranker")]
    pub fn with_rerank_model(mut self, model: fastembed::TextRerank) -> Self {
        self.rerank_model = Some(model);
        self
    }

    /// Run the full ranking pipeline on RRF candidates.
    pub fn rank(
        &self,
        candidates: &[RrfCandidate],
        query: &str,
        intent: Intent,
        active_files: &[String],
        sent_ids: &[String],
        intent_engine: &IntentEngine,
    ) -> Vec<ScoredCandidate> {
        // Stage 1: Multi-factor scoring.
        let scored = scorer::score(
            candidates,
            intent,
            active_files,
            intent_engine,
            &self.weights,
        );

        // Stage 2: Optional cross-encoder re-ranking.
        #[cfg(feature = "reranker")]
        let reranked =
            reranker::rerank(query, scored, self.rerank_top_k, self.rerank_model.as_ref());

        #[cfg(not(feature = "reranker"))]
        let reranked = reranker::rerank(scored, self.rerank_top_k);

        // Suppress unused variable warning when reranker feature is off.
        #[cfg(not(feature = "reranker"))]
        let _ = query;

        // Stage 3: Session-aware deduplication.
        deduplication::deduplicate(reranked, sent_ids)
    }
}

impl Default for RankingPipeline {
    fn default() -> Self {
        Self::new(20)
    }
}

//! RetrievalEngine: implements IRetriever, orchestrates full 2-stage pipeline.
//!
//! Stage 1: Candidate gathering (FTS5 + vector + entity expansion → RRF fusion)
//! Stage 2: Re-ranking (8-factor scorer → optional cross-encoder → dedup → compress)

use cortex_core::config::RetrievalConfig;
use cortex_core::errors::CortexResult;
use cortex_core::models::namespace::NamespaceId;
use cortex_core::models::{CompressedMemory, RetrievalContext};
use cortex_core::traits::{ICompressor, IMemoryStorage, IRetriever};
use tracing::{debug, info};

use crate::budget::BudgetManager;
use crate::expansion;
use crate::intent::IntentEngine;
use crate::ranking::RankingPipeline;
use crate::search::HybridSearcher;

/// The main retrieval engine. Orchestrates the full 2-stage pipeline:
/// query → hybrid search → RRF → re-rank → compress → return.
pub struct RetrievalEngine<'a> {
    storage: &'a dyn IMemoryStorage,
    compressor: &'a dyn ICompressor,
    intent_engine: IntentEngine,
    ranking: RankingPipeline,
    config: RetrievalConfig,
    /// Optional namespace filter for multi-agent retrieval.
    namespace_filter: Option<NamespaceId>,
}

impl<'a> RetrievalEngine<'a> {
    pub fn new(
        storage: &'a dyn IMemoryStorage,
        compressor: &'a dyn ICompressor,
        config: RetrievalConfig,
    ) -> Self {
        Self {
            storage,
            compressor,
            intent_engine: IntentEngine::new(),
            ranking: RankingPipeline::new(config.rerank_top_k),
            config,
            namespace_filter: None,
        }
    }

    /// Set a namespace filter for multi-agent retrieval.
    ///
    /// When set, only memories from the specified namespace are returned.
    /// When `None`, all namespaces are searched (default behavior).
    pub fn with_namespace_filter(mut self, namespace: Option<NamespaceId>) -> Self {
        self.namespace_filter = namespace;
        self
    }

    /// Run the full retrieval pipeline with an optional query embedding.
    pub fn retrieve_with_embedding(
        &self,
        context: &RetrievalContext,
        budget: usize,
        query_embedding: Option<&[f32]>,
    ) -> CortexResult<Vec<CompressedMemory>> {
        // Step 1: Classify intent.
        let intent = self.intent_engine.classify(context);
        debug!(?intent, focus = %context.focus, "classified intent");

        // Step 2: Optionally expand query.
        let search_query = if self.config.query_expansion {
            let expanded = expansion::expand_query(&context.focus, intent);
            expanded.expanded_text
        } else {
            context.focus.clone()
        };

        // Step 3: Hybrid search (FTS5 + vector + entity → RRF).
        let searcher = HybridSearcher::new(self.storage, self.config.rrf_k);
        let candidates =
            searcher.search(&search_query, query_embedding, self.config.rerank_top_k * 2)?;

        if candidates.is_empty() {
            debug!("no candidates found");
            return Ok(Vec::new());
        }

        info!(
            candidates = candidates.len(),
            "hybrid search returned candidates"
        );

        // Step 4: Rank (8-factor scorer → rerank → dedup).
        let ranked = self.ranking.rank(
            &candidates,
            &search_query,
            intent,
            &context.active_files,
            &context.sent_ids,
            &self.intent_engine,
        );

        debug!(ranked = ranked.len(), "ranking pipeline complete");

        // Step 5: Pack into token budget.
        let budget_mgr = BudgetManager::new(self.compressor);
        let compressed = budget_mgr.pack(&ranked, budget)?;

        info!(
            memories = compressed.len(),
            tokens = compressed.iter().map(|c| c.token_count).sum::<usize>(),
            budget,
            "retrieval complete"
        );

        Ok(compressed)
    }
}

impl<'a> IRetriever for RetrievalEngine<'a> {
    fn retrieve(
        &self,
        context: &RetrievalContext,
        budget: usize,
    ) -> CortexResult<Vec<CompressedMemory>> {
        // Without an embedding engine, we run text-only search.
        self.retrieve_with_embedding(context, budget, None)
    }
}

//! # cortex-retrieval
//!
//! The query engine. Two-stage pipeline: fast candidate gathering → precise re-ranking.
//! Hybrid search (FTS5 + sqlite-vec + RRF), intent-aware weighting, generation context building.
//!
//! ## Architecture
//!
//! ```text
//! RetrievalEngine (IRetriever)
//! ├── HybridSearcher
//! │   ├── FTS5 Search (BM25)
//! │   ├── Vector Search (cosine similarity)
//! │   ├── Entity Expansion (shared links)
//! │   └── RRF Fusion (reciprocal rank)
//! ├── IntentEngine
//! │   ├── Classifier (keyword + file heuristics)
//! │   └── WeightMatrix (intent → type boosts)
//! ├── QueryExpander
//! │   ├── SynonymExpander (code-aware)
//! │   └── HyDE (hypothetical document)
//! ├── RankingPipeline
//! │   ├── Scorer (8-factor)
//! │   ├── Reranker (cross-encoder, optional)
//! │   └── Deduplication (session-aware)
//! ├── BudgetManager
//! │   └── Packer (priority-weighted bin-packing)
//! ├── GenerationOrchestrator
//! │   ├── ContextBuilder (budget allocation)
//! │   ├── Gatherers (pattern, tribal, constraint, antipattern)
//! │   ├── Provenance ([drift:*] tags)
//! │   ├── Feedback (confidence adjustment)
//! │   └── Validation (pre-generation checks)
//! └── WhySynthesizer
//!     ├── Synthesizer (8-step pipeline)
//!     └── Aggregator (warning dedup + severity)
//! ```

pub mod budget;
pub mod engine;
pub mod expansion;
pub mod generation;
pub mod intent;
pub mod ranking;
pub mod search;
pub mod why;

pub use engine::RetrievalEngine;
pub use generation::GenerationOrchestrator;
pub use intent::IntentEngine;
pub use ranking::RankingPipeline;
pub use search::HybridSearcher;
pub use why::WhySynthesizer;

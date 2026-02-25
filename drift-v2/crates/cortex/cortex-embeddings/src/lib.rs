//! # cortex-embeddings
//!
//! Multi-provider embedding generation with 3-tier cache.
//! Supports ONNX (Jina Code v2), cloud APIs, Ollama, and TF-IDF fallback.
//! Matryoshka dimension truncation for fast search + full dims for re-ranking.
//!
//! ## Architecture
//!
//! ```text
//! EmbeddingEngine
//! ├── DegradationChain (provider fallback)
//! │   ├── OnnxProvider (default, local)
//! │   ├── ApiProvider (cloud, highest quality)
//! │   ├── OllamaProvider (local, flexible)
//! │   └── TfIdfFallback (always available)
//! ├── CacheCoordinator (3-tier)
//! │   ├── L3 Precomputed (zero-latency)
//! │   ├── L1 Memory (moka, sub-μs)
//! │   └── L2 SQLite (persistent, ms)
//! ├── Enrichment (metadata prefix)
//! └── Matryoshka (dimension truncation)
//! ```

pub mod cache;
pub mod degradation;
pub mod engine;
pub mod enrichment;
pub mod matryoshka;
pub mod migration;
pub mod providers;

pub use cache::{CacheCoordinator, CacheHitTier};
pub use degradation::DegradationChain;
pub use engine::EmbeddingEngine;
pub use migration::{DetectionResult, MigrationProgress, MigrationStatus, ProgressSnapshot};
pub use providers::{ApiModel, ApiProvider, OllamaProvider, OnnxProvider, TfIdfFallback};

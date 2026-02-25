//! Fallback chain for embedding generation.
//!
//! Chain: ONNX → fallback model → cached embeddings → TF-IDF → error.
//! Every fallback is logged to the degradation log.

use chrono::Utc;
use cortex_core::errors::{CortexResult, EmbeddingError};
use cortex_core::models::DegradationEvent;
use cortex_core::traits::IEmbeddingProvider;
use tracing::warn;

/// A provider entry in the fallback chain.
struct ChainEntry {
    provider: Box<dyn IEmbeddingProvider>,
}

/// Manages the degradation fallback chain for embedding providers.
///
/// Tries providers in order. On failure, logs a degradation event and
/// moves to the next provider.
pub struct DegradationChain {
    chain: Vec<ChainEntry>,
    /// Accumulated degradation events for the current session.
    events: Vec<DegradationEvent>,
}

impl Default for DegradationChain {
    fn default() -> Self {
        Self::new()
    }
}

impl DegradationChain {
    /// Create a new chain with the given providers in priority order.
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Add a provider to the end of the chain.
    pub fn push(&mut self, provider: Box<dyn IEmbeddingProvider>) {
        self.chain.push(ChainEntry { provider });
    }

    /// Add a cache-only fallback provider.
    pub fn push_cache_fallback(&mut self, provider: Box<dyn IEmbeddingProvider>) {
        self.chain.push(ChainEntry { provider });
    }

    /// D-02: Try to embed using the chain without mutation (no event tracking).
    /// Used by the `IEmbeddingProvider` trait impl which requires `&self`.
    pub fn embed_readonly(&self, text: &str) -> CortexResult<Vec<f32>> {
        for entry in &self.chain {
            if !entry.provider.is_available() {
                continue;
            }
            match entry.provider.embed(text) {
                Ok(embedding) => return Ok(embedding),
                Err(_) => continue,
            }
        }
        Err(EmbeddingError::ProviderUnavailable {
            provider: format!("all {} providers failed", self.chain.len()),
        }
        .into())
    }

    /// Try to embed text using the fallback chain.
    ///
    /// Returns the embedding from the first successful provider.
    /// Logs a `DegradationEvent` for each fallback.
    pub fn embed(&mut self, text: &str) -> CortexResult<(Vec<f32>, &str)> {
        let mut last_error = None;

        for (i, entry) in self.chain.iter().enumerate() {
            if !entry.provider.is_available() {
                continue;
            }

            match entry.provider.embed(text) {
                Ok(vec) => {
                    if i > 0 {
                        // We fell back — log it.
                        let primary_name = self
                            .chain
                            .first()
                            .map(|e| e.provider.name())
                            .unwrap_or("unknown");
                        self.events.push(DegradationEvent {
                            component: "embeddings".to_string(),
                            failure: format!("{primary_name} unavailable"),
                            fallback_used: entry.provider.name().to_string(),
                            timestamp: Utc::now(),
                        });
                    }
                    return Ok((vec, entry.provider.name()));
                }
                Err(e) => {
                    warn!(
                        provider = entry.provider.name(),
                        error = %e,
                        "provider failed, trying next in chain"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            EmbeddingError::ProviderUnavailable {
                provider: "all providers exhausted".to_string(),
            }
            .into()
        }))
    }

    /// Try to embed a batch using the fallback chain.
    pub fn embed_batch(&mut self, texts: &[String]) -> CortexResult<(Vec<Vec<f32>>, &str)> {
        let mut last_error = None;

        for (i, entry) in self.chain.iter().enumerate() {
            if !entry.provider.is_available() {
                continue;
            }

            match entry.provider.embed_batch(texts) {
                Ok(vecs) => {
                    if i > 0 {
                        let primary_name = self
                            .chain
                            .first()
                            .map(|e| e.provider.name())
                            .unwrap_or("unknown");
                        self.events.push(DegradationEvent {
                            component: "embeddings".to_string(),
                            failure: format!("{primary_name} unavailable"),
                            fallback_used: entry.provider.name().to_string(),
                            timestamp: Utc::now(),
                        });
                    }
                    return Ok((vecs, entry.provider.name()));
                }
                Err(e) => {
                    warn!(
                        provider = entry.provider.name(),
                        error = %e,
                        "batch embed failed, trying next in chain"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            EmbeddingError::ProviderUnavailable {
                provider: "all providers exhausted".to_string(),
            }
            .into()
        }))
    }

    /// Get the name of the currently active (first available) provider.
    pub fn active_provider_name(&self) -> &str {
        self.chain
            .iter()
            .find(|e| e.provider.is_available())
            .map(|e| e.provider.name())
            .unwrap_or("none")
    }

    /// Drain accumulated degradation events.
    pub fn drain_events(&mut self) -> Vec<DegradationEvent> {
        std::mem::take(&mut self.events)
    }

    /// Number of providers in the chain.
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock provider that always fails.
    struct FailingProvider;
    impl IEmbeddingProvider for FailingProvider {
        fn embed(&self, _text: &str) -> CortexResult<Vec<f32>> {
            Err(EmbeddingError::InferenceFailed {
                reason: "mock failure".to_string(),
            }
            .into())
        }
        fn embed_batch(&self, _texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
            Err(EmbeddingError::InferenceFailed {
                reason: "mock failure".to_string(),
            }
            .into())
        }
        fn dimensions(&self) -> usize {
            128
        }
        fn name(&self) -> &str {
            "failing-mock"
        }
        fn is_available(&self) -> bool {
            true
        }
    }

    /// A mock provider that always succeeds.
    struct SuccessProvider {
        name: String,
        dims: usize,
    }
    impl IEmbeddingProvider for SuccessProvider {
        fn embed(&self, _text: &str) -> CortexResult<Vec<f32>> {
            Ok(vec![1.0; self.dims])
        }
        fn embed_batch(&self, texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
            Ok(texts.iter().map(|_| vec![1.0; self.dims]).collect())
        }
        fn dimensions(&self) -> usize {
            self.dims
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn is_available(&self) -> bool {
            true
        }
    }

    #[test]
    fn primary_succeeds_no_degradation() {
        let mut chain = DegradationChain::new();
        chain.push(Box::new(SuccessProvider {
            name: "primary".to_string(),
            dims: 128,
        }));
        chain.push(Box::new(SuccessProvider {
            name: "fallback".to_string(),
            dims: 128,
        }));

        let (vec, name) = chain.embed("test").unwrap();
        assert_eq!(name, "primary");
        assert_eq!(vec.len(), 128);
        assert!(chain.drain_events().is_empty());
    }

    #[test]
    fn fallback_on_primary_failure() {
        let mut chain = DegradationChain::new();
        chain.push(Box::new(FailingProvider));
        chain.push(Box::new(SuccessProvider {
            name: "fallback".to_string(),
            dims: 64,
        }));

        let (vec, name) = chain.embed("test").unwrap();
        assert_eq!(name, "fallback");
        assert_eq!(vec.len(), 64);

        let events = chain.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fallback_used, "fallback");
    }

    #[test]
    fn all_fail_returns_error() {
        let mut chain = DegradationChain::new();
        chain.push(Box::new(FailingProvider));
        chain.push(Box::new(FailingProvider));

        let result = chain.embed("test");
        assert!(result.is_err());
    }

    #[test]
    fn batch_fallback() {
        let mut chain = DegradationChain::new();
        chain.push(Box::new(FailingProvider));
        chain.push(Box::new(SuccessProvider {
            name: "batch-fallback".to_string(),
            dims: 32,
        }));

        let texts = vec!["a".to_string(), "b".to_string()];
        let (vecs, name) = chain.embed_batch(&texts).unwrap();
        assert_eq!(name, "batch-fallback");
        assert_eq!(vecs.len(), 2);
    }
}

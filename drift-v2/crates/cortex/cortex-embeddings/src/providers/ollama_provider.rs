//! Ollama local embedding provider.
//!
//! Connects to a local Ollama instance for embedding generation.
//! Configurable model, health check on startup.

use std::sync::atomic::{AtomicBool, Ordering};

use cortex_core::errors::{CortexResult, EmbeddingError};
use cortex_core::traits::IEmbeddingProvider;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Ollama local embedding provider.
pub struct OllamaProvider {
    base_url: String,
    model: String,
    dimensions: usize,
    available: AtomicBool,
}

#[derive(Serialize)]
struct OllamaEmbedRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Deserialize)]
struct OllamaEmbedResponse {
    embeddings: Vec<Vec<f32>>,
}

impl OllamaProvider {
    /// Create a new Ollama provider.
    ///
    /// `base_url` defaults to `http://localhost:11434` if `None`.
    pub fn new(model: String, dimensions: usize, base_url: Option<String>) -> Self {
        Self {
            base_url: base_url.unwrap_or_else(|| "http://localhost:11434".to_string()),
            model,
            dimensions,
            available: AtomicBool::new(false), // Must pass health check first.
        }
    }

    /// Check if the Ollama server is reachable.
    pub fn health_check(&self) -> bool {
        let url = format!("{}/api/tags", self.base_url);

        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return false,
        };

        let result = rt.block_on(async {
            let client = reqwest::Client::new();
            client
                .get(&url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
        });

        match result {
            Ok(resp) if resp.status().is_success() => {
                self.available.store(true, Ordering::Relaxed);
                debug!(model = %self.model, "Ollama health check passed");
                true
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Ollama health check failed");
                self.available.store(false, Ordering::Relaxed);
                false
            }
            Err(e) => {
                warn!(error = %e, "Ollama unreachable");
                self.available.store(false, Ordering::Relaxed);
                false
            }
        }
    }

    fn request_embeddings(&self, texts: Vec<String>) -> CortexResult<Vec<Vec<f32>>> {
        if !self.available.load(Ordering::Relaxed) {
            return Err(EmbeddingError::ProviderUnavailable {
                provider: self.name().to_string(),
            }
            .into());
        }

        let url = format!("{}/api/embed", self.base_url);
        let request = OllamaEmbedRequest {
            model: self.model.clone(),
            input: texts,
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| EmbeddingError::InferenceFailed {
                reason: format!("runtime error: {e}"),
            })?;

        let dims = self.dimensions;
        let result: CortexResult<Vec<Vec<f32>>> = rt.block_on(async {
            let client = reqwest::Client::new();
            let response = client.post(&url).json(&request).send().await.map_err(|e| {
                EmbeddingError::InferenceFailed {
                    reason: format!("Ollama HTTP error: {e}"),
                }
            })?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(EmbeddingError::InferenceFailed {
                    reason: format!("Ollama returned {status}: {body}"),
                }
                .into());
            }

            let resp: OllamaEmbedResponse =
                response
                    .json()
                    .await
                    .map_err(|e| EmbeddingError::InferenceFailed {
                        reason: format!("Ollama JSON parse error: {e}"),
                    })?;

            let embeddings: Vec<Vec<f32>> = resp
                .embeddings
                .into_iter()
                .map(|mut v: Vec<f32>| {
                    v.resize(dims, 0.0);
                    v
                })
                .collect();

            Ok(embeddings)
        });

        result
    }
}

impl IEmbeddingProvider for OllamaProvider {
    fn embed(&self, text: &str) -> CortexResult<Vec<f32>> {
        let results = self.request_embeddings(vec![text.to_string()])?;
        results.into_iter().next().ok_or_else(|| {
            EmbeddingError::InferenceFailed {
                reason: "empty Ollama response".to_string(),
            }
            .into()
        })
    }

    fn embed_batch(&self, texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
        self.request_embeddings(texts.to_vec())
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn name(&self) -> &str {
        &self.model
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed)
    }
}

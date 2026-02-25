//! Cloud API embedding provider.
//!
//! HTTP client for cloud embedding APIs (Codestral Embed, VoyageCode3,
//! OpenAI text-embedding-3-large). Includes rate limiting and retry with
//! exponential backoff.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cortex_core::errors::{CortexResult, EmbeddingError};
use cortex_core::traits::IEmbeddingProvider;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Supported cloud embedding API providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiModel {
    /// Codestral Embed (Mistral) — SOTA on SWE-Bench, Matryoshka support.
    CodestralEmbed,
    /// VoyageCode3 — 32K context, 2048 dims, 300+ languages.
    VoyageCode3,
    /// OpenAI text-embedding-3-large — general purpose fallback.
    OpenAiLarge,
}

impl ApiModel {
    pub fn default_dimensions(&self) -> usize {
        match self {
            Self::CodestralEmbed => 1024,
            Self::VoyageCode3 => 2048,
            Self::OpenAiLarge => 3072,
        }
    }

    pub fn model_name(&self) -> &'static str {
        match self {
            Self::CodestralEmbed => "codestral-embed",
            Self::VoyageCode3 => "voyage-code-3",
            Self::OpenAiLarge => "text-embedding-3-large",
        }
    }
}

/// Cloud API embedding provider with rate limiting and retry.
pub struct ApiProvider {
    model: ApiModel,
    api_key: String,
    endpoint: String,
    dimensions: usize,
    available: AtomicBool,
    max_retries: u32,
}

#[derive(Serialize)]
struct EmbedRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Deserialize)]
struct EmbedResponse {
    data: Vec<EmbedData>,
}

#[derive(Deserialize)]
struct EmbedData {
    embedding: Vec<f32>,
}

impl ApiProvider {
    /// Create a new API provider.
    pub fn new(
        model: ApiModel,
        api_key: String,
        endpoint: Option<String>,
        dimensions: Option<usize>,
    ) -> Self {
        let default_endpoint = match model {
            ApiModel::CodestralEmbed => "https://api.mistral.ai/v1/embeddings",
            ApiModel::VoyageCode3 => "https://api.voyageai.com/v1/embeddings",
            ApiModel::OpenAiLarge => "https://api.openai.com/v1/embeddings",
        };

        Self {
            dimensions: dimensions.unwrap_or_else(|| model.default_dimensions()),
            endpoint: endpoint.unwrap_or_else(|| default_endpoint.to_string()),
            model,
            api_key,
            available: AtomicBool::new(true),
            max_retries: 3,
        }
    }

    /// Send an embedding request with retry and exponential backoff.
    fn request_embeddings(&self, texts: Vec<String>) -> CortexResult<Vec<Vec<f32>>> {
        if !self.available.load(Ordering::Relaxed) {
            return Err(EmbeddingError::ProviderUnavailable {
                provider: self.name().to_string(),
            }
            .into());
        }

        let body = serde_json::to_string(&EmbedRequest {
            model: self.model.model_name().to_string(),
            input: texts,
        })
        .map_err(|e| EmbeddingError::InferenceFailed {
            reason: format!("JSON serialization error: {e}"),
        })?;

        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = Duration::from_millis(100 * 2u64.pow(attempt - 1));
                std::thread::sleep(delay);
                debug!(attempt, "retrying API embedding request");
            }

            match self.send_request(&body) {
                Ok(embeddings) => return Ok(embeddings),
                Err(e) => {
                    warn!(attempt, error = %e, "API embedding request failed");
                    last_err = Some(e);
                }
            }
        }

        self.available.store(false, Ordering::Relaxed);
        Err(last_err.unwrap_or_else(|| {
            EmbeddingError::InferenceFailed {
                reason: "all retries exhausted".to_string(),
            }
            .into()
        }))
    }

    /// Send a single HTTP request. Uses ureq-style blocking via tokio runtime
    /// or falls back to a simple TCP approach. For the sync IEmbeddingProvider
    /// trait, we spawn a blocking tokio task.
    fn send_request(&self, body: &str) -> CortexResult<Vec<Vec<f32>>> {
        // Use tokio's current-thread runtime for the blocking HTTP call.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| EmbeddingError::InferenceFailed {
                reason: format!("runtime error: {e}"),
            })?;

        let client = reqwest::Client::new();
        let endpoint = self.endpoint.clone();
        let api_key = self.api_key.clone();
        let body_owned = body.to_string();
        let dims = self.dimensions;

        rt.block_on(async {
            let response = client
                .post(&endpoint)
                .header("Authorization", format!("Bearer {api_key}"))
                .header("Content-Type", "application/json")
                .body(body_owned)
                .send()
                .await
                .map_err(|e| EmbeddingError::InferenceFailed {
                    reason: format!("HTTP error: {e}"),
                })?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(EmbeddingError::InferenceFailed {
                    reason: format!("API returned {status}: {body}"),
                }
                .into());
            }

            let resp: EmbedResponse =
                response
                    .json()
                    .await
                    .map_err(|e| EmbeddingError::InferenceFailed {
                        reason: format!("JSON parse error: {e}"),
                    })?;

            let embeddings: Vec<Vec<f32>> = resp
                .data
                .into_iter()
                .map(|d| {
                    let mut v = d.embedding;
                    v.resize(dims, 0.0);
                    v
                })
                .collect();

            Ok(embeddings)
        })
    }

    /// Reset availability (e.g., after a config change or health check).
    pub fn reset_availability(&self) {
        self.available.store(true, Ordering::Relaxed);
    }
}

impl IEmbeddingProvider for ApiProvider {
    fn embed(&self, text: &str) -> CortexResult<Vec<f32>> {
        let results = self.request_embeddings(vec![text.to_string()])?;
        results.into_iter().next().ok_or_else(|| {
            EmbeddingError::InferenceFailed {
                reason: "empty response".to_string(),
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
        self.model.model_name()
    }

    fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed)
    }
}

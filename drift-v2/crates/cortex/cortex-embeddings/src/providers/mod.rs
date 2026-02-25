//! Provider registry and auto-detection.
//!
//! Priority order:
//! 1. ONNX (local, fast, default)
//! 2. API (cloud, highest quality)
//! 3. Ollama (local, flexible)
//! 4. TF-IDF (always available, lowest quality)

pub mod api_provider;
pub mod ollama_provider;
pub mod onnx_provider;
pub mod tfidf_fallback;

pub use api_provider::{ApiModel, ApiProvider};
pub use ollama_provider::OllamaProvider;
pub use onnx_provider::OnnxProvider;
pub use tfidf_fallback::TfIdfFallback;

use cortex_core::config::EmbeddingConfig;
use cortex_core::traits::IEmbeddingProvider;
use tracing::{info, warn};

/// Attempt to create the configured provider, returning it boxed.
///
/// Falls back through the provider hierarchy if the primary isn't available.
pub fn create_provider(config: &EmbeddingConfig) -> Box<dyn IEmbeddingProvider> {
    match config.provider.as_str() {
        "onnx" => {
            if let Some(ref path) = config.model_path {
                match OnnxProvider::load(path, config.dimensions) {
                    Ok(p) => {
                        info!(provider = "onnx", "embedding provider loaded");
                        return Box::new(p);
                    }
                    Err(e) => {
                        warn!(error = %e, "ONNX provider failed to load, falling back");
                    }
                }
            } else {
                warn!("ONNX provider configured but no model_path set, falling back");
            }
            // Fall through to TF-IDF.
            info!(provider = "tfidf", "using TF-IDF fallback");
            Box::new(TfIdfFallback::new(config.dimensions))
        }
        "api" => {
            // API provider requires runtime configuration (API key, etc.)
            // that isn't in EmbeddingConfig. Return TF-IDF as safe default.
            warn!("API provider requires runtime configuration; using TF-IDF fallback");
            Box::new(TfIdfFallback::new(config.dimensions))
        }
        "ollama" => {
            let provider =
                OllamaProvider::new("jina-embeddings-v2".to_string(), config.dimensions, None);
            if provider.health_check() {
                info!(provider = "ollama", "embedding provider connected");
                Box::new(provider)
            } else {
                warn!("Ollama unavailable, falling back to TF-IDF");
                Box::new(TfIdfFallback::new(config.dimensions))
            }
        }
        "tfidf" => {
            info!(provider = "tfidf", "using TF-IDF embedding provider");
            Box::new(TfIdfFallback::new(config.dimensions))
        }
        _ => {
            info!(
                provider = "tfidf",
                "unknown provider, using TF-IDF fallback"
            );
            Box::new(TfIdfFallback::new(config.dimensions))
        }
    }
}

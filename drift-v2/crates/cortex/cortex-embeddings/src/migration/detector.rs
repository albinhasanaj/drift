//! Embedding model change detection.
//!
//! On startup, compares the configured model against the stored
//! `embedding_model_info` to detect dimension changes or model upgrades.

use cortex_core::config::EmbeddingConfig;
use cortex_core::models::EmbeddingModelInfo;
use tracing::info;

/// Result of model change detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionResult {
    /// No change — current model matches stored info.
    NoChange,
    /// Model changed — migration required.
    MigrationRequired {
        old_model: String,
        new_model: String,
        old_dims: usize,
        new_dims: usize,
    },
    /// No stored model info — first run, no migration needed.
    FirstRun,
}

/// Detect whether the embedding model has changed since last run.
///
/// Compares the configured model/dimensions against the stored model info.
pub fn detect_model_change(
    config: &EmbeddingConfig,
    stored_info: Option<&EmbeddingModelInfo>,
) -> DetectionResult {
    let Some(stored) = stored_info else {
        info!("no stored embedding model info — first run");
        return DetectionResult::FirstRun;
    };

    let config_model = config.provider.clone();
    let config_dims = config.dimensions;

    if stored.name == config_model && stored.dimensions == config_dims {
        DetectionResult::NoChange
    } else {
        info!(
            old_model = %stored.name,
            new_model = %config_model,
            old_dims = stored.dimensions,
            new_dims = config_dims,
            "embedding model change detected — migration required"
        );
        DetectionResult::MigrationRequired {
            old_model: stored.name.clone(),
            new_model: config_model,
            old_dims: stored.dimensions,
            new_dims: config_dims,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cortex_core::models::EmbeddingModelStatus;

    fn config(provider: &str, dims: usize) -> EmbeddingConfig {
        EmbeddingConfig {
            provider: provider.to_string(),
            dimensions: dims,
            ..Default::default()
        }
    }

    fn stored(name: &str, dims: usize) -> EmbeddingModelInfo {
        EmbeddingModelInfo {
            name: name.to_string(),
            dimensions: dims,
            status: EmbeddingModelStatus::Active,
        }
    }

    #[test]
    fn first_run() {
        let cfg = config("onnx", 1024);
        assert_eq!(detect_model_change(&cfg, None), DetectionResult::FirstRun);
    }

    #[test]
    fn no_change() {
        let cfg = config("onnx", 1024);
        let info = stored("onnx", 1024);
        assert_eq!(
            detect_model_change(&cfg, Some(&info)),
            DetectionResult::NoChange
        );
    }

    #[test]
    fn dimension_change() {
        let cfg = config("onnx", 2048);
        let info = stored("onnx", 1024);
        assert_eq!(
            detect_model_change(&cfg, Some(&info)),
            DetectionResult::MigrationRequired {
                old_model: "onnx".to_string(),
                new_model: "onnx".to_string(),
                old_dims: 1024,
                new_dims: 2048,
            }
        );
    }

    #[test]
    fn model_change() {
        let cfg = config("api", 1024);
        let info = stored("onnx", 1024);
        assert_eq!(
            detect_model_change(&cfg, Some(&info)),
            DetectionResult::MigrationRequired {
                old_model: "onnx".to_string(),
                new_model: "api".to_string(),
                old_dims: 1024,
                new_dims: 1024,
            }
        );
    }
}

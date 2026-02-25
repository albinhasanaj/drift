//! Prediction bindings: predict, preload, getCacheStats.

use napi_derive::napi;
use serde_json::json;

use cortex_core::traits::{IPredictor, PredictionSignals};

use crate::conversions::error_types;
use crate::runtime;

/// Predict which memories will be needed next.
#[napi]
pub fn cortex_prediction_predict(
    active_files: Option<Vec<String>>,
    recent_queries: Option<Vec<String>>,
    current_intent: Option<String>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let signals = PredictionSignals {
        active_files: active_files.unwrap_or_default(),
        recent_queries: recent_queries.unwrap_or_default(),
        current_intent,
    };
    let result = rt
        .prediction
        .predict(&signals)
        .map_err(error_types::to_napi_error)?;
    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize PredictionResult: {e}")))
}

/// Preload predicted memories into cache.
#[napi]
pub fn cortex_prediction_preload(
    active_files: Option<Vec<String>>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let signals = PredictionSignals {
        active_files: active_files.unwrap_or_default(),
        recent_queries: vec![],
        current_intent: None,
    };
    let result = rt
        .prediction
        .predict(&signals)
        .map_err(error_types::to_napi_error)?;
    Ok(json!({
        "preloaded_count": result.memory_ids.len(),
        "memory_ids": result.memory_ids,
        "confidence": result.confidence,
    }))
}

/// Get prediction cache statistics.
#[napi]
pub fn cortex_prediction_get_cache_stats() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let cache = rt.prediction.cache();
    Ok(json!({
        "entry_count": cache.entry_count(),
        "hits": cache.hits(),
        "misses": cache.misses(),
        "hit_rate": cache.hit_rate(),
    }))
}

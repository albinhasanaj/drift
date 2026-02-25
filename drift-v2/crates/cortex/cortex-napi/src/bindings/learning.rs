//! Learning bindings: analyzeCorrection, learn, getValidationCandidates, processFeedback.

use napi_derive::napi;

use cortex_core::traits::{Correction, ILearner, IMemoryStorage};

use crate::conversions::error_types;
use crate::runtime;

/// Analyze a correction and learn from it.
#[napi]
pub fn cortex_learning_analyze_correction(
    correction_text: String,
    context: String,
    source: String,
    original_memory_id: Option<String>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let correction = Correction {
        original_memory_id,
        correction_text,
        context,
        source,
    };
    let learning = rt
        .learning
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Learning lock poisoned: {e}")))?;
    let result = learning
        .analyze(&correction)
        .map_err(error_types::to_napi_error)?;
    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize LearningResult: {e}")))
}

/// Learn from a correction (alias for analyze_correction).
#[napi]
pub fn cortex_learning_learn(
    correction_text: String,
    context: String,
    source: String,
) -> napi::Result<serde_json::Value> {
    cortex_learning_analyze_correction(correction_text, context, source, None)
}

/// Get memories that are candidates for validation (low confidence).
#[napi]
pub fn cortex_learning_get_validation_candidates(
    min_confidence: Option<f64>,
    max_confidence: Option<f64>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let min = min_confidence.unwrap_or(0.0);
    let max = max_confidence.unwrap_or(0.5);
    let candidates = rt
        .storage
        .query_by_confidence_range(min, max)
        .map_err(error_types::to_napi_error)?;
    crate::conversions::memory_types::memories_to_json(&candidates)
}

/// Process user feedback on a memory.
#[napi]
pub fn cortex_learning_process_feedback(
    memory_id: String,
    feedback: String,
    is_positive: bool,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    // Feedback is processed as a correction with context.
    let correction = Correction {
        original_memory_id: Some(memory_id),
        correction_text: feedback,
        context: if is_positive {
            "positive_feedback".to_string()
        } else {
            "negative_feedback".to_string()
        },
        source: "user_feedback".to_string(),
    };
    let learning = rt
        .learning
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Learning lock poisoned: {e}")))?;
    let result = learning
        .analyze(&correction)
        .map_err(error_types::to_napi_error)?;
    serde_json::to_value(&result)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize LearningResult: {e}")))
}

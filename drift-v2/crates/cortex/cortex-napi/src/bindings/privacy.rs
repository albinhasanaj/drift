//! Privacy bindings: sanitize, getPatternStats.

use napi_derive::napi;
use serde_json::json;

use cortex_core::traits::ISanitizer;

use crate::runtime;

/// Sanitize text by detecting and replacing PII, secrets, and connection strings.
#[napi]
pub fn cortex_privacy_sanitize(text: String) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let result = rt
        .privacy
        .sanitize(&text)
        .map_err(|e| napi::Error::from_reason(format!("Sanitization failed: {e}")))?;
    Ok(json!({
        "text": result.text,
        "redactions": result.redactions,
    }))
}

/// Get privacy pattern statistics (which patterns are healthy).
#[napi]
pub fn cortex_privacy_get_pattern_stats() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let (_, tracker) = rt
        .privacy
        .sanitize_with_tracking("")
        .map_err(|e| napi::Error::from_reason(format!("Pattern check failed: {e}")))?;
    Ok(json!({
        "failure_count": tracker.failure_count(),
        "has_failures": tracker.has_failures(),
        "failures": tracker.failures().iter().map(|f| json!({
            "pattern_name": f.pattern_name,
            "category": f.category,
            "error": f.error,
        })).collect::<Vec<_>>(),
    }))
}

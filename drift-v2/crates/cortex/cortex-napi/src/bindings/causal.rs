//! Causal bindings: inferCause, traverse, getWhy, counterfactual, intervention.

use napi_derive::napi;

use crate::conversions::{causal_types, error_types, memory_types};
use crate::runtime;

/// Infer causal relationship between two memories.
#[napi]
pub fn cortex_causal_infer_cause(
    source_json: serde_json::Value,
    target_json: serde_json::Value,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let source = memory_types::memory_from_json(source_json)?;
    let target = memory_types::memory_from_json(target_json)?;
    let result = rt.causal.infer(&source, &target);
    // InferenceResult doesn't derive Serialize, so convert manually.
    Ok(serde_json::json!({
        "source_id": result.source_id,
        "target_id": result.target_id,
        "strength": result.strength,
        "suggested_relation": format!("{:?}", result.suggested_relation),
        "above_threshold": result.above_threshold,
    }))
}

/// Traverse causal graph from a memory (bidirectional).
#[napi]
pub fn cortex_causal_traverse(memory_id: String) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let result = rt
        .causal
        .bidirectional(&memory_id)
        .map_err(error_types::to_napi_error)?;
    Ok(causal_types::traversal_to_json(&result))
}

/// Get a causal narrative explaining "why" for a memory.
#[napi]
pub fn cortex_causal_get_why(memory_id: String) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let narrative = rt
        .causal
        .narrative(&memory_id)
        .map_err(error_types::to_napi_error)?;
    causal_types::narrative_to_json(&narrative)
}

/// Counterfactual analysis: "what if this memory didn't exist?"
#[napi]
pub fn cortex_causal_counterfactual(memory_id: String) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let result = rt
        .causal
        .counterfactual(&memory_id)
        .map_err(error_types::to_napi_error)?;
    Ok(causal_types::traversal_to_json(&result))
}

/// Intervention analysis: "what would change if we modified this?"
#[napi]
pub fn cortex_causal_intervention(memory_id: String) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let result = rt
        .causal
        .intervention(&memory_id)
        .map_err(error_types::to_napi_error)?;
    Ok(causal_types::traversal_to_json(&result))
}

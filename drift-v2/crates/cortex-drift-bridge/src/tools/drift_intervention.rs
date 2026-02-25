//! drift_intervention MCP tool: "If we change this, what breaks?"
//! Wraps causal::intervention::what_if_changed with JSON response.

use serde_json::json;

use crate::errors::BridgeResult;

/// Handle the drift_intervention MCP tool request.
///
/// Returns a JSON response with:
/// - impacted_count: number of downstream memories affected
/// - propagation_ids: list of affected memory IDs
/// - max_depth: maximum propagation depth
/// - propagation_summary: human-readable summary
pub fn handle_drift_intervention(
    memory_id: &str,
    causal_engine: Option<&cortex_causal::CausalEngine>,
) -> BridgeResult<serde_json::Value> {
    let engine = match causal_engine {
        Some(e) => e,
        None => {
            return Ok(json!({
                "memory_id": memory_id,
                "error": "Causal engine not available",
                "impacted_count": 0,
                "propagation_ids": [],
                "max_depth": 0,
                "propagation_summary": "Causal engine not available — cannot perform intervention analysis.",
            }));
        }
    };

    let result = crate::causal::what_if_changed(engine, memory_id)?;

    Ok(json!({
        "memory_id": result.memory_id,
        "impacted_count": result.impacted_count,
        "propagation_ids": result.propagation_ids,
        "max_depth": result.max_depth,
        "propagation_summary": result.propagation_summary,
    }))
}

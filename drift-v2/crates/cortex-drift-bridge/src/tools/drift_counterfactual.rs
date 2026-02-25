//! drift_counterfactual MCP tool: "What if this memory didn't exist?"
//! Wraps causal::counterfactual::what_if_removed with JSON response.

use serde_json::json;

use crate::errors::BridgeResult;

/// Handle the drift_counterfactual MCP tool request.
///
/// Returns a JSON response with:
/// - affected_count: number of downstream memories impacted
/// - affected_memory_ids: list of impacted memory IDs
/// - max_depth: maximum depth of the impact chain
/// - impact_summary: human-readable summary
pub fn handle_drift_counterfactual(
    memory_id: &str,
    causal_engine: Option<&cortex_causal::CausalEngine>,
) -> BridgeResult<serde_json::Value> {
    let engine = match causal_engine {
        Some(e) => e,
        None => {
            return Ok(json!({
                "memory_id": memory_id,
                "error": "Causal engine not available",
                "affected_count": 0,
                "affected_memory_ids": [],
                "max_depth": 0,
                "impact_summary": "Causal engine not available — cannot perform counterfactual analysis.",
            }));
        }
    };

    let result = crate::causal::what_if_removed(engine, memory_id)?;

    Ok(json!({
        "memory_id": result.memory_id,
        "affected_count": result.affected_count,
        "affected_memory_ids": result.affected_memory_ids,
        "max_depth": result.max_depth,
        "impact_summary": result.impact_summary,
    }))
}

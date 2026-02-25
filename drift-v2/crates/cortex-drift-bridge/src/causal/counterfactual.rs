//! "What if X didn't exist?" — wraps CausalEngine.counterfactual with bridge context.

use cortex_causal::CausalEngine;
use cortex_causal::TraversalResult;
use serde::{Deserialize, Serialize};

use crate::errors::BridgeResult;

/// Result of a counterfactual analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualResult {
    /// The memory being analyzed.
    pub memory_id: String,
    /// Number of downstream nodes affected.
    pub affected_count: usize,
    /// Memory IDs that would be affected.
    pub affected_memory_ids: Vec<String>,
    /// Maximum depth of the impact.
    pub max_depth: u32,
    /// Human-readable impact summary.
    pub impact_summary: String,
}

/// Analyze: "What if memory X didn't exist?"
/// Returns impact assessment: affected memories + confidence deltas.
pub fn what_if_removed(
    engine: &CausalEngine,
    memory_id: &str,
) -> BridgeResult<CounterfactualResult> {
    let traversal = engine
        .counterfactual(memory_id)
        .map_err(|e| crate::errors::BridgeError::Causal {
            operation: "counterfactual".to_string(),
            reason: e.to_string(),
        })?;

    let affected_ids: Vec<String> = traversal
        .nodes
        .iter()
        .filter(|n| n.memory_id != memory_id)
        .map(|n| n.memory_id.clone())
        .collect();

    let max_depth = traversal
        .nodes
        .iter()
        .map(|n| n.depth as u32)
        .max()
        .unwrap_or(0);

    let impact_summary = build_impact_summary(memory_id, &traversal);

    Ok(CounterfactualResult {
        memory_id: memory_id.to_string(),
        affected_count: affected_ids.len(),
        affected_memory_ids: affected_ids,
        max_depth,
        impact_summary,
    })
}

fn build_impact_summary(memory_id: &str, traversal: &TraversalResult) -> String {
    let affected = traversal.nodes.len().saturating_sub(1); // exclude self
    if affected == 0 {
        return format!("Memory '{}' has no downstream dependencies.", memory_id);
    }

    let max_depth = traversal.nodes.iter().map(|n| n.depth).max().unwrap_or(0);

    format!(
        "Removing memory '{}' would affect {} downstream memor{} across {} depth level{}.",
        memory_id,
        affected,
        if affected == 1 { "y" } else { "ies" },
        max_depth,
        if max_depth == 1 { "" } else { "s" },
    )
}

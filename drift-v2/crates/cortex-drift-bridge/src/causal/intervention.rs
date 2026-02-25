//! "If we change X, what breaks?" — wraps CausalEngine.intervention with bridge context.

use cortex_causal::CausalEngine;
use cortex_causal::TraversalResult;
use serde::{Deserialize, Serialize};

use crate::errors::BridgeResult;

/// Result of an intervention analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterventionResult {
    /// The memory being modified.
    pub memory_id: String,
    /// Number of downstream nodes that would be impacted.
    pub impacted_count: usize,
    /// Memory IDs in the propagation graph.
    pub propagation_ids: Vec<String>,
    /// Maximum propagation depth.
    pub max_depth: u32,
    /// Human-readable propagation summary.
    pub propagation_summary: String,
}

/// Analyze: "If we change memory X, what downstream effects propagate?"
pub fn what_if_changed(
    engine: &CausalEngine,
    memory_id: &str,
) -> BridgeResult<InterventionResult> {
    let traversal = engine
        .intervention(memory_id)
        .map_err(|e| crate::errors::BridgeError::Causal {
            operation: "intervention".to_string(),
            reason: e.to_string(),
        })?;

    let propagation_ids: Vec<String> = traversal
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

    let propagation_summary = build_propagation_summary(memory_id, &traversal);

    Ok(InterventionResult {
        memory_id: memory_id.to_string(),
        impacted_count: propagation_ids.len(),
        propagation_ids,
        max_depth,
        propagation_summary,
    })
}

fn build_propagation_summary(memory_id: &str, traversal: &TraversalResult) -> String {
    let impacted = traversal.nodes.len().saturating_sub(1);
    if impacted == 0 {
        return format!("Changing memory '{}' has no downstream propagation effects.", memory_id);
    }

    let max_depth = traversal.nodes.iter().map(|n| n.depth).max().unwrap_or(0);

    format!(
        "Changing memory '{}' would propagate to {} downstream memor{} across {} depth level{}.",
        memory_id,
        impacted,
        if impacted == 1 { "y" } else { "ies" },
        max_depth,
        if max_depth == 1 { "" } else { "s" },
    )
}

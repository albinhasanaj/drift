//! Prune weak/invalidated causal edges after grounding.

use cortex_causal::CausalEngine;
use serde::{Deserialize, Serialize};

use crate::errors::BridgeResult;

/// Report of a pruning operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningReport {
    /// Number of edges removed.
    pub edges_removed: usize,
    /// Minimum strength threshold used.
    pub threshold: f64,
}

/// Prune causal edges below a strength threshold.
///
/// Typically called after grounding to remove edges that are no longer
/// supported by evidence.
pub fn prune_weak_edges(
    engine: &CausalEngine,
    threshold: f64,
) -> BridgeResult<PruningReport> {
    let result = engine
        .prune(threshold)
        .map_err(|e| crate::errors::BridgeError::Causal {
            operation: "prune_weak_edges".to_string(),
            reason: e.to_string(),
        })?;

    tracing::info!(
        edges_removed = result.edges_removed,
        threshold = threshold,
        "Pruned weak causal edges"
    );

    Ok(PruningReport {
        edges_removed: result.edges_removed,
        threshold,
    })
}

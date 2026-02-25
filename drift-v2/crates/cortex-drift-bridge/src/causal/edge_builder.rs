//! Typed causal edge creation with bridge-specific defaults.

use cortex_causal::CausalEngine;
use cortex_causal::relations::CausalRelation;
use cortex_core::memory::BaseMemory;

use crate::errors::BridgeResult;
use crate::grounding::GroundingResult;
use crate::specification::corrections::{CorrectionRootCause, SpecCorrection};

/// Add a correction-caused causal edge between an upstream module and a correction memory.
pub fn add_correction_edge(
    engine: &CausalEngine,
    upstream: &BaseMemory,
    correction: &BaseMemory,
    root_cause: &CorrectionRootCause,
) -> BridgeResult<()> {
    let relation = root_cause.to_causal_relation();
    engine
        .add_edge(upstream, correction, relation, 0.8, vec![], None)
        .map_err(|e| crate::errors::BridgeError::Causal {
            operation: "add_correction_edge".to_string(),
            reason: e.to_string(),
        })?;
    Ok(())
}

/// Add a grounding evidence edge: memory → grounding result.
/// Uses `Supports` if validated, `Contradicts` if invalidated.
pub fn add_grounding_edge(
    engine: &CausalEngine,
    memory: &BaseMemory,
    grounding_result: &GroundingResult,
    grounding_memory: &BaseMemory,
) -> BridgeResult<()> {
    let relation = if grounding_result.grounding_score >= 0.7 {
        CausalRelation::Supports
    } else if grounding_result.grounding_score >= 0.4 {
        // Partial: weakly supports — still a positive signal but not strong
        CausalRelation::Supports
    } else {
        // Weak (< 0.4) and Invalidated (< 0.2): negative signal
        CausalRelation::Contradicts
    };

    engine
        .add_edge(
            memory,
            grounding_memory,
            relation,
            grounding_result.grounding_score,
            vec![],
            None,
        )
        .map_err(|e| crate::errors::BridgeError::Causal {
            operation: "add_grounding_edge".to_string(),
            reason: e.to_string(),
        })?;
    Ok(())
}

/// Add all causal edges for a spec correction (one per upstream module).
pub fn add_correction_edges(
    engine: &CausalEngine,
    correction: &SpecCorrection,
    correction_memory: &BaseMemory,
    create_placeholder: impl Fn(&str) -> BaseMemory,
) -> BridgeResult<usize> {
    let mut added = 0;
    for upstream_id in &correction.upstream_modules {
        let upstream_memory = create_placeholder(upstream_id);
        match add_correction_edge(engine, &upstream_memory, correction_memory, &correction.root_cause) {
            Ok(()) => added += 1,
            Err(e) => {
                tracing::warn!(
                    upstream = upstream_id,
                    error = %e,
                    "Failed to create causal edge for correction"
                );
            }
        }
    }
    Ok(added)
}

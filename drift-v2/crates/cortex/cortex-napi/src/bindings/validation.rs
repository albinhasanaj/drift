//! Validation NAPI bindings: run 4-dimension validation across memories.
//!
//! E-02: Provides `cortex_validation_run` — processes candidate memories through
//! the validation engine's 4 dimensions (citation, temporal, contradiction, pattern
//! alignment) and returns results with healing actions.

use napi_derive::napi;
use tracing::debug;

use cortex_core::traits::{IMemoryStorage, IValidator};

use crate::conversions::error_types;
use crate::runtime;

/// Run 4-dimension validation on candidate memories.
/// Returns JSON with validation results per memory.
#[napi]
pub fn cortex_validation_run(
    min_confidence: Option<f64>,
    max_confidence: Option<f64>,
) -> napi::Result<serde_json::Value> {
    debug!("NAPI: validation_run");

    let rt = runtime::get()?;

    let min = min_confidence.unwrap_or(0.0);
    let max = max_confidence.unwrap_or(1.0);

    // Get candidate memories in the confidence range.
    let candidates = rt
        .storage
        .query_by_confidence_range(min, max)
        .map_err(error_types::to_napi_error)?;

    let mut results = Vec::new();
    let mut passed_count = 0u64;
    let mut failed_count = 0u64;
    let mut total_healing_actions = 0u64;

    for memory in &candidates {
        if memory.archived {
            continue;
        }

        // Run basic validation (temporal + contradiction checks).
        // Full validation with file system access would require a ValidationContext.
        match rt.validation.validate(memory) {
            Ok(result) => {
                if result.passed {
                    passed_count += 1;
                } else {
                    failed_count += 1;
                }
                total_healing_actions += result.healing_actions.len() as u64;

                results.push(serde_json::json!({
                    "memory_id": result.memory_id,
                    "overall_score": result.overall_score,
                    "passed": result.passed,
                    "dimension_scores": {
                        "citation": result.dimension_scores.citation,
                        "temporal": result.dimension_scores.temporal,
                        "contradiction": result.dimension_scores.contradiction,
                        "pattern_alignment": result.dimension_scores.pattern_alignment,
                    },
                    "healing_actions": result.healing_actions.iter().map(|a| {
                        serde_json::json!({
                            "action_type": format!("{:?}", a.action_type),
                            "description": a.description,
                            "applied": a.applied,
                        })
                    }).collect::<Vec<_>>(),
                }));
            }
            Err(e) => {
                debug!(memory_id = %memory.id, error = %e, "validation failed for memory");
            }
        }
    }

    Ok(serde_json::json!({
        "total_checked": results.len(),
        "passed": passed_count,
        "failed": failed_count,
        "total_healing_actions": total_healing_actions,
        "results": results,
    }))
}

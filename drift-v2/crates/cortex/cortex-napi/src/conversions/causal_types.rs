//! CausalNarrative, TraversalResult ↔ serde_json::Value conversions.
//!
//! Neither CausalNarrative nor TraversalResult derive Serialize,
//! so we convert manually to serde_json::Value.

use cortex_causal::{CausalNarrative, TraversalResult};
use serde_json::json;

/// Serialize a CausalNarrative to JSON (manual conversion).
pub fn narrative_to_json(narrative: &CausalNarrative) -> napi::Result<serde_json::Value> {
    Ok(json!({
        "memory_id": narrative.memory_id,
        "summary": narrative.summary,
        "key_points": narrative.key_points,
        "confidence": narrative.confidence,
        "confidence_level": narrative.confidence_level.as_str(),
        "evidence_refs": narrative.evidence_refs,
        "sections": narrative.sections.iter().map(|s| json!({
            "title": s.title,
            "entries": s.entries,
        })).collect::<Vec<_>>(),
    }))
}

/// Serialize a TraversalResult to JSON (manual conversion).
pub fn traversal_to_json(result: &TraversalResult) -> serde_json::Value {
    json!({
        "origin_id": result.origin_id,
        "max_depth_reached": result.max_depth_reached,
        "nodes": result.nodes.iter().map(|n| json!({
            "memory_id": n.memory_id,
            "depth": n.depth,
            "path_strength": n.path_strength,
        })).collect::<Vec<_>>(),
    })
}

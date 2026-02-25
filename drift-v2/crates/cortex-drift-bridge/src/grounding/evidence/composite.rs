//! CompositeCollector: runs all 12 evidence collectors and merges results.

use rusqlite::Connection;

use super::collector::{collect_one, EvidenceContext};
use super::types::{EvidenceType, GroundingEvidence};
use crate::errors::BridgeResult;

/// Run all 12 evidence collectors against drift.db for a single memory.
/// Silently skips collectors that fail or return no data.
pub fn collect_all(
    ctx: &EvidenceContext,
    drift_conn: &Connection,
) -> Vec<GroundingEvidence> {
    let mut evidence = Vec::new();

    for evidence_type in EvidenceType::ALL {
        match collect_one(evidence_type, ctx, drift_conn) {
            Ok(Some(e)) => evidence.push(e),
            Ok(None) => {} // No data for this type — skip
            Err(e) => {
                tracing::debug!(
                    evidence_type = ?evidence_type,
                    error = %e,
                    "Evidence collector failed — skipping"
                );
            }
        }
    }

    evidence
}

/// Run a subset of evidence collectors.
pub fn collect_selected(
    types: &[EvidenceType],
    ctx: &EvidenceContext,
    drift_conn: &Connection,
) -> Vec<GroundingEvidence> {
    let mut evidence = Vec::new();

    for evidence_type in types {
        match collect_one(*evidence_type, ctx, drift_conn) {
            Ok(Some(e)) => evidence.push(e),
            Ok(None) => {}
            Err(e) => {
                tracing::debug!(
                    evidence_type = ?evidence_type,
                    error = %e,
                    "Evidence collector failed — skipping"
                );
            }
        }
    }

    evidence
}

/// Build an EvidenceContext from memory tags and linked patterns.
///
/// Parses tag prefixes like "pattern:p1", "module:src/foo", "constraint:c1", etc.
pub fn context_from_tags(
    tags: &[String],
    linked_patterns: &[String],
    current_confidence: f64,
) -> EvidenceContext {
    let mut ctx = EvidenceContext {
        current_confidence,
        ..Default::default()
    };

    // Use first linked pattern if available
    if let Some(first) = linked_patterns.first() {
        ctx.pattern_id = Some(first.clone());
    }

    for tag in tags {
        if let Some(val) = tag.strip_prefix("pattern:") {
            if ctx.pattern_id.is_none() {
                ctx.pattern_id = Some(val.to_string());
            }
        } else if let Some(val) = tag.strip_prefix("constraint:") {
            ctx.constraint_id = Some(val.to_string());
        } else if let Some(val) = tag.strip_prefix("module:") {
            ctx.module_path = Some(val.to_string());
        } else if let Some(val) = tag.strip_prefix("project:") {
            ctx.project = Some(val.to_string());
        } else if let Some(val) = tag.strip_prefix("decision:") {
            ctx.decision_id = Some(val.to_string());
        } else if let Some(val) = tag.strip_prefix("boundary:") {
            ctx.boundary_id = Some(val.to_string());
        } else if let Some(val) = tag.strip_prefix("function:") {
            ctx.function_id = Some(val.to_string());
        } else if let Some(val) = tag.strip_prefix("file:") {
            ctx.file_path = Some(val.to_string());
        }
    }

    ctx
}

/// Convenience: build context and collect all evidence in one call.
pub fn collect_for_memory(
    tags: &[String],
    linked_patterns: &[String],
    current_confidence: f64,
    drift_conn: &Connection,
) -> Vec<GroundingEvidence> {
    let ctx = context_from_tags(tags, linked_patterns, current_confidence);
    collect_all(&ctx, drift_conn)
}

/// Count how many evidence types have data available for a given context.
pub fn available_evidence_count(
    ctx: &EvidenceContext,
    drift_conn: &Connection,
) -> BridgeResult<usize> {
    let mut count = 0;
    for evidence_type in EvidenceType::ALL {
        if let Ok(Some(_)) = collect_one(evidence_type, ctx, drift_conn) {
            count += 1;
        }
    }
    Ok(count)
}

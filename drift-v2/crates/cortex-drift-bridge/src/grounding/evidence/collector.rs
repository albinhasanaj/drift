//! Enum dispatch evidence collector — replaces passive MemoryForGrounding fields
//! with active queries against drift.db.
//!
//! Uses enum dispatch (not trait objects) per architecture blueprint §6.7.

use rusqlite::Connection;

use super::types::{EvidenceType, GroundingEvidence};
use crate::errors::BridgeResult;
use crate::query::drift_queries;

/// Metadata needed to collect evidence for a memory.
/// Populated from the memory's tags, linked_patterns, and content.
#[derive(Debug, Clone, Default)]
pub struct EvidenceContext {
    /// Pattern ID linked to this memory (if any).
    pub pattern_id: Option<String>,
    /// Constraint ID linked to this memory (if any).
    pub constraint_id: Option<String>,
    /// Module path for coupling queries.
    pub module_path: Option<String>,
    /// Project identifier for DNA health.
    pub project: Option<String>,
    /// Decision ID for decision evidence.
    pub decision_id: Option<String>,
    /// Boundary ID for boundary data.
    pub boundary_id: Option<String>,
    /// Function ID for test_quality queries.
    pub function_id: Option<String>,
    /// File path for error_gaps and future security queries.
    pub file_path: Option<String>,
    /// Current memory confidence (for comparison).
    pub current_confidence: f64,
}

/// Collect a single evidence type from drift.db.
/// Returns None if the required context field is missing or the query returns no data.
pub fn collect_one(
    evidence_type: EvidenceType,
    ctx: &EvidenceContext,
    drift_conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    match evidence_type {
        EvidenceType::PatternConfidence => collect_pattern_confidence(ctx, drift_conn),
        EvidenceType::PatternOccurrence => collect_pattern_occurrence(ctx, drift_conn),
        EvidenceType::FalsePositiveRate => collect_false_positive_rate(ctx, drift_conn),
        EvidenceType::ConstraintVerification => collect_constraint_verification(ctx, drift_conn),
        EvidenceType::CouplingMetric => collect_coupling_metric(ctx, drift_conn),
        EvidenceType::DnaHealth => collect_dna_health(ctx, drift_conn),
        EvidenceType::TestCoverage => collect_test_coverage(ctx, drift_conn),
        EvidenceType::ErrorHandlingGaps => collect_error_handling_gaps(ctx, drift_conn),
        EvidenceType::DecisionEvidence => collect_decision_evidence(ctx, drift_conn),
        EvidenceType::BoundaryData => collect_boundary_data(ctx, drift_conn),
        EvidenceType::TaintAnalysis => collect_taint_analysis(ctx, drift_conn),
        EvidenceType::CallGraphCoverage => collect_call_graph_coverage(drift_conn),
    }
}

fn collect_pattern_confidence(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    let pattern_id = match &ctx.pattern_id {
        Some(id) => id,
        None => return Ok(None),
    };
    match drift_queries::pattern_confidence(conn, pattern_id)? {
        Some(confidence) if confidence.is_finite() => Ok(Some(GroundingEvidence::new(
            EvidenceType::PatternConfidence,
            format!("Pattern confidence: {:.2}", confidence),
            confidence,
            Some(ctx.current_confidence),
            confidence.clamp(0.0, 1.0),
        ))),
        _ => Ok(None),
    }
}

fn collect_pattern_occurrence(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    let pattern_id = match &ctx.pattern_id {
        Some(id) => id,
        None => return Ok(None),
    };
    match drift_queries::pattern_occurrence_rate(conn, pattern_id)? {
        Some(rate) if rate.is_finite() => Ok(Some(GroundingEvidence::new(
            EvidenceType::PatternOccurrence,
            format!("Pattern occurrence rate: {:.1}%", rate * 100.0),
            rate,
            None,
            rate.clamp(0.0, 1.0),
        ))),
        _ => Ok(None),
    }
}

fn collect_false_positive_rate(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    let pattern_id = match &ctx.pattern_id {
        Some(id) => id,
        None => return Ok(None),
    };
    match drift_queries::false_positive_rate(conn, pattern_id)? {
        Some(fp_rate) if fp_rate.is_finite() => {
            let support = (1.0 - fp_rate).clamp(0.0, 1.0);
            Ok(Some(GroundingEvidence::new(
                EvidenceType::FalsePositiveRate,
                format!("False positive rate: {:.1}%", fp_rate * 100.0),
                fp_rate,
                None,
                support,
            )))
        }
        _ => Ok(None),
    }
}

fn collect_constraint_verification(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    let constraint_id = match &ctx.constraint_id {
        Some(id) => id,
        None => return Ok(None),
    };
    match drift_queries::constraint_verified(conn, constraint_id)? {
        Some(verified) => Ok(Some(GroundingEvidence::new(
            EvidenceType::ConstraintVerification,
            format!("Constraint verification: {}", if verified { "pass" } else { "fail" }),
            if verified { 1.0 } else { 0.0 },
            None,
            if verified { 1.0 } else { 0.0 },
        ))),
        None => Ok(None),
    }
}

fn collect_coupling_metric(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    let module_path = match &ctx.module_path {
        Some(p) => p,
        None => return Ok(None),
    };
    match drift_queries::coupling_metric(conn, module_path)? {
        Some(coupling) if coupling.is_finite() => Ok(Some(GroundingEvidence::new(
            EvidenceType::CouplingMetric,
            format!("Coupling metric: {:.2}", coupling),
            coupling,
            None,
            coupling.clamp(0.0, 1.0),
        ))),
        _ => Ok(None),
    }
}

fn collect_dna_health(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    let project = match &ctx.project {
        Some(p) => p,
        None => return Ok(None),
    };
    match drift_queries::dna_health(conn, project)? {
        Some(health) if health.is_finite() => Ok(Some(GroundingEvidence::new(
            EvidenceType::DnaHealth,
            format!("DNA health score: {:.2}", health),
            health,
            None,
            health.clamp(0.0, 1.0),
        ))),
        _ => Ok(None),
    }
}

fn collect_test_coverage(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    // test_quality table is keyed by function_id, fall back to module_path
    let key = match (&ctx.function_id, &ctx.module_path) {
        (Some(fid), _) => fid,
        (None, Some(p)) => p,
        _ => return Ok(None),
    };
    match drift_queries::test_coverage(conn, key)? {
        Some(coverage) if coverage.is_finite() => Ok(Some(GroundingEvidence::new(
            EvidenceType::TestCoverage,
            format!("Test coverage: {:.1}%", coverage * 100.0),
            coverage,
            None,
            coverage.clamp(0.0, 1.0),
        ))),
        _ => Ok(None),
    }
}

fn collect_error_handling_gaps(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    // error_gaps table uses file path prefix match; prefer file_path, fall back to module_path
    let path = match (&ctx.file_path, &ctx.module_path) {
        (Some(fp), _) => fp,
        (None, Some(p)) => p,
        _ => return Ok(None),
    };
    match drift_queries::error_handling_gaps(conn, path)? {
        Some(gaps) => {
            let support = 1.0 - (gaps as f64 / 100.0).clamp(0.0, 1.0);
            Ok(Some(GroundingEvidence::new(
                EvidenceType::ErrorHandlingGaps,
                format!("Error handling gaps: {}", gaps),
                gaps as f64,
                None,
                support,
            )))
        }
        None => Ok(None),
    }
}

fn collect_decision_evidence(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    let decision_id = match &ctx.decision_id {
        Some(id) => id,
        None => return Ok(None),
    };
    match drift_queries::decision_evidence(conn, decision_id)? {
        Some(score) if score.is_finite() => Ok(Some(GroundingEvidence::new(
            EvidenceType::DecisionEvidence,
            format!("Decision evidence score: {:.2}", score),
            score,
            None,
            score.clamp(0.0, 1.0),
        ))),
        _ => Ok(None),
    }
}

fn collect_boundary_data(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    let boundary_id = match &ctx.boundary_id {
        Some(id) => id,
        None => return Ok(None),
    };
    match drift_queries::boundary_data(conn, boundary_id)? {
        Some(score) if score.is_finite() => Ok(Some(GroundingEvidence::new(
            EvidenceType::BoundaryData,
            format!("Boundary data score: {:.2}", score),
            score,
            None,
            score.clamp(0.0, 1.0),
        ))),
        _ => Ok(None),
    }
}

fn collect_taint_analysis(
    ctx: &EvidenceContext,
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    let file_path = match &ctx.file_path {
        Some(fp) => fp,
        None => return Ok(None),
    };
    match drift_queries::taint_flow_risk(conn, file_path)? {
        Some(risk) if risk.is_finite() => {
            // Lower unsanitized ratio = higher support for memory correctness
            let support = (1.0 - risk).clamp(0.0, 1.0);
            Ok(Some(GroundingEvidence::new(
                EvidenceType::TaintAnalysis,
                format!("Taint flow unsanitized ratio: {:.1}%", risk * 100.0),
                risk,
                None,
                support,
            )))
        }
        _ => Ok(None),
    }
}

fn collect_call_graph_coverage(
    conn: &Connection,
) -> BridgeResult<Option<GroundingEvidence>> {
    match drift_queries::call_graph_coverage(conn)? {
        Some(coverage) if coverage.is_finite() => Ok(Some(GroundingEvidence::new(
            EvidenceType::CallGraphCoverage,
            format!("Call graph resolution quality: {:.1}%", coverage * 100.0),
            coverage,
            None,
            coverage.clamp(0.0, 1.0),
        ))),
        _ => Ok(None),
    }
}

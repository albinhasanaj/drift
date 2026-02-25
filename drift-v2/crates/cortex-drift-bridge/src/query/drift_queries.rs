//! Parameterized read-only queries against drift.db.
//!
//! 12 queries matching the 12 evidence types in the grounding system.
//! All queries are read-only — the bridge never writes to drift.db (D6 compliance).
//!
//! Schema reference:
//!   v001: file_metadata, functions, scan_history
//!   v002: call_edges, data_access, detections, boundaries
//!   v003: pattern_confidence, outliers, conventions
//!   v004: reachability_cache, taint_flows, error_gaps, impact_scores, test_coverage, test_quality
//!   v005: coupling_metrics, constraints, constraint_verifications, contracts, ..., dna_genes, ...
//!   v006: violations, gate_results, audit_snapshots, health_trends, feedback, ...
//!   v007: simulations, decisions, ...

use rusqlite::Connection;

use crate::errors::BridgeResult;

/// Query pattern confidence from drift.db by pattern_id.
/// Table: `pattern_confidence` (v003), column: `posterior_mean`.
pub fn pattern_confidence(conn: &Connection, pattern_id: &str) -> BridgeResult<Option<f64>> {
    let result = conn.query_row(
        "SELECT posterior_mean FROM pattern_confidence WHERE pattern_id = ?1",
        rusqlite::params![pattern_id],
        |row| row.get::<_, f64>(0),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Query pattern occurrence rate from drift.db by pattern_id.
/// Computed as the ratio of files containing this pattern to total files scanned.
/// Tables: `detections` (v002).
pub fn pattern_occurrence_rate(conn: &Connection, pattern_id: &str) -> BridgeResult<Option<f64>> {
    // COALESCE handles NULL from NULLIF when detections table is empty
    let result = conn.query_row(
        "SELECT COALESCE( \
             COUNT(DISTINCT file) * 1.0 / \
             NULLIF((SELECT COUNT(DISTINCT file) FROM detections), 0), \
             0.0 \
         ) FROM detections WHERE pattern_id = ?1",
        rusqlite::params![pattern_id],
        |row| row.get::<_, f64>(0),
    );
    match result {
        Ok(v) if v > 0.0 => Ok(Some(v)),
        Ok(_) => Ok(None), // 0.0 means no detections for this pattern
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Query false positive rate from drift.db by pattern_id.
/// Computed as ratio of 'dismiss' actions to total feedback entries.
/// Table: `feedback` (v006).
pub fn false_positive_rate(conn: &Connection, pattern_id: &str) -> BridgeResult<Option<f64>> {
    // First check if any feedback exists for this pattern
    let count: u32 = conn.query_row(
        "SELECT COUNT(*) FROM feedback WHERE pattern_id = ?1",
        rusqlite::params![pattern_id],
        |row| row.get(0),
    )?;
    if count == 0 {
        return Ok(None);
    }
    let result = conn.query_row(
        "SELECT SUM(CASE WHEN action = 'dismiss' THEN 1 ELSE 0 END) * 1.0 / COUNT(*) \
         FROM feedback WHERE pattern_id = ?1",
        rusqlite::params![pattern_id],
        |row| row.get::<_, f64>(0),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Query constraint verification status from drift.db by constraint_id.
/// Returns the most recent verification result.
/// Table: `constraint_verifications` (v005), column: `passed` (INTEGER 0/1).
pub fn constraint_verified(conn: &Connection, constraint_id: &str) -> BridgeResult<Option<bool>> {
    let result = conn.query_row(
        "SELECT passed FROM constraint_verifications \
         WHERE constraint_id = ?1 ORDER BY verified_at DESC LIMIT 1",
        rusqlite::params![constraint_id],
        |row| row.get::<_, bool>(0),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Query coupling instability metric from drift.db by module path.
/// Table: `coupling_metrics` (v005), column: `instability`.
pub fn coupling_metric(conn: &Connection, module_path: &str) -> BridgeResult<Option<f64>> {
    let result = conn.query_row(
        "SELECT instability FROM coupling_metrics WHERE module = ?1",
        rusqlite::params![module_path],
        |row| row.get::<_, f64>(0),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Query DNA health score from drift.db.
/// Project-level aggregate: AVG(confidence * consistency) across all genes.
/// Table: `dna_genes` (v005).
/// Note: `_project` param kept for API compat; DNA health is a global metric.
pub fn dna_health(conn: &Connection, _project: &str) -> BridgeResult<Option<f64>> {
    let result = conn.query_row(
        "SELECT AVG(confidence * consistency) FROM dna_genes",
        [],
        |row| row.get::<_, Option<f64>>(0),
    );
    match result {
        Ok(v) => Ok(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Query test quality score from drift.db by function_id.
/// Table: `test_quality` (v004), column: `overall_score`.
pub fn test_coverage(conn: &Connection, function_id: &str) -> BridgeResult<Option<f64>> {
    let result = conn.query_row(
        "SELECT overall_score FROM test_quality WHERE function_id = ?1",
        rusqlite::params![function_id],
        |row| row.get::<_, f64>(0),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Query error handling gap count from drift.db by file path prefix.
/// Table: `error_gaps` (v004), column: COUNT(*) with file prefix match.
pub fn error_handling_gaps(conn: &Connection, module_path: &str) -> BridgeResult<Option<u32>> {
    let pattern = format!("{}%", module_path);
    let result = conn.query_row(
        "SELECT COUNT(*) FROM error_gaps WHERE file LIKE ?1",
        rusqlite::params![pattern],
        |row| row.get::<_, u32>(0),
    );
    match result {
        Ok(0) => Ok(None),
        Ok(v) => Ok(Some(v)),
        Err(e) => Err(e.into()),
    }
}

/// Query decision evidence score from drift.db by decision_id.
/// Table: `decisions` (v007), column: `confidence`.
/// Note: `id` is INTEGER AUTOINCREMENT — input string is CAST to INTEGER.
pub fn decision_evidence(conn: &Connection, decision_id: &str) -> BridgeResult<Option<f64>> {
    let result = conn.query_row(
        "SELECT confidence FROM decisions WHERE id = CAST(?1 AS INTEGER)",
        rusqlite::params![decision_id],
        |row| row.get::<_, f64>(0),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Query boundary confidence from drift.db by boundary_id.
/// Table: `boundaries` (v002), column: `confidence`.
/// Note: `id` is INTEGER AUTOINCREMENT — input string is CAST to INTEGER.
pub fn boundary_data(conn: &Connection, boundary_id: &str) -> BridgeResult<Option<f64>> {
    let result = conn.query_row(
        "SELECT confidence FROM boundaries WHERE id = CAST(?1 AS INTEGER)",
        rusqlite::params![boundary_id],
        |row| row.get::<_, f64>(0),
    );
    match result {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Query taint flow risk for a file from drift.db.
/// Returns the ratio of unsanitized flows to total flows for the file.
/// Table: `taint_flows` (v004).
pub fn taint_flow_risk(conn: &Connection, file_path: &str) -> BridgeResult<Option<f64>> {
    let total: u32 = conn.query_row(
        "SELECT COUNT(*) FROM taint_flows WHERE source_file = ?1 OR sink_file = ?1",
        rusqlite::params![file_path],
        |row| row.get(0),
    )?;
    if total == 0 {
        return Ok(None);
    }
    let unsanitized: u32 = conn.query_row(
        "SELECT COUNT(*) FROM taint_flows WHERE (source_file = ?1 OR sink_file = ?1) AND is_sanitized = 0",
        rusqlite::params![file_path],
        |row| row.get(0),
    )?;
    Ok(Some(unsanitized as f64 / total as f64))
}

/// Query call graph resolution quality from drift.db.
/// Returns the ratio of resolved (non-fuzzy, non-unresolved) edges to total edges.
/// Table: `call_edges` (v002).
pub fn call_graph_coverage(conn: &Connection) -> BridgeResult<Option<f64>> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM call_edges",
        [],
        |row| row.get(0),
    )?;
    if total == 0 {
        return Ok(None);
    }
    let resolved: i64 = conn.query_row(
        "SELECT COUNT(*) FROM call_edges WHERE resolution != 'fuzzy' AND resolution != 'unresolved'",
        [],
        |row| row.get(0),
    )?;
    Ok(Some(resolved as f64 / total as f64))
}

//! Queries for all 5 graph intelligence systems.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use super::util::OptionalExt;

// --- Reachability ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityCacheRow {
    pub source_node: String,
    pub direction: String,
    pub reachable_set: String, // JSON array
    pub sensitivity: String,
}

pub fn upsert_reachability(conn: &Connection, row: &ReachabilityCacheRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO reachability_cache (source_node, direction, reachable_set, sensitivity)
         VALUES (?1, ?2, ?3, ?4)",
        params![row.source_node, row.direction, row.reachable_set, row.sensitivity],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn get_reachability(
    conn: &Connection,
    source_node: &str,
    direction: &str,
) -> Result<Option<ReachabilityCacheRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT source_node, direction, reachable_set, sensitivity
             FROM reachability_cache WHERE source_node = ?1 AND direction = ?2",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let result = stmt
        .query_row(params![source_node, direction], |row| {
            Ok(ReachabilityCacheRow {
                source_node: row.get(0)?,
                direction: row.get(1)?,
                reachable_set: row.get(2)?,
                sensitivity: row.get(3)?,
            })
        })
        .optional()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(result)
}

pub fn clear_reachability_cache(conn: &Connection) -> Result<(), StorageError> {
    conn.execute("DELETE FROM reachability_cache", [])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

// --- Taint Flows ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlowRow {
    pub id: Option<i64>,
    pub source_file: String,
    pub source_line: u32,
    pub source_type: String,
    pub sink_file: String,
    pub sink_line: u32,
    pub sink_type: String,
    pub cwe_id: Option<u32>,
    pub is_sanitized: bool,
    pub path: String, // JSON
    pub confidence: f64,
}

pub fn insert_taint_flow(conn: &Connection, row: &TaintFlowRow) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO taint_flows (source_file, source_line, source_type, sink_file, sink_line, sink_type, cwe_id, is_sanitized, path, confidence)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            row.source_file, row.source_line, row.source_type,
            row.sink_file, row.sink_line, row.sink_type,
            row.cwe_id, row.is_sanitized as i32, row.path, row.confidence,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(conn.last_insert_rowid())
}

pub fn get_taint_flows_by_file(
    conn: &Connection,
    file: &str,
) -> Result<Vec<TaintFlowRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, source_file, source_line, source_type, sink_file, sink_line, sink_type, cwe_id, is_sanitized, path, confidence
             FROM taint_flows WHERE source_file = ?1 OR sink_file = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], |row| {
            Ok(TaintFlowRow {
                id: row.get(0)?,
                source_file: row.get(1)?,
                source_line: row.get::<_, u32>(2)?,
                source_type: row.get(3)?,
                sink_file: row.get(4)?,
                sink_line: row.get::<_, u32>(5)?,
                sink_type: row.get(6)?,
                cwe_id: row.get(7)?,
                is_sanitized: row.get::<_, i32>(8)? != 0,
                path: row.get(9)?,
                confidence: row.get(10)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

pub fn get_taint_flows_by_cwe(
    conn: &Connection,
    cwe_id: u32,
) -> Result<Vec<TaintFlowRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, source_file, source_line, source_type, sink_file, sink_line, sink_type, cwe_id, is_sanitized, path, confidence
             FROM taint_flows WHERE cwe_id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![cwe_id], |row| {
            Ok(TaintFlowRow {
                id: row.get(0)?,
                source_file: row.get(1)?,
                source_line: row.get::<_, u32>(2)?,
                source_type: row.get(3)?,
                sink_file: row.get(4)?,
                sink_line: row.get::<_, u32>(5)?,
                sink_type: row.get(6)?,
                cwe_id: row.get(7)?,
                is_sanitized: row.get::<_, i32>(8)? != 0,
                path: row.get(9)?,
                confidence: row.get(10)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// --- Error Gaps ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorGapRow {
    pub id: Option<i64>,
    pub file: String,
    pub function_id: String,
    pub gap_type: String,
    pub error_type: Option<String>,
    pub propagation_chain: Option<String>, // JSON
    pub framework: Option<String>,
    pub cwe_id: Option<u32>,
    pub severity: String,
}

pub fn insert_error_gap(conn: &Connection, row: &ErrorGapRow) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO error_gaps (file, function_id, gap_type, error_type, propagation_chain, framework, cwe_id, severity)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            row.file, row.function_id, row.gap_type, row.error_type,
            row.propagation_chain, row.framework, row.cwe_id, row.severity,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(conn.last_insert_rowid())
}

pub fn get_error_gaps_by_file(
    conn: &Connection,
    file: &str,
) -> Result<Vec<ErrorGapRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, function_id, gap_type, error_type, propagation_chain, framework, cwe_id, severity
             FROM error_gaps WHERE file = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], |row| {
            Ok(ErrorGapRow {
                id: row.get(0)?,
                file: row.get(1)?,
                function_id: row.get(2)?,
                gap_type: row.get(3)?,
                error_type: row.get(4)?,
                propagation_chain: row.get(5)?,
                framework: row.get(6)?,
                cwe_id: row.get(7)?,
                severity: row.get(8)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// --- Impact Scores ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactScoreRow {
    pub function_id: String,
    pub blast_radius: u32,
    pub risk_score: f64,
    pub is_dead_code: bool,
    pub dead_code_reason: Option<String>,
    pub exclusion_category: Option<String>,
}

pub fn upsert_impact_score(conn: &Connection, row: &ImpactScoreRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO impact_scores (function_id, blast_radius, risk_score, is_dead_code, dead_code_reason, exclusion_category)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            row.function_id, row.blast_radius, row.risk_score,
            row.is_dead_code as i32, row.dead_code_reason, row.exclusion_category,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn get_impact_score(
    conn: &Connection,
    function_id: &str,
) -> Result<Option<ImpactScoreRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT function_id, blast_radius, risk_score, is_dead_code, dead_code_reason, exclusion_category
             FROM impact_scores WHERE function_id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let result = stmt
        .query_row(params![function_id], |row| {
            Ok(ImpactScoreRow {
                function_id: row.get(0)?,
                blast_radius: row.get::<_, u32>(1)?,
                risk_score: row.get(2)?,
                is_dead_code: row.get::<_, i32>(3)? != 0,
                dead_code_reason: row.get(4)?,
                exclusion_category: row.get(5)?,
            })
        })
        .optional()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(result)
}

// --- Test Coverage ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCoverageRow {
    pub test_function_id: String,
    pub source_function_id: String,
    pub coverage_type: String,
}

pub fn insert_test_coverage(conn: &Connection, row: &TestCoverageRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO test_coverage (test_function_id, source_function_id, coverage_type)
         VALUES (?1, ?2, ?3)",
        params![row.test_function_id, row.source_function_id, row.coverage_type],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn get_test_coverage_for_source(
    conn: &Connection,
    source_function_id: &str,
) -> Result<Vec<TestCoverageRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT test_function_id, source_function_id, coverage_type
             FROM test_coverage WHERE source_function_id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![source_function_id], |row| {
            Ok(TestCoverageRow {
                test_function_id: row.get(0)?,
                source_function_id: row.get(1)?,
                coverage_type: row.get(2)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// --- Test Quality ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestQualityRow {
    pub function_id: String,
    pub coverage_breadth: Option<f64>,
    pub coverage_depth: Option<f64>,
    pub assertion_density: Option<f64>,
    pub mock_ratio: Option<f64>,
    pub isolation: Option<f64>,
    pub freshness: Option<f64>,
    pub stability: Option<f64>,
    pub overall_score: f64,
    pub smells: Option<String>, // JSON array
}

pub fn upsert_test_quality(conn: &Connection, row: &TestQualityRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO test_quality (function_id, coverage_breadth, coverage_depth, assertion_density, mock_ratio, isolation, freshness, stability, overall_score, smells)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            row.function_id, row.coverage_breadth, row.coverage_depth,
            row.assertion_density, row.mock_ratio, row.isolation,
            row.freshness, row.stability, row.overall_score, row.smells,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn get_test_quality(
    conn: &Connection,
    function_id: &str,
) -> Result<Option<TestQualityRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT function_id, coverage_breadth, coverage_depth, assertion_density, mock_ratio, isolation, freshness, stability, overall_score, smells
             FROM test_quality WHERE function_id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let result = stmt
        .query_row(params![function_id], |row| {
            Ok(TestQualityRow {
                function_id: row.get(0)?,
                coverage_breadth: row.get(1)?,
                coverage_depth: row.get(2)?,
                assertion_density: row.get(3)?,
                mock_ratio: row.get(4)?,
                isolation: row.get(5)?,
                freshness: row.get(6)?,
                stability: row.get(7)?,
                overall_score: row.get(8)?,
                smells: row.get(9)?,
            })
        })
        .optional()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(result)
}


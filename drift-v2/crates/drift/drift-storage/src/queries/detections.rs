//! detections table queries.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// A detection record from the database.
#[derive(Debug, Clone)]
pub struct DetectionRecord {
    pub id: i64,
    pub file: String,
    pub line: i64,
    pub column_num: i64,
    pub pattern_id: String,
    pub category: String,
    pub confidence: f64,
    pub detection_method: String,
    pub cwe_ids: Option<String>,
    pub owasp: Option<String>,
    pub matched_text: Option<String>,
    pub created_at: i64,
}

/// Insert a batch of detections.
pub fn insert_detections(
    conn: &Connection,
    detections: &[DetectionRecord],
) -> Result<usize, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO detections
             (file, line, column_num, pattern_id, category, confidence,
              detection_method, cwe_ids, owasp, matched_text)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut count = 0;
    for d in detections {
        stmt.execute(params![
            d.file, d.line, d.column_num, d.pattern_id, d.category,
            d.confidence, d.detection_method, d.cwe_ids, d.owasp, d.matched_text,
        ])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
        count += 1;
    }
    Ok(count)
}

/// Get all detections for a given file.
pub fn get_detections_by_file(
    conn: &Connection,
    file: &str,
) -> Result<Vec<DetectionRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, column_num, pattern_id, category, confidence,
                    detection_method, cwe_ids, owasp, matched_text, created_at
             FROM detections WHERE file = ?1 ORDER BY line",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], |row| {
            Ok(DetectionRecord {
                id: row.get(0)?,
                file: row.get(1)?,
                line: row.get(2)?,
                column_num: row.get(3)?,
                pattern_id: row.get(4)?,
                category: row.get(5)?,
                confidence: row.get(6)?,
                detection_method: row.get(7)?,
                cwe_ids: row.get(8)?,
                owasp: row.get(9)?,
                matched_text: row.get(10)?,
                created_at: row.get(11)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?);
    }
    Ok(result)
}

/// Get detections by category.
pub fn get_detections_by_category(
    conn: &Connection,
    category: &str,
) -> Result<Vec<DetectionRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, column_num, pattern_id, category, confidence,
                    detection_method, cwe_ids, owasp, matched_text, created_at
             FROM detections WHERE category = ?1 ORDER BY confidence DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![category], |row| {
            Ok(DetectionRecord {
                id: row.get(0)?,
                file: row.get(1)?,
                line: row.get(2)?,
                column_num: row.get(3)?,
                pattern_id: row.get(4)?,
                category: row.get(5)?,
                confidence: row.get(6)?,
                detection_method: row.get(7)?,
                cwe_ids: row.get(8)?,
                owasp: row.get(9)?,
                matched_text: row.get(10)?,
                created_at: row.get(11)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?);
    }
    Ok(result)
}

/// Get all detections (no category filter), ordered by confidence desc.
pub fn query_all_detections(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<DetectionRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, column_num, pattern_id, category, confidence,
                    detection_method, cwe_ids, owasp, matched_text, created_at
             FROM detections ORDER BY confidence DESC LIMIT ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![limit as i64], |row| {
            Ok(DetectionRecord {
                id: row.get(0)?,
                file: row.get(1)?,
                line: row.get(2)?,
                column_num: row.get(3)?,
                pattern_id: row.get(4)?,
                category: row.get(5)?,
                confidence: row.get(6)?,
                detection_method: row.get(7)?,
                cwe_ids: row.get(8)?,
                owasp: row.get(9)?,
                matched_text: row.get(10)?,
                created_at: row.get(11)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?);
    }
    Ok(result)
}

/// Delete all detections for a given file.
pub fn delete_detections_by_file(
    conn: &Connection,
    file: &str,
) -> Result<usize, StorageError> {
    conn.execute("DELETE FROM detections WHERE file = ?1", params![file])
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Count total detections.
pub fn count_detections(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row("SELECT COUNT(*) FROM detections", [], |row| row.get(0))
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Get detections by detection method (e.g., "TomlPattern", "LearningDeviation").
pub fn get_detections_by_method(
    conn: &Connection,
    method: &str,
) -> Result<Vec<DetectionRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, column_num, pattern_id, category, confidence,
                    detection_method, cwe_ids, owasp, matched_text, created_at
             FROM detections WHERE detection_method = ?1 ORDER BY confidence DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![method], map_detection_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    collect_rows(rows)
}

/// Get detections by pattern ID prefix (e.g., "spring/" for all Spring patterns).
pub fn get_detections_by_pattern_prefix(
    conn: &Connection,
    prefix: &str,
) -> Result<Vec<DetectionRecord>, StorageError> {
    let like_pattern = format!("{prefix}%");
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, column_num, pattern_id, category, confidence,
                    detection_method, cwe_ids, owasp, matched_text, created_at
             FROM detections WHERE pattern_id LIKE ?1 ORDER BY confidence DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![like_pattern], map_detection_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    collect_rows(rows)
}

/// Get detections that reference a specific CWE ID.
pub fn get_detections_by_cwe(
    conn: &Connection,
    cwe_id: u32,
) -> Result<Vec<DetectionRecord>, StorageError> {
    let cwe_str = cwe_id.to_string();
    let like_pattern = format!("%{cwe_str}%");
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, column_num, pattern_id, category, confidence,
                    detection_method, cwe_ids, owasp, matched_text, created_at
             FROM detections WHERE cwe_ids LIKE ?1 ORDER BY confidence DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![like_pattern], map_detection_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    collect_rows(rows)
}

/// Summary row for framework detection aggregation.
#[derive(Debug, Clone)]
pub struct DetectionSummaryRow {
    pub detection_method: String,
    pub count: i64,
    pub avg_confidence: f64,
}

/// Get a summary of detections grouped by detection method.
pub fn get_framework_detection_summary(
    conn: &Connection,
) -> Result<Vec<DetectionSummaryRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT detection_method, COUNT(*), AVG(confidence)
             FROM detections GROUP BY detection_method",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(DetectionSummaryRow {
                detection_method: row.get(0)?,
                count: row.get(1)?,
                avg_confidence: row.get(2)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?);
    }
    Ok(result)
}

/// Shared row mapper for detection queries.
fn map_detection_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DetectionRecord> {
    Ok(DetectionRecord {
        id: row.get(0)?,
        file: row.get(1)?,
        line: row.get(2)?,
        column_num: row.get(3)?,
        pattern_id: row.get(4)?,
        category: row.get(5)?,
        confidence: row.get(6)?,
        detection_method: row.get(7)?,
        cwe_ids: row.get(8)?,
        owasp: row.get(9)?,
        matched_text: row.get(10)?,
        created_at: row.get(11)?,
    })
}

/// Collect rusqlite mapped rows into a Vec.
fn collect_rows(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<DetectionRecord>>,
) -> Result<Vec<DetectionRecord>, StorageError> {
    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?);
    }
    Ok(result)
}

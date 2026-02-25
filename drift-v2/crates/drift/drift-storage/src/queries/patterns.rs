//! Pattern confidence, outlier, and convention queries.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// A pattern confidence row.
#[derive(Debug, Clone)]
pub struct PatternConfidenceRow {
    pub pattern_id: String,
    pub alpha: f64,
    pub beta: f64,
    pub posterior_mean: f64,
    pub credible_interval_low: f64,
    pub credible_interval_high: f64,
    pub tier: String,
    pub momentum: String,
    pub last_updated: i64,
}

/// An outlier row.
#[derive(Debug, Clone)]
pub struct OutlierRow {
    pub id: i64,
    pub pattern_id: String,
    pub file: String,
    pub line: i64,
    pub deviation_score: f64,
    pub significance: String,
    pub method: String,
    pub created_at: i64,
}

/// A convention row.
#[derive(Debug, Clone)]
pub struct ConventionRow {
    pub id: i64,
    pub pattern_id: String,
    pub category: String,
    pub scope: String,
    pub dominance_ratio: f64,
    pub promotion_status: String,
    pub discovered_at: i64,
    pub last_seen: i64,
    pub expires_at: Option<i64>,
}

/// Insert or update a pattern confidence score.
pub fn upsert_confidence(conn: &Connection, row: &PatternConfidenceRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO pattern_confidence (pattern_id, alpha, beta, posterior_mean, credible_interval_low, credible_interval_high, tier, momentum, last_updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(pattern_id) DO UPDATE SET
           alpha = excluded.alpha,
           beta = excluded.beta,
           posterior_mean = excluded.posterior_mean,
           credible_interval_low = excluded.credible_interval_low,
           credible_interval_high = excluded.credible_interval_high,
           tier = excluded.tier,
           momentum = excluded.momentum,
           last_updated = excluded.last_updated",
        params![
            row.pattern_id,
            row.alpha,
            row.beta,
            row.posterior_mean,
            row.credible_interval_low,
            row.credible_interval_high,
            row.tier,
            row.momentum,
            row.last_updated,
        ],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Query pattern confidence by tier with keyset pagination.
pub fn query_confidence_by_tier(
    conn: &Connection,
    tier: &str,
    after_id: Option<&str>,
    limit: usize,
) -> Result<Vec<PatternConfidenceRow>, StorageError> {
    let sql = if after_id.is_some() {
        "SELECT pattern_id, alpha, beta, posterior_mean, credible_interval_low, credible_interval_high, tier, momentum, last_updated
         FROM pattern_confidence
         WHERE tier = ?1 AND pattern_id > ?2
         ORDER BY pattern_id ASC
         LIMIT ?3"
    } else {
        "SELECT pattern_id, alpha, beta, posterior_mean, credible_interval_low, credible_interval_high, tier, momentum, last_updated
         FROM pattern_confidence
         WHERE tier = ?1
         ORDER BY pattern_id ASC
         LIMIT ?2"
    };

    let mut stmt = conn.prepare_cached(sql)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    let rows = if let Some(cursor) = after_id {
        stmt.query_map(params![tier, cursor, limit as i64], map_confidence_row)
            .map_err(|e| StorageError::SqliteError { message: e.to_string() })?
    } else {
        stmt.query_map(params![tier, limit as i64], map_confidence_row)
            .map_err(|e| StorageError::SqliteError { message: e.to_string() })?
    };

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query all pattern confidence scores.
pub fn query_all_confidence(conn: &Connection) -> Result<Vec<PatternConfidenceRow>, StorageError> {
    let mut stmt = conn.prepare_cached(
        "SELECT pattern_id, alpha, beta, posterior_mean, credible_interval_low, credible_interval_high, tier, momentum, last_updated
         FROM pattern_confidence
         ORDER BY posterior_mean DESC",
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    let rows = stmt.query_map([], map_confidence_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

fn map_confidence_row(row: &rusqlite::Row) -> rusqlite::Result<PatternConfidenceRow> {
    Ok(PatternConfidenceRow {
        pattern_id: row.get(0)?,
        alpha: row.get(1)?,
        beta: row.get(2)?,
        posterior_mean: row.get(3)?,
        credible_interval_low: row.get(4)?,
        credible_interval_high: row.get(5)?,
        tier: row.get(6)?,
        momentum: row.get(7)?,
        last_updated: row.get(8)?,
    })
}

/// Insert an outlier row.
pub fn insert_outlier(conn: &Connection, row: &OutlierRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO outliers (pattern_id, file, line, deviation_score, significance, method)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            row.pattern_id,
            row.file,
            row.line,
            row.deviation_score,
            row.significance,
            row.method,
        ],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Query outliers by pattern_id.
pub fn query_outliers_by_pattern(conn: &Connection, pattern_id: &str) -> Result<Vec<OutlierRow>, StorageError> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, pattern_id, file, line, deviation_score, significance, method, created_at
         FROM outliers WHERE pattern_id = ?1 ORDER BY deviation_score DESC",
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    let rows = stmt.query_map(params![pattern_id], |row| {
        Ok(OutlierRow {
            id: row.get(0)?,
            pattern_id: row.get(1)?,
            file: row.get(2)?,
            line: row.get(3)?,
            deviation_score: row.get(4)?,
            significance: row.get(5)?,
            method: row.get(6)?,
            created_at: row.get(7)?,
        })
    }).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Insert a convention row.
pub fn insert_convention(conn: &Connection, row: &ConventionRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO conventions (pattern_id, category, scope, dominance_ratio, promotion_status, discovered_at, last_seen, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            row.pattern_id,
            row.category,
            row.scope,
            row.dominance_ratio,
            row.promotion_status,
            row.discovered_at,
            row.last_seen,
            row.expires_at,
        ],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Query conventions by category.
pub fn query_conventions_by_category(conn: &Connection, category: &str) -> Result<Vec<ConventionRow>, StorageError> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, pattern_id, category, scope, dominance_ratio, promotion_status, discovered_at, last_seen, expires_at
         FROM conventions WHERE category = ?1 ORDER BY dominance_ratio DESC",
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    let rows = stmt.query_map(params![category], map_convention_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query all conventions.
pub fn query_all_conventions(conn: &Connection) -> Result<Vec<ConventionRow>, StorageError> {
    let mut stmt = conn.prepare_cached(
        "SELECT id, pattern_id, category, scope, dominance_ratio, promotion_status, discovered_at, last_seen, expires_at
         FROM conventions ORDER BY dominance_ratio DESC",
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    let rows = stmt.query_map([], map_convention_row)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

fn map_convention_row(row: &rusqlite::Row) -> rusqlite::Result<ConventionRow> {
    Ok(ConventionRow {
        id: row.get(0)?,
        pattern_id: row.get(1)?,
        category: row.get(2)?,
        scope: row.get(3)?,
        dominance_ratio: row.get(4)?,
        promotion_status: row.get(5)?,
        discovered_at: row.get(6)?,
        last_seen: row.get(7)?,
        expires_at: row.get(8)?,
    })
}

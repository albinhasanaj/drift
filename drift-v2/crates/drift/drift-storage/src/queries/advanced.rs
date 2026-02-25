//! Queries for Phase 7 advanced systems: simulations, decisions, context, migrations.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

// ─── Simulations ───

#[allow(clippy::too_many_arguments)]
pub fn insert_simulation(
    conn: &Connection,
    task_category: &str,
    task_description: &str,
    approach_count: i32,
    recommended_approach: Option<&str>,
    p10_effort: f64,
    p50_effort: f64,
    p90_effort: f64,
) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO simulations (task_category, task_description, approach_count, recommended_approach, p10_effort, p50_effort, p90_effort)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![task_category, task_description, approach_count, recommended_approach, p10_effort, p50_effort, p90_effort],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(conn.last_insert_rowid())
}

pub fn get_simulations(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<SimulationRow>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, task_category, task_description, approach_count, recommended_approach, p10_effort, p50_effort, p90_effort, created_at
         FROM simulations ORDER BY created_at DESC LIMIT ?1"
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt.query_map(params![limit as i64], |row| {
        Ok(SimulationRow {
            id: row.get(0)?,
            task_category: row.get(1)?,
            task_description: row.get(2)?,
            approach_count: row.get(3)?,
            recommended_approach: row.get(4)?,
            p10_effort: row.get(5)?,
            p50_effort: row.get(6)?,
            p90_effort: row.get(7)?,
            created_at: row.get(8)?,
        })
    }).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

#[derive(Debug, Clone)]
pub struct SimulationRow {
    pub id: i64,
    pub task_category: String,
    pub task_description: String,
    pub approach_count: i32,
    pub recommended_approach: Option<String>,
    pub p10_effort: f64,
    pub p50_effort: f64,
    pub p90_effort: f64,
    pub created_at: i64,
}

// ─── Decisions ───

#[allow(clippy::too_many_arguments)]
pub fn insert_decision(
    conn: &Connection,
    category: &str,
    description: &str,
    commit_sha: Option<&str>,
    confidence: f64,
    related_patterns: Option<&str>,
    author: Option<&str>,
    files_changed: Option<&str>,
) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO decisions (category, description, commit_sha, confidence, related_patterns, author, files_changed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![category, description, commit_sha, confidence, related_patterns, author, files_changed],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(conn.last_insert_rowid())
}

// ─── Context Cache ───

pub fn insert_context_cache(
    conn: &Connection,
    session_id: &str,
    intent: &str,
    depth: &str,
    token_count: i32,
    content_hash: &str,
) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO context_cache (session_id, intent, depth, token_count, content_hash)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![session_id, intent, depth, token_count, content_hash],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(conn.last_insert_rowid())
}

// ─── Migration Projects ───

pub fn create_migration_project(
    conn: &Connection,
    name: &str,
    source_language: &str,
    target_language: &str,
    source_framework: Option<&str>,
    target_framework: Option<&str>,
) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO migration_projects (name, source_language, target_language, source_framework, target_framework)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![name, source_language, target_language, source_framework, target_framework],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(conn.last_insert_rowid())
}

pub fn create_migration_module(
    conn: &Connection,
    project_id: i64,
    module_name: &str,
) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO migration_modules (project_id, module_name)
         VALUES (?1, ?2)",
        params![project_id, module_name],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(conn.last_insert_rowid())
}

pub fn update_module_status(
    conn: &Connection,
    module_id: i64,
    status: &str,
) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE migration_modules SET status = ?1, updated_at = unixepoch() WHERE id = ?2",
        params![status, module_id],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(())
}

pub fn insert_migration_correction(
    conn: &Connection,
    module_id: i64,
    section: &str,
    original_text: &str,
    corrected_text: &str,
    reason: Option<&str>,
) -> Result<i64, StorageError> {
    conn.execute(
        "INSERT INTO migration_corrections (module_id, section, original_text, corrected_text, reason)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![module_id, section, original_text, corrected_text, reason],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    Ok(conn.last_insert_rowid())
}

pub fn get_migration_correction(
    conn: &Connection,
    correction_id: i64,
) -> Result<Option<CorrectionRow>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, module_id, section, original_text, corrected_text, reason, created_at
         FROM migration_corrections WHERE id = ?1"
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut rows = stmt.query_map(params![correction_id], |row| {
        Ok(CorrectionRow {
            id: row.get(0)?,
            module_id: row.get(1)?,
            section: row.get(2)?,
            original_text: row.get(3)?,
            corrected_text: row.get(4)?,
            reason: row.get(5)?,
            created_at: row.get(6)?,
        })
    }).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    match rows.next() {
        Some(Ok(row)) => Ok(Some(row)),
        Some(Err(e)) => Err(StorageError::SqliteError { message: e.to_string() }),
        None => Ok(None),
    }
}

#[derive(Debug, Clone)]
pub struct CorrectionRow {
    pub id: i64,
    pub module_id: i64,
    pub section: String,
    pub original_text: String,
    pub corrected_text: String,
    pub reason: Option<String>,
    pub created_at: i64,
}


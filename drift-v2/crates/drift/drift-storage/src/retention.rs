//! Data retention policies for drift.db.
//!
//! Three retention tiers:
//! - **Current**: Tables representing current project state. Old rows are cleaned
//!   by removing entries for files no longer in `file_metadata` (orphan cleanup).
//! - **Short** (default 30 days): Findings/violations from recent scans.
//! - **Medium** (default 90 days): Trend data, feedback, verification history.
//! - **Long** (default 365 days): Caches and decision history.
//!
//! Tables with UPSERT semantics (e.g. `pattern_confidence`, `impact_scores`)
//! are self-bounding and don't need time-based retention.

use rusqlite::{params, Connection};
use serde::Serialize;

use drift_core::errors::StorageError;

/// Configurable retention periods.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Short-lived findings (default 30 days).
    pub short_days: u32,
    /// Medium-lived trend/history data (default 90 days).
    pub medium_days: u32,
    /// Long-lived caches and decisions (default 365 days).
    pub long_days: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            short_days: 30,
            medium_days: 90,
            long_days: 365,
        }
    }
}

/// Report of what was cleaned.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RetentionReport {
    pub total_deleted: u64,
    pub per_table: Vec<TableCleanup>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TableCleanup {
    pub table: String,
    pub deleted: u64,
}

/// Apply the full retention policy to drift.db.
///
/// Runs inside a single transaction for atomicity.
/// Returns a report of how many rows were deleted per table.
pub fn apply_retention(
    conn: &Connection,
    policy: &RetentionPolicy,
) -> Result<RetentionReport, StorageError> {
    let start = std::time::Instant::now();
    let mut report = RetentionReport::default();

    // RAII transaction — auto-rollback on drop, auto-commit on .commit()
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| StorageError::SqliteError {
            message: format!("retention begin: {e}"),
        })?;

    apply_retention_inner(&tx, policy, &mut report)?;

    tx.commit()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    report.duration_ms = start.elapsed().as_millis() as u64;
    report.total_deleted = report.per_table.iter().map(|t| t.deleted).sum();
    Ok(report)
}

fn apply_retention_inner(
    conn: &Connection,
    policy: &RetentionPolicy,
    report: &mut RetentionReport,
) -> Result<(), StorageError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let short_cutoff = now - (policy.short_days as i64 * 86400);
    let medium_cutoff = now - (policy.medium_days as i64 * 86400);
    let long_cutoff = now - (policy.long_days as i64 * 86400);

    // ─── Orphan cleanup (Current tier) ──────────────────────────────
    // Remove rows referencing files no longer tracked in file_metadata.

    cleanup_orphans_by_file(conn, "detections", "file", report)?;
    cleanup_orphans_by_file(conn, "functions", "file", report)?;
    cleanup_orphans_by_file(conn, "boundaries", "file", report)?;
    cleanup_orphans_by_file(conn, "constants", "file", report)?;
    cleanup_orphans_by_file(conn, "secrets", "file", report)?;
    cleanup_orphans_by_file(conn, "env_variables", "file", report)?;
    cleanup_orphans_by_file(conn, "wrappers", "file", report)?;
    cleanup_orphans_by_file(conn, "crypto_findings", "file", report)?;
    cleanup_orphans_by_file(conn, "owasp_findings", "file", report)?;

    // ─── Short retention (30 days) ──────────────────────────────────

    cleanup_by_time(conn, "detections", "created_at", short_cutoff, report)?;
    cleanup_by_time(conn, "outliers", "created_at", short_cutoff, report)?;
    cleanup_by_time(conn, "violations", "created_at", short_cutoff, report)?;
    cleanup_by_time(conn, "gate_results", "run_at", short_cutoff, report)?;
    cleanup_by_time(conn, "error_gaps", "created_at", short_cutoff, report)?;
    cleanup_by_time(conn, "taint_flows", "created_at", short_cutoff, report)?;
    cleanup_by_time(conn, "crypto_findings", "created_at", short_cutoff, report)?;
    cleanup_by_time(conn, "owasp_findings", "created_at", short_cutoff, report)?;
    cleanup_by_time(conn, "secrets", "created_at", short_cutoff, report)?;
    cleanup_by_time(conn, "degradation_alerts", "created_at", short_cutoff, report)?;
    cleanup_by_time(conn, "policy_results", "run_at", short_cutoff, report)?;

    // ─── Medium retention (90 days) ─────────────────────────────────

    cleanup_by_time(conn, "scan_history", "started_at", medium_cutoff, report)?;
    cleanup_by_time(conn, "audit_snapshots", "created_at", medium_cutoff, report)?;
    cleanup_by_time(conn, "health_trends", "recorded_at", medium_cutoff, report)?;
    cleanup_by_time(conn, "feedback", "created_at", medium_cutoff, report)?;
    cleanup_by_time(conn, "constraint_verifications", "verified_at", medium_cutoff, report)?;
    cleanup_by_time(conn, "contract_mismatches", "created_at", medium_cutoff, report)?;
    cleanup_by_time(conn, "dna_mutations", "detected_at", medium_cutoff, report)?;
    cleanup_by_time(conn, "coupling_cycles", "created_at", medium_cutoff, report)?;
    cleanup_by_time(conn, "decomposition_decisions", "created_at", medium_cutoff, report)?;

    // ─── Long retention (365 days) ──────────────────────────────────

    cleanup_by_time(conn, "parse_cache", "created_at", long_cutoff, report)?;
    cleanup_by_time(conn, "context_cache", "created_at", long_cutoff, report)?;
    cleanup_by_time(conn, "simulations", "created_at", long_cutoff, report)?;
    cleanup_by_time(conn, "decisions", "created_at", long_cutoff, report)?;
    cleanup_by_time(conn, "migration_corrections", "created_at", long_cutoff, report)?;
    cleanup_by_time(conn, "migration_modules", "created_at", long_cutoff, report)?;
    cleanup_by_time(conn, "migration_projects", "created_at", long_cutoff, report)?;

    Ok(())
}

/// Delete rows from `table` where `file_column` is not in file_metadata.path.
fn cleanup_orphans_by_file(
    conn: &Connection,
    table: &str,
    file_column: &str,
    report: &mut RetentionReport,
) -> Result<(), StorageError> {
    // Use a safe SQL construction — table/column names are hardcoded strings from this module.
    let sql = format!(
        "DELETE FROM {table} WHERE {file_column} NOT IN (SELECT path FROM file_metadata)"
    );
    let deleted = conn
        .execute(&sql, [])
        .map_err(|e| StorageError::SqliteError {
            message: format!("{table}: {e}"),
        })? as u64;

    if deleted > 0 {
        report.per_table.push(TableCleanup {
            table: format!("{table} (orphan)"),
            deleted,
        });
    }
    Ok(())
}

/// Delete rows from `table` where `time_column` < `cutoff`.
fn cleanup_by_time(
    conn: &Connection,
    table: &str,
    time_column: &str,
    cutoff: i64,
    report: &mut RetentionReport,
) -> Result<(), StorageError> {
    let sql = format!("DELETE FROM {table} WHERE {time_column} < ?1");
    let deleted = conn
        .execute(&sql, params![cutoff])
        .map_err(|e| StorageError::SqliteError {
            message: format!("{table}: {e}"),
        })? as u64;

    if deleted > 0 {
        report.per_table.push(TableCleanup {
            table: table.to_string(),
            deleted,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        // Minimal schema for testing
        conn.execute_batch(
            "CREATE TABLE file_metadata (path TEXT PRIMARY KEY);
             CREATE TABLE detections (id INTEGER PRIMARY KEY, file TEXT, created_at INTEGER DEFAULT 0);
             CREATE TABLE violations (id TEXT PRIMARY KEY, file TEXT, created_at INTEGER DEFAULT 0);
             CREATE TABLE scan_history (id INTEGER PRIMARY KEY, started_at INTEGER DEFAULT 0);
             CREATE TABLE parse_cache (content_hash BLOB PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE feedback (id INTEGER PRIMARY KEY, pattern_id TEXT, created_at INTEGER DEFAULT 0);
             CREATE TABLE outliers (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE gate_results (id INTEGER PRIMARY KEY, run_at INTEGER DEFAULT 0);
             CREATE TABLE error_gaps (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE taint_flows (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE crypto_findings (id INTEGER PRIMARY KEY, file TEXT, created_at INTEGER DEFAULT 0);
             CREATE TABLE owasp_findings (id TEXT PRIMARY KEY, file TEXT, created_at INTEGER DEFAULT 0);
             CREATE TABLE secrets (id INTEGER PRIMARY KEY, file TEXT, created_at INTEGER DEFAULT 0);
             CREATE TABLE degradation_alerts (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE policy_results (id INTEGER PRIMARY KEY, run_at INTEGER DEFAULT 0);
             CREATE TABLE audit_snapshots (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE health_trends (id INTEGER PRIMARY KEY, recorded_at INTEGER DEFAULT 0);
             CREATE TABLE constraint_verifications (id INTEGER PRIMARY KEY, verified_at INTEGER DEFAULT 0);
             CREATE TABLE contract_mismatches (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE dna_mutations (id TEXT PRIMARY KEY, detected_at INTEGER DEFAULT 0);
             CREATE TABLE coupling_cycles (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE decomposition_decisions (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE context_cache (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE simulations (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE decisions (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE migration_corrections (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE migration_modules (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE migration_projects (id INTEGER PRIMARY KEY, created_at INTEGER DEFAULT 0);
             CREATE TABLE functions (id INTEGER PRIMARY KEY, file TEXT);
             CREATE TABLE boundaries (id INTEGER PRIMARY KEY, file TEXT, created_at INTEGER DEFAULT 0);
             CREATE TABLE constants (id INTEGER PRIMARY KEY, file TEXT, created_at INTEGER DEFAULT 0);
             CREATE TABLE env_variables (id INTEGER PRIMARY KEY, file TEXT, created_at INTEGER DEFAULT 0);
             CREATE TABLE wrappers (id INTEGER PRIMARY KEY, file TEXT, created_at INTEGER DEFAULT 0);",
        )
        .unwrap();
        conn
    }

    #[test]
    fn test_orphan_cleanup() {
        let conn = setup_db();
        // tracked file
        conn.execute("INSERT INTO file_metadata (path) VALUES ('src/a.ts')", []).unwrap();
        // detections: one for tracked file, one for removed file
        conn.execute("INSERT INTO detections (file, created_at) VALUES ('src/a.ts', 9999999999)", []).unwrap();
        conn.execute("INSERT INTO detections (file, created_at) VALUES ('src/removed.ts', 9999999999)", []).unwrap();

        let report = apply_retention(&conn, &RetentionPolicy { short_days: 9999, medium_days: 9999, long_days: 9999 }).unwrap();

        // Only the orphan should be deleted
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM detections", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "Should keep detection for tracked file");
        assert!(report.total_deleted >= 1, "Should report orphan deletion");
    }

    #[test]
    fn test_time_based_cleanup() {
        let conn = setup_db();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Add file so orphan cleanup doesn't interfere
        conn.execute("INSERT INTO file_metadata (path) VALUES ('src/a.ts')", []).unwrap();

        // Old violation (60 days ago)
        conn.execute(
            "INSERT INTO violations (id, file, created_at) VALUES ('v1', 'src/a.ts', ?1)",
            params![now - 60 * 86400],
        ).unwrap();

        // Recent violation (1 day ago)
        conn.execute(
            "INSERT INTO violations (id, file, created_at) VALUES ('v2', 'src/a.ts', ?1)",
            params![now - 86400],
        ).unwrap();

        let report = apply_retention(&conn, &RetentionPolicy { short_days: 30, medium_days: 90, long_days: 365 }).unwrap();

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM violations", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "Should keep only recent violation");
        assert!(report.total_deleted >= 1);
    }

    #[test]
    fn test_empty_db_no_errors() {
        let conn = setup_db();
        // No file_metadata = all orphan cleanups will noop (no rows to delete)
        let report = apply_retention(&conn, &RetentionPolicy::default()).unwrap();
        assert_eq!(report.total_deleted, 0);
    }
}

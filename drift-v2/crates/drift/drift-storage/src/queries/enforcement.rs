//! Queries for enforcement tables: violations, gate_results, audit_snapshots,
//! health_trends, feedback.

use rusqlite::{params, Connection};

use drift_core::errors::StorageError;

// ─── Row Types ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ViolationRow {
    pub id: String,
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    pub severity: String,
    pub pattern_id: String,
    pub rule_id: String,
    pub message: String,
    pub quick_fix_strategy: Option<String>,
    pub quick_fix_description: Option<String>,
    pub cwe_id: Option<u32>,
    pub owasp_category: Option<String>,
    pub suppressed: bool,
    pub is_new: bool,
}

#[derive(Debug, Clone)]
pub struct GateResultRow {
    pub gate_id: String,
    pub status: String,
    pub passed: bool,
    pub score: f64,
    pub summary: String,
    pub violation_count: u32,
    pub warning_count: u32,
    pub execution_time_ms: u64,
    pub details: Option<String>,
    pub error: Option<String>,
    pub run_at: u64,
}

#[derive(Debug, Clone)]
pub struct AuditSnapshotRow {
    pub health_score: f64,
    pub avg_confidence: f64,
    pub approval_ratio: f64,
    pub compliance_rate: f64,
    pub cross_validation_rate: f64,
    pub duplicate_free_rate: f64,
    pub pattern_count: u32,
    pub category_scores: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct HealthTrendRow {
    pub metric_name: String,
    pub metric_value: f64,
    pub recorded_at: u64,
}

#[derive(Debug, Clone)]
pub struct FeedbackRow {
    pub violation_id: String,
    pub pattern_id: String,
    pub detector_id: String,
    pub action: String,
    pub dismissal_reason: Option<String>,
    pub reason: Option<String>,
    pub author: Option<String>,
    pub created_at: u64,
}

// ─── Violations ──────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn insert_violation(
    conn: &Connection,
    v: &ViolationRow,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO violations (id, file, line, column_num, end_line, end_column, severity, pattern_id, rule_id, message, quick_fix_strategy, quick_fix_description, cwe_id, owasp_category, suppressed, is_new)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![v.id, v.file, v.line, v.column, v.end_line, v.end_column, v.severity, v.pattern_id, v.rule_id, v.message, v.quick_fix_strategy, v.quick_fix_description, v.cwe_id, v.owasp_category, v.suppressed as i32, v.is_new as i32],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn query_violations_by_file(
    conn: &Connection,
    file: &str,
) -> Result<Vec<ViolationRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, column_num, end_line, end_column, severity, pattern_id, rule_id, message, quick_fix_strategy, quick_fix_description, cwe_id, owasp_category, suppressed, is_new
             FROM violations WHERE file = ?1 ORDER BY line",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![file], |row| {
            Ok(ViolationRow {
                id: row.get(0)?,
                file: row.get(1)?,
                line: row.get(2)?,
                column: row.get(3)?,
                end_line: row.get(4)?,
                end_column: row.get(5)?,
                severity: row.get(6)?,
                pattern_id: row.get(7)?,
                rule_id: row.get(8)?,
                message: row.get(9)?,
                quick_fix_strategy: row.get(10)?,
                quick_fix_description: row.get(11)?,
                cwe_id: row.get(12)?,
                owasp_category: row.get(13)?,
                suppressed: row.get::<_, i32>(14)? != 0,
                is_new: row.get::<_, i32>(15).unwrap_or(0) != 0,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

pub fn query_all_violations(conn: &Connection) -> Result<Vec<ViolationRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, file, line, column_num, end_line, end_column, severity, pattern_id, rule_id, message, quick_fix_strategy, quick_fix_description, cwe_id, owasp_category, suppressed, is_new
             FROM violations ORDER BY file, line",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(ViolationRow {
                id: row.get(0)?,
                file: row.get(1)?,
                line: row.get(2)?,
                column: row.get(3)?,
                end_line: row.get(4)?,
                end_column: row.get(5)?,
                severity: row.get(6)?,
                pattern_id: row.get(7)?,
                rule_id: row.get(8)?,
                message: row.get(9)?,
                quick_fix_strategy: row.get(10)?,
                quick_fix_description: row.get(11)?,
                cwe_id: row.get(12)?,
                owasp_category: row.get(13)?,
                suppressed: row.get::<_, i32>(14)? != 0,
                is_new: row.get::<_, i32>(15).unwrap_or(0) != 0,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Gate Results ────────────────────────────────────────────────────

pub fn insert_gate_result(
    conn: &Connection,
    g: &GateResultRow,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO gate_results (gate_id, status, passed, score, summary, violation_count, warning_count, execution_time_ms, details, error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![g.gate_id, g.status, g.passed as i32, g.score, g.summary, g.violation_count, g.warning_count, g.execution_time_ms, g.details, g.error],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn query_gate_results(conn: &Connection) -> Result<Vec<GateResultRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT gate_id, status, passed, score, summary, violation_count, warning_count, execution_time_ms, details, error, run_at
             FROM (
                 SELECT *, ROW_NUMBER() OVER (PARTITION BY gate_id ORDER BY run_at DESC) AS rn
                 FROM gate_results
             ) WHERE rn = 1
             ORDER BY gate_id",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(GateResultRow {
                gate_id: row.get(0)?,
                status: row.get(1)?,
                passed: row.get::<_, i32>(2)? != 0,
                score: row.get(3)?,
                summary: row.get(4)?,
                violation_count: row.get(5)?,
                warning_count: row.get::<_, u32>(6).unwrap_or(0),
                execution_time_ms: row.get(7)?,
                details: row.get(8)?,
                error: row.get(9)?,
                run_at: row.get(10)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query historical runs for a specific gate, ordered newest-first.
pub fn query_gate_history(
    conn: &Connection,
    gate_id: &str,
    limit: u32,
) -> Result<Vec<GateResultRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT gate_id, status, passed, score, summary, violation_count, warning_count,
                    execution_time_ms, details, error, run_at
             FROM gate_results WHERE gate_id = ?1 ORDER BY run_at DESC LIMIT ?2",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![gate_id, limit], |row| {
            Ok(GateResultRow {
                gate_id: row.get(0)?,
                status: row.get(1)?,
                passed: row.get::<_, i32>(2)? != 0,
                score: row.get(3)?,
                summary: row.get(4)?,
                violation_count: row.get(5)?,
                warning_count: row.get::<_, u32>(6).unwrap_or(0),
                execution_time_ms: row.get(7)?,
                details: row.get(8)?,
                error: row.get(9)?,
                run_at: row.get(10)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Audit Snapshots ─────────────────────────────────────────────────

pub fn insert_audit_snapshot(
    conn: &Connection,
    s: &AuditSnapshotRow,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO audit_snapshots (health_score, avg_confidence, approval_ratio, compliance_rate, cross_validation_rate, duplicate_free_rate, pattern_count, category_scores)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![s.health_score, s.avg_confidence, s.approval_ratio, s.compliance_rate, s.cross_validation_rate, s.duplicate_free_rate, s.pattern_count, s.category_scores],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn query_audit_snapshots(
    conn: &Connection,
    limit: u32,
) -> Result<Vec<AuditSnapshotRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT health_score, avg_confidence, approval_ratio, compliance_rate, cross_validation_rate, duplicate_free_rate, pattern_count, category_scores, created_at
             FROM audit_snapshots ORDER BY created_at DESC LIMIT ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![limit], |row| {
            Ok(AuditSnapshotRow {
                health_score: row.get(0)?,
                avg_confidence: row.get(1)?,
                approval_ratio: row.get(2)?,
                compliance_rate: row.get(3)?,
                cross_validation_rate: row.get(4)?,
                duplicate_free_rate: row.get(5)?,
                pattern_count: row.get(6)?,
                category_scores: row.get(7)?,
                created_at: row.get(8)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Health Trends ───────────────────────────────────────────────────

pub fn insert_health_trend(
    conn: &Connection,
    metric_name: &str,
    metric_value: f64,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO health_trends (metric_name, metric_value) VALUES (?1, ?2)",
        params![metric_name, metric_value],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn query_health_trends(
    conn: &Connection,
    metric_name: &str,
    limit: u32,
) -> Result<Vec<HealthTrendRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT metric_name, metric_value, recorded_at
             FROM health_trends WHERE metric_name = ?1 ORDER BY recorded_at DESC LIMIT ?2",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![metric_name, limit], |row| {
            Ok(HealthTrendRow {
                metric_name: row.get(0)?,
                metric_value: row.get(1)?,
                recorded_at: row.get(2)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Feedback ────────────────────────────────────────────────────────

pub fn insert_feedback(
    conn: &Connection,
    f: &FeedbackRow,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO feedback (violation_id, pattern_id, detector_id, action, dismissal_reason, reason, author)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![f.violation_id, f.pattern_id, f.detector_id, f.action, f.dismissal_reason, f.reason, f.author],
    ).map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

pub fn query_feedback_by_detector(
    conn: &Connection,
    detector_id: &str,
) -> Result<Vec<FeedbackRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT violation_id, pattern_id, detector_id, action, dismissal_reason, reason, author, created_at
             FROM feedback WHERE detector_id = ?1 ORDER BY created_at DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![detector_id], |row| {
            Ok(FeedbackRow {
                violation_id: row.get(0)?,
                pattern_id: row.get(1)?,
                detector_id: row.get(2)?,
                action: row.get(3)?,
                dismissal_reason: row.get(4)?,
                reason: row.get(5)?,
                author: row.get(6)?,
                created_at: row.get(7)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query all feedback rows for a given pattern_id.
pub fn query_feedback_by_pattern(
    conn: &Connection,
    pattern_id: &str,
) -> Result<Vec<FeedbackRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT violation_id, pattern_id, detector_id, action, dismissal_reason, reason, author, created_at
             FROM feedback WHERE pattern_id = ?1 ORDER BY created_at DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![pattern_id], |row| {
            Ok(FeedbackRow {
                violation_id: row.get(0)?,
                pattern_id: row.get(1)?,
                detector_id: row.get(2)?,
                action: row.get(3)?,
                dismissal_reason: row.get(4)?,
                reason: row.get(5)?,
                author: row.get(6)?,
                created_at: row.get(7)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Compute (alpha_delta, beta_delta) adjustments for a pattern from its feedback rows.
///
/// Maps action strings to Bayesian parameter deltas using the same logic as
/// `ConfidenceFeedback::compute_adjustment()`:
/// - "fix" → (1.0, 0.0)
/// - "dismiss" with reason "false_positive" → (0.0, 0.5)
/// - "dismiss" with reason "not_applicable" → (0.0, 0.25)
/// - "dismiss" with reason "wont_fix" or "duplicate" → (0.0, 0.0)
/// - "dismiss" without reason → (0.0, 0.25)
/// - "suppress" → (0.0, 0.1)
/// - "escalate" → (0.5, 0.0)
pub fn query_feedback_adjustments(
    conn: &Connection,
    pattern_id: &str,
) -> Result<Vec<(f64, f64)>, StorageError> {
    let rows = query_feedback_by_pattern(conn, pattern_id)?;
    Ok(rows
        .iter()
        .map(|f| feedback_action_to_deltas(&f.action, f.dismissal_reason.as_deref()))
        .collect())
}

/// Get the pattern_id for a given violation.
pub fn get_violation_pattern_id(
    conn: &Connection,
    violation_id: &str,
) -> Result<Option<String>, StorageError> {
    let mut stmt = conn
        .prepare_cached("SELECT pattern_id FROM violations WHERE id = ?1")
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let result = stmt
        .query_row(params![violation_id], |row| row.get::<_, String>(0))
        .ok();

    Ok(result)
}

/// Feedback statistics for audit metrics.
#[derive(Debug, Clone, Default)]
pub struct FeedbackStats {
    pub total_count: u32,
    pub fix_count: u32,
    pub dismiss_count: u32,
    pub suppress_count: u32,
    pub escalate_count: u32,
}

/// Query aggregate feedback statistics.
pub fn query_feedback_stats(conn: &Connection) -> Result<FeedbackStats, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT action, COUNT(*) FROM feedback GROUP BY action"
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let mut stats = FeedbackStats::default();
    for row in rows {
        let (action, count) = row.map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
        match action.as_str() {
            "fix" => stats.fix_count = count,
            "dismiss" => stats.dismiss_count = count,
            "suppress" => stats.suppress_count = count,
            "escalate" => stats.escalate_count = count,
            _ => {}
        }
        stats.total_count += count;
    }
    Ok(stats)
}

/// Query count of violations needing review (not suppressed, not dismissed).
pub fn count_needs_review(conn: &Connection) -> Result<u32, StorageError> {
    let count: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM violations WHERE suppressed = 0 AND id NOT IN (SELECT violation_id FROM feedback WHERE action IN ('dismiss', 'fix'))",
            [],
            |row| row.get(0),
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(count)
}

/// Map a feedback action string + optional dismissal reason to (alpha_delta, beta_delta).
fn feedback_action_to_deltas(action: &str, dismissal_reason: Option<&str>) -> (f64, f64) {
    match action {
        "fix" => (1.0, 0.0),
        "dismiss" => match dismissal_reason {
            Some("false_positive") => (0.0, 0.5),
            Some("not_applicable") => (0.0, 0.25),
            Some("wont_fix") | Some("duplicate") => (0.0, 0.0),
            _ => (0.0, 0.25),
        },
        "suppress" => (0.0, 0.1),
        "escalate" => (0.5, 0.0),
        _ => (0.0, 0.0),
    }
}

// ─── Policy Results ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyResultRow {
    pub id: i64,
    pub policy_name: String,
    pub aggregation_mode: String,
    pub overall_passed: bool,
    pub overall_score: f64,
    pub gate_count: i64,
    pub gates_passed: i64,
    pub gates_failed: i64,
    pub details: Option<String>,
    pub run_at: i64,
}

/// Insert a policy result.
pub fn insert_policy_result(conn: &Connection, row: &PolicyResultRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO policy_results (policy_name, aggregation_mode, overall_passed, overall_score, gate_count, gates_passed, gates_failed, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            row.policy_name,
            row.aggregation_mode,
            row.overall_passed as i32,
            row.overall_score,
            row.gate_count,
            row.gates_passed,
            row.gates_failed,
            row.details,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Query recent policy results.
pub fn query_recent_policy_results(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<PolicyResultRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, policy_name, aggregation_mode, overall_passed, overall_score, gate_count, gates_passed, gates_failed, details, run_at
             FROM policy_results ORDER BY run_at DESC LIMIT ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![limit as i64], |row| {
            Ok(PolicyResultRow {
                id: row.get(0)?,
                policy_name: row.get(1)?,
                aggregation_mode: row.get(2)?,
                overall_passed: row.get::<_, i32>(3)? != 0,
                overall_score: row.get(4)?,
                gate_count: row.get(5)?,
                gates_passed: row.get(6)?,
                gates_failed: row.get(7)?,
                details: row.get(8)?,
                run_at: row.get(9)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

// ─── Degradation Alerts ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DegradationAlertRow {
    pub id: i64,
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub current_value: f64,
    pub previous_value: f64,
    pub delta: f64,
    pub created_at: i64,
}

/// Insert a degradation alert.
pub fn insert_degradation_alert(conn: &Connection, row: &DegradationAlertRow) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO degradation_alerts (alert_type, severity, message, current_value, previous_value, delta)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            row.alert_type,
            row.severity,
            row.message,
            row.current_value,
            row.previous_value,
            row.delta,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Query recent degradation alerts.
pub fn query_recent_degradation_alerts(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<DegradationAlertRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, alert_type, severity, message, current_value, previous_value, delta, created_at
             FROM degradation_alerts ORDER BY created_at DESC LIMIT ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![limit as i64], |row| {
            Ok(DegradationAlertRow {
                id: row.get(0)?,
                alert_type: row.get(1)?,
                severity: row.get(2)?,
                message: row.get(3)?,
                current_value: row.get(4)?,
                previous_value: row.get(5)?,
                delta: row.get(6)?,
                created_at: row.get(7)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Clear degradation alerts older than 24 hours (TTL-based cleanup).
pub fn clear_recovered_alerts(conn: &Connection) -> Result<u64, StorageError> {
    let deleted = conn
        .execute(
            "DELETE FROM degradation_alerts WHERE created_at < unixepoch() - 86400",
            [],
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(deleted as u64)
}

// ─── Pattern Status ──────────────────────────────────────────────────

/// A pattern status row from the pattern_status table.
#[derive(Debug, Clone)]
pub struct PatternStatusRow {
    pub pattern_id: String,
    pub status: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<i64>,
    pub confidence_at_approval: Option<f64>,
    pub reason: Option<String>,
    pub updated_at: i64,
}

/// Insert or update a pattern status record.
pub fn upsert_pattern_status(
    conn: &Connection,
    row: &PatternStatusRow,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO pattern_status (pattern_id, status, approved_by, approved_at, confidence_at_approval, reason, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(pattern_id) DO UPDATE SET
           status = CASE
             WHEN excluded.approved_by = 'auto' AND pattern_status.approved_by IS NOT NULL AND pattern_status.approved_by != 'auto'
             THEN pattern_status.status
             ELSE excluded.status
           END,
           approved_by = CASE
             WHEN excluded.approved_by = 'auto' AND pattern_status.approved_by IS NOT NULL AND pattern_status.approved_by != 'auto'
             THEN pattern_status.approved_by
             ELSE excluded.approved_by
           END,
           approved_at = CASE
             WHEN excluded.approved_by = 'auto' AND pattern_status.approved_by IS NOT NULL AND pattern_status.approved_by != 'auto'
             THEN pattern_status.approved_at
             ELSE excluded.approved_at
           END,
           confidence_at_approval = CASE
             WHEN excluded.approved_by = 'auto' AND pattern_status.approved_by IS NOT NULL AND pattern_status.approved_by != 'auto'
             THEN pattern_status.confidence_at_approval
             ELSE excluded.confidence_at_approval
           END,
           reason = CASE
             WHEN excluded.approved_by = 'auto' AND pattern_status.approved_by IS NOT NULL AND pattern_status.approved_by != 'auto'
             THEN pattern_status.reason
             ELSE excluded.reason
           END,
           updated_at = excluded.updated_at",
        params![
            row.pattern_id,
            row.status,
            row.approved_by,
            row.approved_at,
            row.confidence_at_approval,
            row.reason,
            row.updated_at,
        ],
    )
    .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;
    Ok(())
}

/// Query pattern status by pattern_id. Returns None if not tracked.
pub fn query_pattern_status(
    conn: &Connection,
    pattern_id: &str,
) -> Result<Option<PatternStatusRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT pattern_id, status, approved_by, approved_at, confidence_at_approval, reason, updated_at
             FROM pattern_status WHERE pattern_id = ?1",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let result = stmt
        .query_row(params![pattern_id], |row| {
            Ok(PatternStatusRow {
                pattern_id: row.get(0)?,
                status: row.get(1)?,
                approved_by: row.get(2)?,
                approved_at: row.get(3)?,
                confidence_at_approval: row.get(4)?,
                reason: row.get(5)?,
                updated_at: row.get(6)?,
            })
        });

    match result {
        Ok(row) => Ok(Some(row)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(StorageError::SqliteError { message: e.to_string() }),
    }
}

/// Query all pattern statuses, optionally filtered by status string.
pub fn query_all_pattern_statuses(
    conn: &Connection,
    status_filter: Option<&str>,
) -> Result<Vec<PatternStatusRow>, StorageError> {
    let (sql, use_filter) = if status_filter.is_some() {
        (
            "SELECT pattern_id, status, approved_by, approved_at, confidence_at_approval, reason, updated_at
             FROM pattern_status WHERE status = ?1 ORDER BY updated_at DESC",
            true,
        )
    } else {
        (
            "SELECT pattern_id, status, approved_by, approved_at, confidence_at_approval, reason, updated_at
             FROM pattern_status ORDER BY updated_at DESC",
            false,
        )
    };

    let mut stmt = conn
        .prepare_cached(sql)
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = if use_filter {
        stmt.query_map(params![status_filter.unwrap()], map_pattern_status_row)
            .map_err(|e| StorageError::SqliteError { message: e.to_string() })?
    } else {
        stmt.query_map([], map_pattern_status_row)
            .map_err(|e| StorageError::SqliteError { message: e.to_string() })?
    };

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Count patterns by status.
pub fn count_patterns_by_status(conn: &Connection) -> Result<Vec<(String, u32)>, StorageError> {
    let mut stmt = conn
        .prepare_cached("SELECT status, COUNT(*) FROM pattern_status GROUP BY status")
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?)))
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

fn map_pattern_status_row(row: &rusqlite::Row) -> rusqlite::Result<PatternStatusRow> {
    Ok(PatternStatusRow {
        pattern_id: row.get(0)?,
        status: row.get(1)?,
        approved_by: row.get(2)?,
        approved_at: row.get(3)?,
        confidence_at_approval: row.get(4)?,
        reason: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

// ─── Pattern Audit Data Builder ──────────────────────────────────────

/// Lightweight row returned by the audit data builder query.
/// Joins pattern_confidence + detection counts + outlier counts + pattern_status.
#[derive(Debug, Clone)]
pub struct PatternAuditRow {
    pub pattern_id: String,
    pub category: String,
    pub confidence: f64,
    pub location_count: usize,
    pub outlier_count: usize,
    pub status: String,
    pub has_error_issues: bool,
}

/// Build pattern audit data by joining upstream tables:
/// - pattern_confidence for confidence scores
/// - detections for location counts and category
/// - outliers for outlier counts
/// - pattern_status for current lifecycle status
/// - violations for error-level issues
///
/// This is the single source of truth for `PatternAuditData` construction.
pub fn query_patterns_for_audit(conn: &Connection) -> Result<Vec<PatternAuditRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT
                pc.pattern_id,
                COALESCE(d_cat.category, 'unknown') AS category,
                pc.posterior_mean AS confidence,
                COALESCE(d_cnt.loc_count, 0) AS location_count,
                COALESCE(o_cnt.outlier_count, 0) AS outlier_count,
                COALESCE(ps.status, 'discovered') AS status,
                COALESCE(v_err.error_count, 0) > 0 AS has_error_issues
             FROM pattern_confidence pc
             LEFT JOIN (
                 SELECT pattern_id, category,
                        ROW_NUMBER() OVER (PARTITION BY pattern_id ORDER BY COUNT(*) DESC) AS rn
                 FROM detections GROUP BY pattern_id, category
             ) d_cat ON d_cat.pattern_id = pc.pattern_id AND d_cat.rn = 1
             LEFT JOIN (
                 SELECT pattern_id, COUNT(*) AS loc_count
                 FROM detections GROUP BY pattern_id
             ) d_cnt ON d_cnt.pattern_id = pc.pattern_id
             LEFT JOIN (
                 SELECT pattern_id, COUNT(*) AS outlier_count
                 FROM outliers GROUP BY pattern_id
             ) o_cnt ON o_cnt.pattern_id = pc.pattern_id
             LEFT JOIN pattern_status ps ON ps.pattern_id = pc.pattern_id
             LEFT JOIN (
                 SELECT pattern_id, COUNT(*) AS error_count
                 FROM violations WHERE severity IN ('critical', 'error') AND suppressed = 0
                 GROUP BY pattern_id
             ) v_err ON v_err.pattern_id = pc.pattern_id
             ORDER BY pc.posterior_mean DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(PatternAuditRow {
                pattern_id: row.get(0)?,
                category: row.get(1)?,
                confidence: row.get(2)?,
                location_count: row.get::<_, i64>(3)? as usize,
                outlier_count: row.get::<_, i64>(4)? as usize,
                status: row.get(5)?,
                has_error_issues: row.get::<_, i32>(6)? != 0,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

/// Query degradation alerts by type.
pub fn query_degradation_alerts_by_type(
    conn: &Connection,
    alert_type: &str,
) -> Result<Vec<DegradationAlertRow>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT id, alert_type, severity, message, current_value, previous_value, delta, created_at
             FROM degradation_alerts WHERE alert_type = ?1 ORDER BY created_at DESC",
        )
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    let rows = stmt
        .query_map(params![alert_type], |row| {
            Ok(DegradationAlertRow {
                id: row.get(0)?,
                alert_type: row.get(1)?,
                severity: row.get(2)?,
                message: row.get(3)?,
                current_value: row.get(4)?,
                previous_value: row.get(5)?,
                delta: row.get(6)?,
                created_at: row.get(7)?,
            })
        })
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| StorageError::SqliteError { message: e.to_string() })
}

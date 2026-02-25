//! Tests for materialized views: status, security, trends.
//! These aggregation queries feed the UI/CLI status display.

use drift_storage::materialized::{security, status, trends};
use drift_storage::migrations::run_migrations;
use drift_storage::queries::enforcement::*;
use rusqlite::Connection;

fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    run_migrations(&conn).unwrap();
    conn
}

// ═══════════════════════════════════════════════════════════════════════════
// STATUS VIEW
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn status_view_empty_db() {
    let conn = setup_db();
    let s = status::refresh_status(&conn).unwrap();
    assert!((s.health_score - 0.0).abs() < 0.001);
    assert_eq!(s.violation_count, 0);
    assert_eq!(s.gate_pass_count, 0);
    assert_eq!(s.gate_fail_count, 0);
}

#[test]
fn status_view_with_data() {
    let conn = setup_db();

    // Insert audit snapshot
    insert_audit_snapshot(&conn, &AuditSnapshotRow {
        health_score: 0.85, avg_confidence: 0.72,
        approval_ratio: 0.9, compliance_rate: 0.95,
        cross_validation_rate: 0.88, duplicate_free_rate: 0.99,
        pattern_count: 42, category_scores: None, created_at: 0,
    }).unwrap();

    // Insert unsuppressed violation
    insert_violation(&conn, &ViolationRow {
        id: "v1".into(), file: "a.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "error".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();
    // Insert suppressed violation (should NOT count)
    insert_violation(&conn, &ViolationRow {
        id: "v2".into(), file: "a.ts".into(), line: 2,
        column: None, end_line: None, end_column: None,
        severity: "error".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: true, is_new: false,
    }).unwrap();

    // Insert gate results
    insert_gate_result(&conn, &GateResultRow {
        gate_id: "confidence".into(), status: "passed".into(), passed: true,
        score: 0.9, summary: "ok".into(), violation_count: 0,
        warning_count: 0, execution_time_ms: 100, details: None, error: None, run_at: 1000,
    }).unwrap();
    insert_gate_result(&conn, &GateResultRow {
        gate_id: "coverage".into(), status: "failed".into(), passed: false,
        score: 0.3, summary: "low".into(), violation_count: 5,
        warning_count: 0, execution_time_ms: 50, details: None, error: None, run_at: 1000,
    }).unwrap();

    let s = status::refresh_status(&conn).unwrap();
    assert!((s.health_score - 0.85).abs() < 0.001);
    assert_eq!(s.violation_count, 1); // only unsuppressed
    assert_eq!(s.gate_pass_count, 1);
    assert_eq!(s.gate_fail_count, 1);
    assert_eq!(s.pattern_count, 42);
}

// ═══════════════════════════════════════════════════════════════════════════
// SECURITY VIEW
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn security_view_empty_db() {
    let conn = setup_db();
    let s = security::refresh_security(&conn).unwrap();
    assert_eq!(s.critical_count, 0);
    assert_eq!(s.high_count, 0);
    assert_eq!(s.total_security_violations, 0);
}

#[test]
fn security_view_counts_by_severity() {
    let conn = setup_db();

    // Critical: error + cwe_id + not suppressed
    insert_violation(&conn, &ViolationRow {
        id: "sc1".into(), file: "a.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "error".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: Some(89), owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    // High: warning + cwe_id + not suppressed
    insert_violation(&conn, &ViolationRow {
        id: "sc2".into(), file: "b.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "warning".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: Some(79), owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    // Suppressed security (should NOT count)
    insert_violation(&conn, &ViolationRow {
        id: "sc3".into(), file: "c.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "error".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: Some(95), owasp_category: None, suppressed: true, is_new: false,
    }).unwrap();

    // Non-security (no cwe_id, should NOT count)
    insert_violation(&conn, &ViolationRow {
        id: "sc4".into(), file: "d.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "error".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    let s = security::refresh_security(&conn).unwrap();
    assert_eq!(s.critical_count, 1);
    assert_eq!(s.high_count, 1);
    assert_eq!(s.total_security_violations, 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// TRENDS VIEW
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn trends_view_empty_db() {
    let conn = setup_db();
    let points = trends::query_health_trend(&conn, 30).unwrap();
    assert!(points.is_empty());
}

#[test]
fn trends_view_returns_health_score_points() {
    let conn = setup_db();

    // Insert health_score trend data
    insert_health_trend(&conn, "health_score", 0.85).unwrap();
    insert_health_trend(&conn, "health_score", 0.87).unwrap();
    // Non-health_score metric (should NOT appear)
    insert_health_trend(&conn, "confidence", 0.72).unwrap();

    let points = trends::query_health_trend(&conn, 30).unwrap();
    assert_eq!(points.len(), 2);
    assert!((points[0].value - 0.85).abs() < 0.001 || (points[0].value - 0.87).abs() < 0.001);
}

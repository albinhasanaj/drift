//! Tests for the untested enforcement query functions:
//! audit_snapshots, health_trends, feedback_by_pattern, feedback_adjustments,
//! policy_results, degradation_alerts_by_type, violations_by_file, get_violation_pattern_id.

use drift_storage::migrations::run_migrations;
use drift_storage::queries::enforcement::*;
use rusqlite::Connection;

fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    run_migrations(&conn).unwrap();
    conn
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT SNAPSHOTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn audit_snapshot_insert_and_query() {
    let conn = setup_db();
    insert_audit_snapshot(&conn, &AuditSnapshotRow {
        health_score: 0.85,
        avg_confidence: 0.72,
        approval_ratio: 0.90,
        compliance_rate: 0.95,
        cross_validation_rate: 0.88,
        duplicate_free_rate: 0.99,
        pattern_count: 42,
        category_scores: Some(r#"{"security":0.9,"quality":0.8}"#.to_string()),
        created_at: 0,
    }).unwrap();

    let results = query_audit_snapshots(&conn, 10).unwrap();
    assert_eq!(results.len(), 1);
    assert!((results[0].health_score - 0.85).abs() < 0.001);
    assert_eq!(results[0].pattern_count, 42);
    assert!(results[0].category_scores.as_ref().unwrap().contains("security"));
}

#[test]
fn audit_snapshots_ordered_by_created_at_desc() {
    let conn = setup_db();
    for i in 0..3 {
        insert_audit_snapshot(&conn, &AuditSnapshotRow {
            health_score: 0.5 + (i as f64 * 0.1),
            avg_confidence: 0.5, approval_ratio: 0.5,
            compliance_rate: 0.5, cross_validation_rate: 0.5,
            duplicate_free_rate: 0.5, pattern_count: i,
            category_scores: None, created_at: 0,
        }).unwrap();
    }
    let results = query_audit_snapshots(&conn, 2).unwrap();
    assert_eq!(results.len(), 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// HEALTH TRENDS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn health_trend_insert_and_query() {
    let conn = setup_db();
    insert_health_trend(&conn, "confidence", 0.85).unwrap();
    insert_health_trend(&conn, "confidence", 0.87).unwrap();
    insert_health_trend(&conn, "violations", 42.0).unwrap();

    let confidence = query_health_trends(&conn, "confidence", 10).unwrap();
    assert_eq!(confidence.len(), 2);
    assert_eq!(confidence[0].metric_name, "confidence");

    let violations = query_health_trends(&conn, "violations", 10).unwrap();
    assert_eq!(violations.len(), 1);
}

#[test]
fn health_trends_limit_respected() {
    let conn = setup_db();
    for _ in 0..10 {
        insert_health_trend(&conn, "score", 0.5).unwrap();
    }
    let results = query_health_trends(&conn, "score", 3).unwrap();
    assert_eq!(results.len(), 3);
}

// ═══════════════════════════════════════════════════════════════════════════
// FEEDBACK BY PATTERN + ADJUSTMENTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn feedback_by_pattern_roundtrip() {
    let conn = setup_db();
    // Need a violation first for the violation_id reference
    insert_violation(&conn, &ViolationRow {
        id: "v1".into(), file: "a.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "warning".into(), pattern_id: "no-eval".into(),
        rule_id: "r1".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    insert_feedback(&conn, &FeedbackRow {
        violation_id: "v1".into(), pattern_id: "no-eval".into(),
        detector_id: "d1".into(), action: "fix".into(),
        dismissal_reason: None, reason: None, author: Some("user".into()),
        created_at: 0,
    }).unwrap();
    insert_feedback(&conn, &FeedbackRow {
        violation_id: "v1".into(), pattern_id: "no-eval".into(),
        detector_id: "d1".into(), action: "dismiss".into(),
        dismissal_reason: Some("false_positive".into()), reason: None,
        author: None, created_at: 0,
    }).unwrap();

    let by_pattern = query_feedback_by_pattern(&conn, "no-eval").unwrap();
    assert_eq!(by_pattern.len(), 2);
}

#[test]
fn feedback_adjustments_bayesian_deltas() {
    let conn = setup_db();
    insert_violation(&conn, &ViolationRow {
        id: "v2".into(), file: "b.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "warning".into(), pattern_id: "p-adj".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    // fix → (1.0, 0.0)
    insert_feedback(&conn, &FeedbackRow {
        violation_id: "v2".into(), pattern_id: "p-adj".into(),
        detector_id: "d".into(), action: "fix".into(),
        dismissal_reason: None, reason: None, author: None, created_at: 0,
    }).unwrap();
    // dismiss(false_positive) → (0.0, 0.5)
    insert_feedback(&conn, &FeedbackRow {
        violation_id: "v2".into(), pattern_id: "p-adj".into(),
        detector_id: "d".into(), action: "dismiss".into(),
        dismissal_reason: Some("false_positive".into()), reason: None,
        author: None, created_at: 0,
    }).unwrap();
    // suppress → (0.0, 0.1)
    insert_feedback(&conn, &FeedbackRow {
        violation_id: "v2".into(), pattern_id: "p-adj".into(),
        detector_id: "d".into(), action: "suppress".into(),
        dismissal_reason: None, reason: None, author: None, created_at: 0,
    }).unwrap();

    let deltas = query_feedback_adjustments(&conn, "p-adj").unwrap();
    assert_eq!(deltas.len(), 3);
    assert!((deltas[0].0 - 1.0).abs() < 0.001); // fix alpha
    assert!((deltas[1].1 - 0.5).abs() < 0.001); // dismiss beta
    assert!((deltas[2].1 - 0.1).abs() < 0.001); // suppress beta
}

// ═══════════════════════════════════════════════════════════════════════════
// POLICY RESULTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn policy_result_insert_and_query() {
    let conn = setup_db();
    insert_policy_result(&conn, &PolicyResultRow {
        id: 0, policy_name: "strict".into(), aggregation_mode: "all_must_pass".into(),
        overall_passed: false, overall_score: 0.65,
        gate_count: 6, gates_passed: 4, gates_failed: 2,
        details: Some(r#"{"failed":["confidence","coverage"]}"#.into()),
        run_at: 0,
    }).unwrap();

    let results = query_recent_policy_results(&conn, 10).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].policy_name, "strict");
    assert!(!results[0].overall_passed);
    assert_eq!(results[0].gates_failed, 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// DEGRADATION ALERTS BY TYPE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn degradation_alerts_by_type_filter() {
    let conn = setup_db();
    insert_degradation_alert(&conn, &DegradationAlertRow {
        id: 0, alert_type: "confidence_drop".into(), severity: "warning".into(),
        message: "dropped".into(), current_value: 0.6, previous_value: 0.8, delta: -0.2,
        created_at: 0,
    }).unwrap();
    insert_degradation_alert(&conn, &DegradationAlertRow {
        id: 0, alert_type: "violation_spike".into(), severity: "error".into(),
        message: "spiked".into(), current_value: 50.0, previous_value: 10.0, delta: 40.0,
        created_at: 0,
    }).unwrap();

    let drops = query_degradation_alerts_by_type(&conn, "confidence_drop").unwrap();
    assert_eq!(drops.len(), 1);
    assert_eq!(drops[0].severity, "warning");
}

// ═══════════════════════════════════════════════════════════════════════════
// VIOLATIONS BY FILE + GET PATTERN ID
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn violations_by_file() {
    let conn = setup_db();
    insert_violation(&conn, &ViolationRow {
        id: "vf-1".into(), file: "src/auth.ts".into(), line: 10,
        column: None, end_line: None, end_column: None,
        severity: "error".into(), pattern_id: "no-eval".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: Some(95), owasp_category: None, suppressed: false, is_new: true,
    }).unwrap();
    insert_violation(&conn, &ViolationRow {
        id: "vf-2".into(), file: "src/db.ts".into(), line: 5,
        column: None, end_line: None, end_column: None,
        severity: "warning".into(), pattern_id: "no-sql-concat".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: Some(89), owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    let auth = query_violations_by_file(&conn, "src/auth.ts").unwrap();
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0].id, "vf-1");
    assert!(auth[0].is_new);
}

#[test]
fn get_violation_pattern_id_found() {
    let conn = setup_db();
    insert_violation(&conn, &ViolationRow {
        id: "vp-1".into(), file: "a.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "warning".into(), pattern_id: "target-pattern".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    let pid = get_violation_pattern_id(&conn, "vp-1").unwrap();
    assert_eq!(pid, Some("target-pattern".to_string()));
}

#[test]
fn get_violation_pattern_id_not_found() {
    let conn = setup_db();
    let pid = get_violation_pattern_id(&conn, "nonexistent").unwrap();
    assert!(pid.is_none());
}

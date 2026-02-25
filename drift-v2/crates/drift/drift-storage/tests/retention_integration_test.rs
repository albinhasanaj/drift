//! Integration tests for retention with real migrated schema.
//! Verifies that apply_retention works correctly against the actual
//! drift.db schema (not a hand-built fake), tests FK safety,
//! tier correctness, orphan cleanup, and edge cases.

use drift_storage::migrations::run_migrations;
use drift_storage::queries::{enforcement, scan_history};
use drift_storage::retention::{apply_retention, RetentionPolicy};
use rusqlite::{params, Connection};

fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    run_migrations(&conn).unwrap();
    conn
}

fn epoch_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ═══════════════════════════════════════════════════════════════════════════
// ORPHAN CLEANUP WITH REAL SCHEMA
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn orphan_cleanup_detections_real_schema() {
    let conn = setup_db();
    let now = epoch_now();

    // Track one file
    conn.execute(
        "INSERT OR REPLACE INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at, scan_duration_us) VALUES ('src/keep.ts', 'ts', 100, X'AA', ?1, 0, ?1, 10)",
        params![now],
    ).unwrap();

    // Detection for tracked file (far future so time cleanup doesn't hit it)
    conn.execute(
        "INSERT INTO detections (file, line, column_num, pattern_id, category, confidence, detection_method) VALUES ('src/keep.ts', 1, 1, 'p1', 'c', 0.9, 'regex')",
        [],
    ).unwrap();

    // Detection for removed file
    conn.execute(
        "INSERT INTO detections (file, line, column_num, pattern_id, category, confidence, detection_method) VALUES ('src/removed.ts', 1, 1, 'p1', 'c', 0.9, 'regex')",
        [],
    ).unwrap();

    let report = apply_retention(&conn, &RetentionPolicy { short_days: 9999, medium_days: 9999, long_days: 9999 }).unwrap();
    assert!(report.total_deleted >= 1);

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM detections", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1, "Should keep detection for tracked file only");
}

#[test]
fn orphan_cleanup_functions_and_boundaries() {
    let conn = setup_db();
    let now = epoch_now();

    conn.execute(
        "INSERT OR REPLACE INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at, scan_duration_us) VALUES ('src/keep.ts', 'ts', 100, X'AA', ?1, 0, ?1, 10)",
        params![now],
    ).unwrap();

    // Function for kept file
    conn.execute(
        "INSERT OR REPLACE INTO functions (file, name, qualified_name, language, line, end_line, parameter_count, is_exported, is_async, body_hash, signature_hash) VALUES ('src/keep.ts', 'fn1', 'keep.ts::fn1', 'ts', 1, 10, 0, 0, 0, X'AA', X'BB')",
        [],
    ).unwrap();
    // Function for removed file
    conn.execute(
        "INSERT OR REPLACE INTO functions (file, name, qualified_name, language, line, end_line, parameter_count, is_exported, is_async, body_hash, signature_hash) VALUES ('src/gone.ts', 'fn2', 'gone.ts::fn2', 'ts', 1, 10, 0, 0, 0, X'CC', X'DD')",
        [],
    ).unwrap();

    apply_retention(&conn, &RetentionPolicy { short_days: 9999, medium_days: 9999, long_days: 9999 }).unwrap();

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM functions", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// TIME-BASED TIERS WITH REAL SCHEMA
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn short_tier_violations_cleaned() {
    let conn = setup_db();
    let now = epoch_now();

    // Old violation (60 days ago)
    enforcement::insert_violation(&conn, &enforcement::ViolationRow {
        id: "v-old".into(), file: "a.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "warning".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "old".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();
    // Backdate it
    conn.execute(
        "UPDATE violations SET created_at = ?1 WHERE id = 'v-old'",
        params![now - 60 * 86400],
    ).unwrap();

    // Recent violation (1 day ago)
    enforcement::insert_violation(&conn, &enforcement::ViolationRow {
        id: "v-new".into(), file: "a.ts".into(), line: 2,
        column: None, end_line: None, end_column: None,
        severity: "warning".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "new".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    let report = apply_retention(&conn, &RetentionPolicy { short_days: 30, medium_days: 90, long_days: 365 }).unwrap();
    assert!(report.total_deleted >= 1);

    let remaining = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, "v-new");
}

#[test]
fn medium_tier_scan_history_cleaned() {
    let conn = setup_db();
    let now = epoch_now();

    // Old scan (120 days ago)
    let old_id = scan_history::insert_scan_start(&conn, now - 120 * 86400, "/project").unwrap();
    scan_history::update_scan_complete(&conn, old_id, now - 120 * 86400 + 10, 50, 10, 5, 2, 33, 5000, "completed", None).unwrap();

    // Recent scan (1 day ago)
    let new_id = scan_history::insert_scan_start(&conn, now - 86400, "/project").unwrap();
    scan_history::update_scan_complete(&conn, new_id, now - 86400 + 10, 60, 15, 3, 1, 41, 6000, "completed", None).unwrap();

    apply_retention(&conn, &RetentionPolicy { short_days: 30, medium_days: 90, long_days: 365 }).unwrap();

    let scans = scan_history::query_recent(&conn, 10).unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].total_files, Some(60));
}

#[test]
fn long_tier_parse_cache_cleaned() {
    let conn = setup_db();
    let now = epoch_now();

    // Old cache entry (400 days ago)
    conn.execute(
        "INSERT OR REPLACE INTO parse_cache (content_hash, language, parse_result_json, created_at) VALUES (X'AABB', 'ts', '{}', ?1)",
        params![now - 400 * 86400],
    ).unwrap();

    // Recent cache entry
    conn.execute(
        "INSERT OR REPLACE INTO parse_cache (content_hash, language, parse_result_json, created_at) VALUES (X'CCDD', 'ts', '{}', ?1)",
        params![now - 10 * 86400],
    ).unwrap();

    apply_retention(&conn, &RetentionPolicy { short_days: 30, medium_days: 90, long_days: 365 }).unwrap();

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM parse_cache", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1, "Should keep only recent parse cache entry");
}

// ═══════════════════════════════════════════════════════════════════════════
// EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn empty_database_retention_no_errors() {
    let conn = setup_db();
    let report = apply_retention(&conn, &RetentionPolicy::default()).unwrap();
    assert_eq!(report.total_deleted, 0);
    assert_eq!(report.per_table.len(), 0);
}

#[test]
fn retention_atomicity_all_or_nothing() {
    let conn = setup_db();
    let now = epoch_now();

    // Insert data across multiple tier tables
    enforcement::insert_violation(&conn, &enforcement::ViolationRow {
        id: "v1".into(), file: "a.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "warning".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();
    conn.execute("UPDATE violations SET created_at = ?1 WHERE id = 'v1'", params![now - 60 * 86400]).unwrap();

    let old_scan_id = scan_history::insert_scan_start(&conn, now - 120 * 86400, "/p").unwrap();
    scan_history::update_scan_complete(&conn, old_scan_id, now - 120 * 86400, 10, 1, 0, 0, 9, 100, "completed", None).unwrap();

    // Apply retention — both should be cleaned in one atomic transaction
    let report = apply_retention(&conn, &RetentionPolicy { short_days: 30, medium_days: 90, long_days: 365 }).unwrap();
    assert!(report.total_deleted >= 2);
    assert!(report.duration_ms < 10000, "Retention should complete quickly");

    let v_count: i64 = conn.query_row("SELECT COUNT(*) FROM violations", [], |r| r.get(0)).unwrap();
    let s_count: i64 = conn.query_row("SELECT COUNT(*) FROM scan_history", [], |r| r.get(0)).unwrap();
    assert_eq!(v_count, 0);
    assert_eq!(s_count, 0);
}

#[test]
fn retention_report_tracks_per_table() {
    let conn = setup_db();
    let now = epoch_now();

    // 3 old violations
    for i in 0..3 {
        enforcement::insert_violation(&conn, &enforcement::ViolationRow {
            id: format!("v-{i}"), file: "a.ts".into(), line: i as u32,
            column: None, end_line: None, end_column: None,
            severity: "warning".into(), pattern_id: "p".into(),
            rule_id: "r".into(), message: "m".into(),
            quick_fix_strategy: None, quick_fix_description: None,
            cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
        }).unwrap();
    }
    conn.execute("UPDATE violations SET created_at = ?1", params![now - 60 * 86400]).unwrap();

    let report = apply_retention(&conn, &RetentionPolicy { short_days: 30, medium_days: 90, long_days: 365 }).unwrap();
    assert_eq!(report.total_deleted, 3);
    let violation_cleanup = report.per_table.iter().find(|t| t.table == "violations");
    assert!(violation_cleanup.is_some());
    assert_eq!(violation_cleanup.unwrap().deleted, 3);
}

//! File-backed persistence tests for drift-storage.
//! Verifies data survives engine close/reopen, WAL mode is active,
//! pragmas persist, integrity checks pass, and foreign keys are enforced.

use drift_storage::connection::pragmas;
use drift_storage::connection::DatabaseManager;
use drift_storage::migrations::run_migrations;
use drift_storage::queries::{enforcement, files, functions, graph, scan_history, structural};
use rusqlite::Connection;
use tempfile::tempdir;

fn open_file_db(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    pragmas::apply_pragmas(&conn).unwrap();
    run_migrations(&conn).unwrap();
    conn
}

fn reopen_file_db(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    pragmas::apply_pragmas(&conn).unwrap();
    conn
}

// ═══════════════════════════════════════════════════════════════════════════
// RESTART SURVIVAL
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn file_metadata_survives_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");

    {
        let conn = open_file_db(&db_path);
        conn.execute(
            "INSERT OR REPLACE INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at, scan_duration_us) VALUES ('src/main.ts', 'typescript', 1024, X'AABB', 1700000000, 0, 1700000000, 500)",
            [],
        ).unwrap();
    }

    let conn = reopen_file_db(&db_path);
    let meta = files::get_file_metadata(&conn, "src/main.ts").unwrap();
    assert!(meta.is_some());
    let meta = meta.unwrap();
    assert_eq!(meta.language.as_deref(), Some("typescript"));
    assert_eq!(meta.file_size, 1024);
}

#[test]
fn functions_survive_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");

    {
        let conn = open_file_db(&db_path);
        conn.execute(
            "INSERT OR REPLACE INTO functions (file, name, qualified_name, language, line, end_line, parameter_count, return_type, is_exported, is_async, body_hash, signature_hash) VALUES ('src/auth.ts', 'login', 'auth.ts::login', 'typescript', 10, 50, 2, 'Promise<void>', 1, 1, X'AA', X'BB')",
            [],
        ).unwrap();
    }

    let conn = reopen_file_db(&db_path);
    let fns = functions::get_functions_by_file(&conn, "src/auth.ts").unwrap();
    assert_eq!(fns.len(), 1);
    assert_eq!(fns[0].name, "login");
}

#[test]
fn violations_survive_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");

    {
        let conn = open_file_db(&db_path);
        enforcement::insert_violation(&conn, &enforcement::ViolationRow {
            id: "v-persist".to_string(),
            file: "src/auth.ts".to_string(),
            line: 42,
            column: Some(5),
            end_line: None,
            end_column: None,
            severity: "error".to_string(),
            pattern_id: "no-eval".to_string(),
            rule_id: "security/no-eval".to_string(),
            message: "eval is dangerous".to_string(),
            quick_fix_strategy: None,
            quick_fix_description: None,
            cwe_id: Some(95),
            owasp_category: None,
            suppressed: false,
            is_new: true,
        }).unwrap();
    }

    let conn = reopen_file_db(&db_path);
    let violations = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].id, "v-persist");
    assert!(violations[0].is_new);
}

#[test]
fn structural_data_survives_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");

    {
        let conn = open_file_db(&db_path);
        structural::upsert_coupling_metrics(&conn, &structural::CouplingMetricsRow {
            module: "src/auth".to_string(),
            ce: 5, ca: 3, instability: 0.625, abstractness: 0.2,
            distance: 0.175, zone: "main_sequence".to_string(),
        }).unwrap();
        structural::upsert_dna_gene(&conn, &structural::DnaGeneRow {
            gene_id: "naming".into(), name: "Naming".into(),
            description: "camelCase".into(), dominant_allele: None,
            alleles: "[]".into(), confidence: 0.9, consistency: 0.8,
            exemplars: "[]".into(),
        }).unwrap();
    }

    let conn = reopen_file_db(&db_path);
    let cm = structural::get_coupling_metrics(&conn, "src/auth").unwrap();
    assert!(cm.is_some());
    assert_eq!(cm.unwrap().ce, 5);

    let gene = structural::get_dna_gene(&conn, "naming").unwrap();
    assert!(gene.is_some());
}

#[test]
fn graph_data_survives_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");

    {
        let conn = open_file_db(&db_path);
        graph::upsert_reachability(&conn, &graph::ReachabilityCacheRow {
            source_node: "auth::login".into(),
            direction: "forward".into(),
            reachable_set: r#"["db::query"]"#.into(),
            sensitivity: "critical".into(),
        }).unwrap();
        graph::upsert_impact_score(&conn, &graph::ImpactScoreRow {
            function_id: "auth::login".into(),
            blast_radius: 42,
            risk_score: 0.75,
            is_dead_code: false,
            dead_code_reason: None,
            exclusion_category: None,
        }).unwrap();
    }

    let conn = reopen_file_db(&db_path);
    let reach = graph::get_reachability(&conn, "auth::login", "forward").unwrap();
    assert!(reach.is_some());
    let impact = graph::get_impact_score(&conn, "auth::login").unwrap();
    assert!(impact.is_some());
    assert_eq!(impact.unwrap().blast_radius, 42);
}

#[test]
fn scan_history_survives_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");

    {
        let conn = open_file_db(&db_path);
        let id = scan_history::insert_scan_start(&conn, 1700000000, "/project").unwrap();
        scan_history::update_scan_complete(
            &conn, id, 1700000010, 100, 20, 5, 3, 72, 10000, "completed", None,
        ).unwrap();
    }

    let conn = reopen_file_db(&db_path);
    let scans = scan_history::query_recent(&conn, 10).unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].status, "completed");
    assert_eq!(scans[0].total_files, Some(100));
}

// ═══════════════════════════════════════════════════════════════════════════
// WAL MODE & PRAGMAS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn wal_mode_active_after_open() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");
    let conn = open_file_db(&db_path);

    let is_wal = pragmas::verify_wal_mode(&conn).unwrap();
    assert!(is_wal, "WAL mode should be active");
}

#[test]
fn wal_mode_persists_across_reopen() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");

    { let _conn = open_file_db(&db_path); }

    let conn = reopen_file_db(&db_path);
    let is_wal = pragmas::verify_wal_mode(&conn).unwrap();
    assert!(is_wal, "WAL mode should persist across reopen");
}

#[test]
fn foreign_keys_enforced() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");
    let conn = open_file_db(&db_path);

    let fk_on: i32 = conn.pragma_query_value(None, "foreign_keys", |r| r.get(0)).unwrap();
    assert_eq!(fk_on, 1, "Foreign keys should be ON");

    // constraint_verifications has FK to constraints(id) — should fail without parent
    let result = structural::insert_constraint_verification(&conn, "nonexistent", true, "[]");
    assert!(result.is_err(), "FK constraint should reject orphan verification");
}

// ═══════════════════════════════════════════════════════════════════════════
// INTEGRITY
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integrity_check_passes_empty_db() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");
    let conn = open_file_db(&db_path);

    let result: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(result, "ok");
}

#[test]
fn integrity_check_passes_after_heavy_writes() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");
    let conn = open_file_db(&db_path);

    // Write 500 violations
    for i in 0..500 {
        enforcement::insert_violation(&conn, &enforcement::ViolationRow {
            id: format!("v-{i}"),
            file: format!("src/file-{}.ts", i % 50),
            line: i as u32,
            column: None, end_line: None, end_column: None,
            severity: "warning".to_string(),
            pattern_id: "p1".to_string(),
            rule_id: "r1".to_string(),
            message: format!("violation {i}"),
            quick_fix_strategy: None, quick_fix_description: None,
            cwe_id: None, owasp_category: None,
            suppressed: false, is_new: false,
        }).unwrap();
    }

    let result: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(result, "ok");

    let violations = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(violations.len(), 500);
}

// ═══════════════════════════════════════════════════════════════════════════
// DATABASE MANAGER
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn database_manager_file_backed_roundtrip() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");

    {
        let db = DatabaseManager::open(&db_path).unwrap();
        db.with_writer(|conn| {
            structural::insert_secret(conn, &structural::SecretRow {
                id: None,
                pattern_name: "aws_key".into(),
                redacted_value: "AKIA****".into(),
                file: "src/config.ts".into(),
                line: 10,
                severity: "critical".into(),
                entropy: 4.5,
                confidence: 0.95,
                cwe_ids: "[798]".into(),
            })?;
            Ok(())
        }).unwrap();
        db.checkpoint().unwrap();
    }

    let db = DatabaseManager::open(&db_path).unwrap();
    db.with_writer(|conn| {
        let secrets = structural::get_secrets_by_file(conn, "src/config.ts")?;
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].pattern_name, "aws_key");
        Ok(())
    }).unwrap();
}

#[test]
fn database_manager_read_pool_sees_writes() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    db.with_writer(|conn| {
        structural::upsert_coupling_metrics(conn, &structural::CouplingMetricsRow {
            module: "mod-a".into(), ce: 1, ca: 1, instability: 0.5,
            abstractness: 0.5, distance: 0.0, zone: "main_sequence".into(),
        })
    }).unwrap();

    // Read pool should see the write (WAL mode allows concurrent reads)
    let result = db.with_reader(|conn| {
        structural::get_coupling_metrics(conn, "mod-a")
    }).unwrap();
    assert!(result.is_some());
}

//! Edge case tests for drift-storage: SQL injection resistance,
//! Unicode handling, empty strings, huge content, boundary values,
//! and adversarial inputs.

use drift_storage::migrations::run_migrations;
use drift_storage::queries::{enforcement, functions, scan_history, structural};
use rusqlite::Connection;

fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    run_migrations(&conn).unwrap();
    conn
}

// ═══════════════════════════════════════════════════════════════════════════
// SQL INJECTION RESISTANCE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sql_injection_in_violation_id() {
    let conn = setup_db();
    let malicious_id = "'; DROP TABLE violations; --".to_string();
    enforcement::insert_violation(&conn, &enforcement::ViolationRow {
        id: malicious_id.clone(), file: "a.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "warning".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    // Table still exists and violation was inserted
    let violations = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].id, malicious_id);
}

#[test]
fn sql_injection_in_file_path() {
    let conn = setup_db();
    let malicious_file = "src/' OR '1'='1".to_string();
    enforcement::insert_violation(&conn, &enforcement::ViolationRow {
        id: "v1".into(), file: malicious_file.clone(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "error".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    let results = enforcement::query_violations_by_file(&conn, &malicious_file).unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn sql_injection_in_coupling_metrics_module() {
    let conn = setup_db();
    structural::upsert_coupling_metrics(&conn, &structural::CouplingMetricsRow {
        module: "'; DELETE FROM coupling_metrics; --".into(),
        ce: 1, ca: 1, instability: 0.5, abstractness: 0.5,
        distance: 0.0, zone: "main_sequence".into(),
    }).unwrap();

    let all = structural::get_all_coupling_metrics(&conn).unwrap();
    assert_eq!(all.len(), 1);
}

#[test]
fn sql_injection_in_scan_root_path() {
    let conn = setup_db();
    let id = scan_history::insert_scan_start(
        &conn, 1700000000, "'; DROP TABLE scan_history; --",
    ).unwrap();
    assert!(id > 0);

    let scans = scan_history::query_recent(&conn, 10).unwrap();
    assert_eq!(scans.len(), 1);
    assert!(scans[0].root_path.contains("DROP TABLE"));
}

// ═══════════════════════════════════════════════════════════════════════════
// UNICODE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn unicode_in_violation_message() {
    let conn = setup_db();
    let unicode_msg = "🔥 Error: файл содержит опасный код 日本語テスト".to_string();
    enforcement::insert_violation(&conn, &enforcement::ViolationRow {
        id: "v-unicode".into(), file: "src/日本語.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "error".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: unicode_msg.clone(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    let violations = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(violations[0].message, unicode_msg);
    assert_eq!(violations[0].file, "src/日本語.ts");
}

#[test]
fn unicode_in_dna_gene_fields() {
    let conn = setup_db();
    structural::upsert_dna_gene(&conn, &structural::DnaGeneRow {
        gene_id: "名前規則".into(),
        name: "命名規則テスト".into(),
        description: "キャメルケースを使用 🐫".into(),
        dominant_allele: Some("「キャメルケース」".into()),
        alleles: r#"["キャメル","スネーク"]"#.into(),
        confidence: 0.9, consistency: 0.8,
        exemplars: "[]".into(),
    }).unwrap();

    let gene = structural::get_dna_gene(&conn, "名前規則").unwrap().unwrap();
    assert_eq!(gene.name, "命名規則テスト");
    assert!(gene.description.contains('🐫'));
}

#[test]
fn unicode_function_names() {
    let conn = setup_db();
    conn.execute(
        "INSERT OR REPLACE INTO functions (file, name, qualified_name, language, line, end_line, parameter_count, is_exported, is_async, body_hash, signature_hash) VALUES ('src/数学.py', 'вычислить', '数学.py::вычислить', 'python', 1, 10, 0, 0, 0, X'AA', X'BB')",
        [],
    ).unwrap();

    let fns = functions::get_functions_by_file(&conn, "src/数学.py").unwrap();
    assert_eq!(fns.len(), 1);
    assert_eq!(fns[0].name, "вычислить");
}

// ═══════════════════════════════════════════════════════════════════════════
// EMPTY STRINGS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn empty_string_violation_fields() {
    let conn = setup_db();
    enforcement::insert_violation(&conn, &enforcement::ViolationRow {
        id: "v-empty".into(), file: "".into(), line: 0,
        column: None, end_line: None, end_column: None,
        severity: "".into(), pattern_id: "".into(),
        rule_id: "".into(), message: "".into(),
        quick_fix_strategy: Some("".into()),
        quick_fix_description: Some("".into()),
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    let violations = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].file, "");
    assert_eq!(violations[0].message, "");
}

#[test]
fn empty_string_coupling_module() {
    let conn = setup_db();
    structural::upsert_coupling_metrics(&conn, &structural::CouplingMetricsRow {
        module: "".into(), ce: 0, ca: 0, instability: 0.0,
        abstractness: 0.0, distance: 0.0, zone: "".into(),
    }).unwrap();

    let result = structural::get_coupling_metrics(&conn, "").unwrap();
    assert!(result.is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// HUGE CONTENT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn huge_violation_message() {
    let conn = setup_db();
    let huge_msg = "x".repeat(100_000);
    enforcement::insert_violation(&conn, &enforcement::ViolationRow {
        id: "v-huge".into(), file: "a.ts".into(), line: 1,
        column: None, end_line: None, end_column: None,
        severity: "warning".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: huge_msg.clone(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
    }).unwrap();

    let violations = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(violations[0].message.len(), 100_000);
}

#[test]
fn huge_json_in_contract_endpoints() {
    let conn = setup_db();
    let huge_json = format!(r#"[{}]"#, (0..1000).map(|i| format!(r#"{{"method":"GET","path":"/api/v{i}"}}"#)).collect::<Vec<_>>().join(","));
    structural::upsert_contract(&conn, &structural::ContractRow {
        id: "big-contract".into(), paradigm: "rest".into(),
        source_file: "routes.ts".into(), framework: "express".into(),
        confidence: 0.9, endpoints: huge_json.clone(),
    }).unwrap();

    let contract = structural::get_contract(&conn, "big-contract").unwrap().unwrap();
    assert_eq!(contract.endpoints.len(), huge_json.len());
}

// ═══════════════════════════════════════════════════════════════════════════
// BOUNDARY VALUES
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn max_integer_values() {
    let conn = setup_db();
    enforcement::insert_violation(&conn, &enforcement::ViolationRow {
        id: "v-max".into(), file: "a.ts".into(), line: u32::MAX,
        column: Some(u32::MAX), end_line: Some(u32::MAX),
        end_column: Some(u32::MAX),
        severity: "error".into(), pattern_id: "p".into(),
        rule_id: "r".into(), message: "m".into(),
        quick_fix_strategy: None, quick_fix_description: None,
        cwe_id: Some(u32::MAX), owasp_category: None,
        suppressed: false, is_new: false,
    }).unwrap();

    let violations = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(violations[0].line, u32::MAX);
    assert_eq!(violations[0].cwe_id, Some(u32::MAX));
}

#[test]
fn zero_values_everywhere() {
    let conn = setup_db();
    structural::upsert_coupling_metrics(&conn, &structural::CouplingMetricsRow {
        module: "zero".into(), ce: 0, ca: 0, instability: 0.0,
        abstractness: 0.0, distance: 0.0, zone: "zero".into(),
    }).unwrap();

    let result = structural::get_coupling_metrics(&conn, "zero").unwrap().unwrap();
    assert_eq!(result.ce, 0);
    assert!((result.instability - 0.0).abs() < f64::EPSILON);
}

#[test]
fn negative_delta_in_degradation_alert() {
    let conn = setup_db();
    enforcement::insert_degradation_alert(&conn, &enforcement::DegradationAlertRow {
        id: 0, alert_type: "drop".into(), severity: "warning".into(),
        message: "dropped".into(),
        current_value: -1.5, previous_value: -0.5, delta: -1.0,
        created_at: 0,
    }).unwrap();

    let alerts = enforcement::query_recent_degradation_alerts(&conn, 10).unwrap();
    assert!((alerts[0].current_value - (-1.5)).abs() < 0.001);
    assert!((alerts[0].delta - (-1.0)).abs() < 0.001);
}

#[test]
fn special_characters_in_file_paths() {
    let conn = setup_db();
    let special_paths = vec![
        "src/file with spaces.ts",
        "src/file\twith\ttabs.ts",
        "src/path/to/../../../etc/passwd",
        "src/file#hash.ts",
        "src/file%20encoded.ts",
        "C:\\Windows\\System32\\config.ts",
    ];

    for (i, path) in special_paths.iter().enumerate() {
        enforcement::insert_violation(&conn, &enforcement::ViolationRow {
            id: format!("v-special-{i}"), file: path.to_string(), line: 1,
            column: None, end_line: None, end_column: None,
            severity: "warning".into(), pattern_id: "p".into(),
            rule_id: "r".into(), message: "m".into(),
            quick_fix_strategy: None, quick_fix_description: None,
            cwe_id: None, owasp_category: None, suppressed: false, is_new: false,
        }).unwrap();
    }

    let all = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(all.len(), special_paths.len());

    // Verify each path round-trips correctly
    for path in &special_paths {
        let by_file = enforcement::query_violations_by_file(&conn, path).unwrap();
        assert_eq!(by_file.len(), 1, "Should find violation for path: {path}");
    }
}

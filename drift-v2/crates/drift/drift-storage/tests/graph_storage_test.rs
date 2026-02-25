//! T4-INT-02: All results persist to drift.db in their respective tables.

use drift_storage::migrations::run_migrations;
use drift_storage::queries::graph::*;
use rusqlite::Connection;

fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    run_migrations(&conn).unwrap();
    conn
}

#[test]
fn test_reachability_persistence() {
    let conn = setup_db();

    let row = ReachabilityCacheRow {
        source_node: "auth.ts::login".to_string(),
        direction: "forward".to_string(),
        reachable_set: r#"["db.ts::query","utils.ts::format"]"#.to_string(),
        sensitivity: "critical".to_string(),
    };

    upsert_reachability(&conn, &row).unwrap();
    let result = get_reachability(&conn, "auth.ts::login", "forward").unwrap();
    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.sensitivity, "critical");
    assert!(result.reachable_set.contains("db.ts::query"));

    // Upsert overwrites
    let row2 = ReachabilityCacheRow {
        sensitivity: "high".to_string(),
        ..row
    };
    upsert_reachability(&conn, &row2).unwrap();
    let result = get_reachability(&conn, "auth.ts::login", "forward").unwrap().unwrap();
    assert_eq!(result.sensitivity, "high");

    // Clear cache
    clear_reachability_cache(&conn).unwrap();
    let result = get_reachability(&conn, "auth.ts::login", "forward").unwrap();
    assert!(result.is_none());
}

#[test]
fn test_taint_flow_persistence() {
    let conn = setup_db();

    let row = TaintFlowRow {
        id: None,
        source_file: "handler.ts".to_string(),
        source_line: 5,
        source_type: "UserInput".to_string(),
        sink_file: "db.ts".to_string(),
        sink_line: 20,
        sink_type: "SqlQuery".to_string(),
        cwe_id: Some(89),
        is_sanitized: false,
        path: r#"[{"file":"handler.ts","line":5}]"#.to_string(),
        confidence: 0.85,
    };

    let id = insert_taint_flow(&conn, &row).unwrap();
    assert!(id > 0);

    let flows = get_taint_flows_by_file(&conn, "handler.ts").unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].cwe_id, Some(89));
    assert!(!flows[0].is_sanitized);

    let cwe_flows = get_taint_flows_by_cwe(&conn, 89).unwrap();
    assert_eq!(cwe_flows.len(), 1);
}

#[test]
fn test_error_gap_persistence() {
    let conn = setup_db();

    let row = ErrorGapRow {
        id: None,
        file: "handler.ts".to_string(),
        function_id: "handler.ts::processRequest".to_string(),
        gap_type: "empty_catch".to_string(),
        error_type: Some("Error".to_string()),
        propagation_chain: None,
        framework: None,
        cwe_id: Some(390),
        severity: "high".to_string(),
    };

    let id = insert_error_gap(&conn, &row).unwrap();
    assert!(id > 0);

    let gaps = get_error_gaps_by_file(&conn, "handler.ts").unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].gap_type, "empty_catch");
    assert_eq!(gaps[0].cwe_id, Some(390));
}

#[test]
fn test_impact_score_persistence() {
    let conn = setup_db();

    let row = ImpactScoreRow {
        function_id: "auth.ts::login".to_string(),
        blast_radius: 42,
        risk_score: 0.75,
        is_dead_code: false,
        dead_code_reason: None,
        exclusion_category: None,
    };

    upsert_impact_score(&conn, &row).unwrap();
    let result = get_impact_score(&conn, "auth.ts::login").unwrap();
    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.blast_radius, 42);
    assert!((result.risk_score - 0.75).abs() < 0.001);
    assert!(!result.is_dead_code);
}

#[test]
fn test_test_coverage_persistence() {
    let conn = setup_db();

    let row = TestCoverageRow {
        test_function_id: "test_auth.ts::test_login".to_string(),
        source_function_id: "auth.ts::login".to_string(),
        coverage_type: "direct".to_string(),
    };

    insert_test_coverage(&conn, &row).unwrap();
    let results = get_test_coverage_for_source(&conn, "auth.ts::login").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].test_function_id, "test_auth.ts::test_login");
}

#[test]
fn test_test_quality_persistence() {
    let conn = setup_db();

    let row = TestQualityRow {
        function_id: "test_auth.ts::test_login".to_string(),
        coverage_breadth: Some(0.8),
        coverage_depth: Some(0.6),
        assertion_density: Some(0.9),
        mock_ratio: Some(0.3),
        isolation: Some(1.0),
        freshness: Some(0.95),
        stability: Some(1.0),
        overall_score: 0.82,
        smells: Some(r#"["eager_test"]"#.to_string()),
    };

    upsert_test_quality(&conn, &row).unwrap();
    let result = get_test_quality(&conn, "test_auth.ts::test_login").unwrap();
    assert!(result.is_some());
    let result = result.unwrap();
    assert!((result.overall_score - 0.82).abs() < 0.001);
    assert!(result.smells.as_ref().unwrap().contains("eager_test"));
}

// T4-INT-02: All 6 tables exist and have correct schema
#[test]
fn test_all_tables_exist() {
    let conn = setup_db();

    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert!(tables.contains(&"reachability_cache".to_string()), "Missing reachability_cache table");
    assert!(tables.contains(&"taint_flows".to_string()), "Missing taint_flows table");
    assert!(tables.contains(&"error_gaps".to_string()), "Missing error_gaps table");
    assert!(tables.contains(&"impact_scores".to_string()), "Missing impact_scores table");
    assert!(tables.contains(&"test_coverage".to_string()), "Missing test_coverage table");
    assert!(tables.contains(&"test_quality".to_string()), "Missing test_quality table");
}

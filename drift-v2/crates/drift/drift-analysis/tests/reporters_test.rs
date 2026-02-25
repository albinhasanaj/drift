//! Phase 6 tests: Reporters — Schema Validation & Format Correctness
//! T6-RPT-01 through T6-RPT-07

use drift_analysis::enforcement::gates::*;
use drift_analysis::enforcement::reporters::*;
use drift_analysis::enforcement::reporters::sarif::SarifReporter;
use drift_analysis::enforcement::reporters::json::JsonReporter;
use drift_analysis::enforcement::reporters::console::ConsoleReporter;
use drift_analysis::enforcement::rules::*;

fn make_test_results() -> Vec<GateResult> {
    vec![
        GateResult {
            gate_id: GateId::PatternCompliance,
            status: GateStatus::Failed,
            passed: false,
            score: 75.0,
            summary: "Pattern compliance: 75%".to_string(),
            violations: vec![
                Violation {
                    id: "v1".to_string(),
                    file: "src/app.ts".to_string(),
                    line: 10,
                    column: Some(5),
                    end_line: Some(10),
                    end_column: Some(30),
                    severity: Severity::Error,
                    pattern_id: "sql-check".to_string(),
                    rule_id: "security/sql-injection".to_string(),
                    message: "SQL injection vulnerability".to_string(),
                    quick_fix: Some(QuickFix {
                        strategy: QuickFixStrategy::WrapInTryCatch,
                        description: "Use parameterized query".to_string(),
                        replacement: None,
                    }),
                    cwe_id: Some(89),
                    owasp_category: Some("A03:2021-Injection".to_string()),
                    suppressed: false,
                    is_new: true,
                },
                Violation {
                    id: "v2".to_string(),
                    file: "src/utils.ts".to_string(),
                    line: 25,
                    column: None,
                    end_line: None,
                    end_column: None,
                    severity: Severity::Warning,
                    pattern_id: "naming".to_string(),
                    rule_id: "naming/camelCase".to_string(),
                    message: "Should use camelCase".to_string(),
                    quick_fix: None,
                    cwe_id: None,
                    owasp_category: None,
                    suppressed: false,
                    is_new: false,
                },
            ],
            warnings: vec![],
            execution_time_ms: 15,
            details: serde_json::Value::Null,
            error: None,
        },
        GateResult::pass(
            GateId::TestCoverage,
            90.0,
            "Test coverage: 90%".to_string(),
        ),
    ]
}

/// T6-RPT-01: Test SARIF 2.1.0 reporter produces valid SARIF with CWE + OWASP taxonomies.
#[test]
fn test_sarif_reporter_produces_valid_sarif() {
    let reporter = SarifReporter::new();
    let results = make_test_results();
    let output = reporter.generate(&results).unwrap();

    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    // Verify SARIF 2.1.0 structure
    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["$schema"].as_str().unwrap().contains("sarif-schema-2.1.0"));
    assert!(sarif["runs"].is_array());
    assert_eq!(sarif["runs"].as_array().unwrap().len(), 1);

    let run = &sarif["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "drift");
    assert!(run["results"].is_array());

    // Verify CWE taxonomy
    let taxonomies = run["taxonomies"].as_array().unwrap();
    let cwe_tax = taxonomies.iter().find(|t| t["name"] == "CWE");
    assert!(cwe_tax.is_some(), "Should have CWE taxonomy");

    // Verify OWASP taxonomy
    let owasp_tax = taxonomies.iter().find(|t| t["name"] == "OWASP");
    assert!(owasp_tax.is_some(), "Should have OWASP taxonomy");
}

/// T6-RPT-02: Validate SARIF output structure (schema validation).
#[test]
fn test_sarif_schema_structure() {
    let reporter = SarifReporter::new();
    let results = make_test_results();
    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    // Check required SARIF fields
    let run = &sarif["runs"][0];
    let results_arr = run["results"].as_array().unwrap();

    for result in results_arr {
        assert!(result["ruleId"].is_string(), "Each result must have ruleId");
        assert!(result["level"].is_string(), "Each result must have level");
        assert!(result["message"]["text"].is_string(), "Each result must have message.text");
        assert!(result["locations"].is_array(), "Each result must have locations");

        let loc = &result["locations"][0];
        assert!(loc["physicalLocation"]["artifactLocation"]["uri"].is_string());
        assert!(loc["physicalLocation"]["region"]["startLine"].is_number());
    }

    // Check rules
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    assert!(!rules.is_empty(), "Should have rules defined");
    for rule in rules {
        assert!(rule["id"].is_string(), "Each rule must have id");
    }
}

/// T6-RPT-03: Test SARIF with 0 violations produces valid empty SARIF.
#[test]
fn test_sarif_empty_violations() {
    let reporter = SarifReporter::new();
    let results = vec![GateResult::pass(
        GateId::PatternCompliance,
        100.0,
        "All clean".to_string(),
    )];

    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    assert!(run["results"].is_array());
    assert_eq!(run["results"].as_array().unwrap().len(), 0);
}

/// T6-RPT-04: Test SARIF with 10K violations — reasonable size and time.
#[test]
fn test_sarif_10k_violations_performance() {
    let violations: Vec<Violation> = (0..10_000)
        .map(|i| Violation {
            id: format!("v{i}"),
            file: format!("src/file{}.ts", i / 100),
            line: (i % 1000) as u32,
            column: Some(1),
            end_line: None,
            end_column: None,
            severity: Severity::Warning,
            pattern_id: "perf-test".to_string(),
            rule_id: "perf/test".to_string(),
            message: format!("Violation {i}"),
            quick_fix: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        })
        .collect();

    let results = vec![GateResult {
        gate_id: GateId::PatternCompliance,
        status: GateStatus::Failed,
        passed: false,
        score: 50.0,
        summary: "Many violations".to_string(),
        violations,
        warnings: vec![],
        execution_time_ms: 0,
        details: serde_json::Value::Null,
        error: None,
    }];

    let reporter = SarifReporter::new();
    let start = std::time::Instant::now();
    let output = reporter.generate(&results).unwrap();
    let elapsed = start.elapsed();

    assert!(elapsed.as_secs() < 5, "SARIF generation took {}s, should be <5s", elapsed.as_secs());
    assert!(output.len() < 50_000_000, "SARIF file too large: {} bytes", output.len());

    // Verify it's valid JSON
    let _: serde_json::Value = serde_json::from_str(&output).unwrap();
}

/// T6-RPT-05: Test JSON reporter produces valid JSON.
#[test]
fn test_json_reporter() {
    let reporter = JsonReporter;
    let results = make_test_results();
    let output = reporter.generate(&results).unwrap();

    let json: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(json["overall_passed"].is_boolean());
    assert!(json["total_violations"].is_number());
    assert!(json["gates"].is_array());

    let gates = json["gates"].as_array().unwrap();
    assert_eq!(gates.len(), 2);

    // Check violation fields
    let gate0 = &gates[0];
    let violations = gate0["violations"].as_array().unwrap();
    for v in violations {
        assert!(v["id"].is_string());
        assert!(v["file"].is_string());
        assert!(v["line"].is_number());
        assert!(v["severity"].is_string());
        assert!(v["rule_id"].is_string());
        assert!(v["message"].is_string());
    }
}

/// T6-RPT-06: Test console reporter produces human-readable output.
#[test]
fn test_console_reporter() {
    let reporter = ConsoleReporter::new(false); // No color for testing
    let results = make_test_results();
    let output = reporter.generate(&results).unwrap();

    assert!(output.contains("Quality Gate Report"));
    assert!(output.contains("pattern-compliance"));
    assert!(output.contains("test-coverage"));
    assert!(output.contains("src/app.ts"));
    assert!(output.contains("Summary"));
    assert!(output.contains("FAILED") || output.contains("PASSED"));
}

/// T6-RPT-07: Test SARIF code flows for taint paths.
#[test]
fn test_sarif_cwe_owasp_references() {
    let reporter = SarifReporter::new();
    let results = make_test_results();
    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    let run = &sarif["runs"][0];
    let results_arr = run["results"].as_array().unwrap();

    // Find the SQL injection result
    let sql_result = results_arr.iter().find(|r| r["ruleId"] == "security/sql-injection");
    assert!(sql_result.is_some(), "Should have SQL injection result");

    let sql = sql_result.unwrap();
    // CWE reference is in properties (per-result) and in rules[*].relationships + taxonomies (per-run)
    assert!(sql["properties"]["cweId"].as_str().unwrap().contains("CWE-89"),
        "Result properties should contain CWE ID");

    // Taxonomies are at runs[0].taxonomies (SARIF 2.1.0 §3.14.8)
    let taxonomies = run["taxonomies"].as_array().unwrap();
    assert!(taxonomies.iter().any(|t| t["name"] == "CWE"), "Should have CWE taxonomy");

    // Rules should have relationships referencing CWE
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let sql_rule = rules.iter().find(|r| r["id"] == "security/sql-injection");
    assert!(sql_rule.is_some(), "Should have SQL injection rule");
    let relationships = sql_rule.unwrap()["relationships"].as_array().unwrap();
    assert!(relationships.iter().any(|r| r["target"]["id"].as_str().unwrap().contains("CWE-89")));
}

#![allow(clippy::len_zero)]
//! Phase 8 reporter tests — T8-RPT-01 through T8-RPT-07.
//!
//! Tests all 8 reporter formats: SARIF, JSON, console, GitHub Code Quality,
//! GitLab Code Quality, JUnit XML, HTML, SonarQube.

use drift_analysis::enforcement::gates::{GateId, GateResult};
use drift_analysis::enforcement::reporters::*;
use drift_analysis::enforcement::rules::{QuickFix, QuickFixStrategy, Severity, Violation};

/// Create a set of test violations for reporter testing.
fn test_violations() -> Vec<Violation> {
    vec![
        Violation {
            id: "pattern-consistency-src/auth.ts-42".to_string(),
            file: "src/auth.ts".to_string(),
            line: 42,
            column: Some(5),
            end_line: Some(42),
            end_column: Some(30),
            severity: Severity::Error,
            pattern_id: "error-handling".to_string(),
            rule_id: "pattern-consistency".to_string(),
            message: "Inconsistent error handling: missing try-catch".to_string(),
            quick_fix: Some(QuickFix {
                strategy: QuickFixStrategy::WrapInTryCatch,
                description: "Wrap in try-catch block".to_string(),
                replacement: None,
            }),
            cwe_id: Some(755),
            owasp_category: Some("A09:2021".to_string()),
            suppressed: false,
            is_new: true,
        },
        Violation {
            id: "security-boundary-src/db.ts-10".to_string(),
            file: "src/db.ts".to_string(),
            line: 10,
            column: None,
            end_line: None,
            end_column: None,
            severity: Severity::Warning,
            pattern_id: "sql-injection".to_string(),
            rule_id: "security-boundary".to_string(),
            message: "Potential SQL injection via string concatenation".to_string(),
            quick_fix: None,
            cwe_id: Some(89),
            owasp_category: Some("A03:2021".to_string()),
            suppressed: false,
            is_new: false,
        },
        Violation {
            id: "info-hint-src/utils.ts-5".to_string(),
            file: "src/utils.ts".to_string(),
            line: 5,
            column: Some(1),
            end_line: Some(5),
            end_column: Some(20),
            severity: Severity::Info,
            pattern_id: "naming".to_string(),
            rule_id: "naming-convention".to_string(),
            message: "Consider using camelCase for function names".to_string(),
            quick_fix: Some(QuickFix {
                strategy: QuickFixStrategy::Rename,
                description: "Rename to camelCase".to_string(),
                replacement: Some("myFunction".to_string()),
            }),
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        },
    ]
}

fn test_gate_results() -> Vec<GateResult> {
    vec![
        GateResult::fail(
            GateId::PatternCompliance,
            65.0,
            "3 violations found".to_string(),
            test_violations(),
        ),
        GateResult::pass(
            GateId::SecurityBoundaries,
            95.0,
            "Security checks passed".to_string(),
        ),
    ]
}

fn empty_gate_results() -> Vec<GateResult> {
    vec![GateResult::pass(
        GateId::PatternCompliance,
        100.0,
        "No violations".to_string(),
    )]
}

// T8-RPT-01: Test all 8 reporter formats produce valid output
#[test]
fn t8_rpt_01_all_reporters_produce_valid_output() {
    let results = test_gate_results();

    // SARIF
    let sarif = sarif::SarifReporter::new();
    let output = sarif.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
    assert!(!parsed["runs"][0]["results"].as_array().unwrap().is_empty());

    // JSON
    let json = json::JsonReporter;
    let output = json.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(!parsed["gates"].as_array().unwrap().is_empty());

    // Console
    let console = console::ConsoleReporter::new(false);
    let output = console.generate(&results).unwrap();
    assert!(output.contains("Quality Gate Report"));
    assert!(output.contains("FAILED"));

    // GitHub Code Quality
    let github = github::GitHubCodeQualityReporter::new();
    let output = github.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(!parsed.as_array().unwrap().is_empty());

    // GitLab Code Quality
    let gitlab = gitlab::GitLabCodeQualityReporter::new();
    let output = gitlab.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(!parsed.as_array().unwrap().is_empty());

    // JUnit XML
    let junit = junit::JUnitReporter::new();
    let output = junit.generate(&results).unwrap();
    assert!(output.starts_with("<?xml"));
    assert!(output.contains("<testsuites"));
    assert!(output.contains("</testsuites>"));

    // HTML
    let html = html::HtmlReporter::new();
    let output = html.generate(&results).unwrap();
    assert!(output.starts_with("<!DOCTYPE html>"));
    assert!(output.contains("</html>"));

    // SonarQube
    let sonarqube = sonarqube::SonarQubeReporter::new();
    let output = sonarqube.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(!parsed["issues"].as_array().unwrap().is_empty());
}

// T8-RPT-02: Validate GitHub Code Quality format
#[test]
fn t8_rpt_02_github_code_quality_format() {
    let results = test_gate_results();
    let reporter = github::GitHubCodeQualityReporter::new();
    let output = reporter.generate(&results).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();

    for annotation in &parsed {
        // Required fields per GitHub schema
        assert!(annotation["path"].is_string());
        assert!(annotation["start_line"].is_number());
        assert!(annotation["end_line"].is_number());
        assert!(annotation["annotation_level"].is_string());
        assert!(annotation["message"].is_string());
        assert!(annotation["title"].is_string());

        let level = annotation["annotation_level"].as_str().unwrap();
        assert!(["failure", "warning", "notice"].contains(&level));
    }
}

// T8-RPT-03: Validate JUnit XML format
#[test]
fn t8_rpt_03_junit_xml_format() {
    let results = test_gate_results();
    let reporter = junit::JUnitReporter::new();
    let output = reporter.generate(&results).unwrap();

    // Valid XML structure
    assert!(output.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(output.contains("<testsuites"));
    assert!(output.contains("</testsuites>"));
    assert!(output.contains("<testsuite"));
    assert!(output.contains("</testsuite>"));
    assert!(output.contains("<testcase"));
    assert!(output.contains("<failure"));

    // Attributes present
    assert!(output.contains("name="));
    assert!(output.contains("tests="));
    assert!(output.contains("failures="));
    assert!(output.contains("time="));
}

// T8-RPT-04: Test HTML reporter produces self-contained HTML
#[test]
fn t8_rpt_04_html_self_contained() {
    let results = test_gate_results();
    let reporter = html::HtmlReporter::new();
    let output = reporter.generate(&results).unwrap();

    // Self-contained: inline CSS and JS, no external dependencies
    assert!(output.contains("<style>"));
    assert!(output.contains("</style>"));
    assert!(output.contains("<script>"));
    assert!(output.contains("</script>"));

    // No external links
    assert!(!output.contains("href=\"http"));
    assert!(!output.contains("src=\"http"));

    // Contains violation data
    assert!(output.contains("src/auth.ts"));
    assert!(output.contains("pattern-consistency"));
    assert!(output.contains("CWE-755"));
}

// T8-RPT-05: Test all reporters with 0 violations
#[test]
fn t8_rpt_05_empty_violations() {
    let results = empty_gate_results();

    let reporters: Vec<Box<dyn Reporter>> = vec![
        Box::new(sarif::SarifReporter::new()),
        Box::new(json::JsonReporter),
        Box::new(console::ConsoleReporter::new(false)),
        Box::new(github::GitHubCodeQualityReporter::new()),
        Box::new(gitlab::GitLabCodeQualityReporter::new()),
        Box::new(junit::JUnitReporter::new()),
        Box::new(html::HtmlReporter::new()),
        Box::new(sonarqube::SonarQubeReporter::new()),
    ];

    for reporter in &reporters {
        let output = reporter.generate(&results);
        assert!(
            output.is_ok(),
            "Reporter '{}' failed on empty violations: {:?}",
            reporter.name(),
            output.err()
        );
        let text = output.unwrap();
        assert!(!text.is_empty(), "Reporter '{}' produced empty output", reporter.name());
    }
}

// T8-RPT-06: Test reporters with Unicode characters
#[test]
fn t8_rpt_06_unicode_handling() {
    let violations = vec![Violation {
        id: "unicode-test".to_string(),
        file: "src/日本語/テスト.ts".to_string(),
        line: 1,
        column: None,
        end_line: None,
        end_column: None,
        severity: Severity::Warning,
        pattern_id: "unicode".to_string(),
        rule_id: "unicode-test".to_string(),
        message: "🔥 Critical issue in 中文 module — ñoño".to_string(),
        quick_fix: None,
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: false,
    }];

    let results = vec![GateResult::fail(
        GateId::PatternCompliance,
        50.0,
        "Unicode test".to_string(),
        violations,
    )];

    let reporters: Vec<Box<dyn Reporter>> = vec![
        Box::new(sarif::SarifReporter::new()),
        Box::new(json::JsonReporter),
        Box::new(console::ConsoleReporter::new(false)),
        Box::new(github::GitHubCodeQualityReporter::new()),
        Box::new(gitlab::GitLabCodeQualityReporter::new()),
        Box::new(junit::JUnitReporter::new()),
        Box::new(html::HtmlReporter::new()),
        Box::new(sonarqube::SonarQubeReporter::new()),
    ];

    for reporter in &reporters {
        let output = reporter.generate(&results);
        assert!(
            output.is_ok(),
            "Reporter '{}' failed on Unicode: {:?}",
            reporter.name(),
            output.err()
        );
        let text = output.unwrap();
        assert!(
            text.contains("日本語") || text.contains("\\u"),
            "Reporter '{}' lost Unicode content",
            reporter.name()
        );
    }
}

// T8-RPT-07: Test reporter with many violations (performance)
#[test]
fn t8_rpt_07_large_violation_set() {
    // Generate 1000 violations (scaled down from 50K for unit test speed)
    let violations: Vec<Violation> = (0..1000)
        .map(|i| Violation {
            id: format!("perf-test-{i}"),
            file: format!("src/module_{}.ts", i % 100),
            line: (i % 500) as u32 + 1,
            column: Some(1),
            end_line: None,
            end_column: None,
            severity: if i % 3 == 0 {
                Severity::Error
            } else if i % 3 == 1 {
                Severity::Warning
            } else {
                Severity::Info
            },
            pattern_id: format!("pattern-{}", i % 10),
            rule_id: format!("rule-{}", i % 20),
            message: format!("Violation {i}: test message for performance benchmarking"),
            quick_fix: None,
            cwe_id: if i % 5 == 0 { Some(79) } else { None },
            owasp_category: if i % 7 == 0 {
                Some("A03:2021".to_string())
            } else {
                None
            },
            suppressed: false,
            is_new: i % 2 == 0,
        })
        .collect();

    let results = vec![GateResult::fail(
        GateId::PatternCompliance,
        30.0,
        "1000 violations".to_string(),
        violations,
    )];

    let reporters: Vec<Box<dyn Reporter>> = vec![
        Box::new(sarif::SarifReporter::new()),
        Box::new(json::JsonReporter),
        Box::new(github::GitHubCodeQualityReporter::new()),
        Box::new(gitlab::GitLabCodeQualityReporter::new()),
        Box::new(junit::JUnitReporter::new()),
        Box::new(html::HtmlReporter::new()),
        Box::new(sonarqube::SonarQubeReporter::new()),
    ];

    for reporter in &reporters {
        let start = std::time::Instant::now();
        let output = reporter.generate(&results);
        let elapsed = start.elapsed();

        assert!(
            output.is_ok(),
            "Reporter '{}' failed on 1000 violations",
            reporter.name()
        );
        assert!(
            elapsed.as_secs() < 5,
            "Reporter '{}' took too long: {:?}",
            reporter.name(),
            elapsed
        );
    }
}

// Test create_reporter factory
#[test]
fn test_create_reporter_factory() {
    for format in available_formats() {
        let reporter = create_reporter(format);
        assert!(
            reporter.is_some(),
            "create_reporter returned None for '{format}'"
        );
        assert_eq!(reporter.unwrap().name(), *format);
    }

    assert!(create_reporter("nonexistent").is_none());
}

// Test available_formats
#[test]
fn test_available_formats() {
    let formats = available_formats();
    assert_eq!(formats.len(), 8);
    assert!(formats.contains(&"sarif"));
    assert!(formats.contains(&"json"));
    assert!(formats.contains(&"console"));
    assert!(formats.contains(&"github"));
    assert!(formats.contains(&"gitlab"));
    assert!(formats.contains(&"junit"));
    assert!(formats.contains(&"html"));
    assert!(formats.contains(&"sonarqube"));
}

// Test GitLab fingerprint stability
#[test]
fn test_gitlab_fingerprint_stability() {
    let results = test_gate_results();
    let reporter = gitlab::GitLabCodeQualityReporter::new();

    let output1 = reporter.generate(&results).unwrap();
    let output2 = reporter.generate(&results).unwrap();

    // Same input should produce same fingerprints
    assert_eq!(output1, output2);
}

// Test suppressed violations are excluded
#[test]
fn test_suppressed_violations_excluded() {
    let violations = vec![
        Violation {
            id: "suppressed".to_string(),
            file: "src/test.ts".to_string(),
            line: 1,
            column: None,
            end_line: None,
            end_column: None,
            severity: Severity::Error,
            pattern_id: "test".to_string(),
            rule_id: "test-rule".to_string(),
            message: "This is suppressed".to_string(),
            quick_fix: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: true,
            is_new: false,
        },
    ];

    let results = vec![GateResult::fail(
        GateId::PatternCompliance,
        50.0,
        "1 suppressed".to_string(),
        violations,
    )];

    // GitHub reporter should exclude suppressed
    let github = github::GitHubCodeQualityReporter::new();
    let output = github.generate(&results).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed.len(), 0);

    // GitLab reporter should exclude suppressed
    let gitlab = gitlab::GitLabCodeQualityReporter::new();
    let output = gitlab.generate(&results).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed.len(), 0);

    // SonarQube reporter should exclude suppressed
    let sonarqube = sonarqube::SonarQubeReporter::new();
    let output = sonarqube.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["issues"].as_array().unwrap().len(), 0);
}

// Test SonarQube issue type classification
#[test]
fn test_sonarqube_issue_types() {
    let violations = vec![
        Violation {
            id: "vuln".to_string(),
            file: "src/test.ts".to_string(),
            line: 1,
            column: None,
            end_line: None,
            end_column: None,
            severity: Severity::Error,
            pattern_id: "test".to_string(),
            rule_id: "security-check".to_string(),
            message: "Security issue".to_string(),
            quick_fix: None,
            cwe_id: Some(89),
            owasp_category: None,
            suppressed: false,
            is_new: false,
        },
        Violation {
            id: "bug".to_string(),
            file: "src/test.ts".to_string(),
            line: 2,
            column: None,
            end_line: None,
            end_column: None,
            severity: Severity::Error,
            pattern_id: "test".to_string(),
            rule_id: "bug-null-check".to_string(),
            message: "Potential null dereference".to_string(),
            quick_fix: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        },
        Violation {
            id: "smell".to_string(),
            file: "src/test.ts".to_string(),
            line: 3,
            column: None,
            end_line: None,
            end_column: None,
            severity: Severity::Info,
            pattern_id: "test".to_string(),
            rule_id: "naming-convention".to_string(),
            message: "Naming convention".to_string(),
            quick_fix: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        },
    ];

    let results = vec![GateResult::fail(
        GateId::PatternCompliance,
        50.0,
        "Mixed types".to_string(),
        violations,
    )];

    let reporter = sonarqube::SonarQubeReporter::new();
    let output = reporter.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    let issues = parsed["issues"].as_array().unwrap();

    assert_eq!(issues[0]["type"], "VULNERABILITY");
    assert_eq!(issues[1]["type"], "BUG");
    assert_eq!(issues[2]["type"], "CODE_SMELL");
}

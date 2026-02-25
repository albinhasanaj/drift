//! Production Category 10: Reporter Format Correctness
//!
//! 8 report formats, each with format-specific correctness requirements.
//! Tests T10-01 through T10-10.

use drift_analysis::enforcement::gates::{GateId, GateResult, GateStatus};
use drift_analysis::enforcement::reporters::{self, Reporter};
use drift_analysis::enforcement::rules::{QuickFix, QuickFixStrategy, Severity, Violation};

// ─── Test Helpers ──────────────────────────────────────────────────────

/// Build a violation with CWE + OWASP for security-focused tests.
fn make_cwe_owasp_violation() -> Violation {
    Violation {
        id: "sec-sql-src/db.ts-10".to_string(),
        file: "src/db.ts".to_string(),
        line: 10,
        column: Some(5),
        end_line: Some(15),
        end_column: Some(40),
        severity: Severity::Error,
        pattern_id: "sql-check".to_string(),
        rule_id: "security/sql-injection".to_string(),
        message: "SQL injection vulnerability detected".to_string(),
        quick_fix: Some(QuickFix {
            strategy: QuickFixStrategy::UseParameterizedQuery,
            description: "Use parameterized query instead of string concatenation".to_string(),
            replacement: None,
        }),
        cwe_id: Some(89),
        owasp_category: Some("A03:2021-Injection".to_string()),
        suppressed: false,
        is_new: true,
    }
}

/// Build a Warning-severity violation without CWE/OWASP.
fn make_warning_violation() -> Violation {
    Violation {
        id: "naming-src/utils.ts-25".to_string(),
        file: "src/utils.ts".to_string(),
        line: 25,
        column: None,
        end_line: None,
        end_column: None,
        severity: Severity::Warning,
        pattern_id: "naming".to_string(),
        rule_id: "naming/camelCase".to_string(),
        message: "Should use camelCase for function names".to_string(),
        quick_fix: Some(QuickFix {
            strategy: QuickFixStrategy::Rename,
            description: "Rename to camelCase".to_string(),
            replacement: Some("myFunction".to_string()),
        }),
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: false,
    }
}

/// Build an Info-severity violation.
fn make_info_violation() -> Violation {
    Violation {
        id: "doc-src/lib.ts-3".to_string(),
        file: "src/lib.ts".to_string(),
        line: 3,
        column: Some(1),
        end_line: Some(3),
        end_column: Some(20),
        severity: Severity::Info,
        pattern_id: "docs".to_string(),
        rule_id: "docs/missing-jsdoc".to_string(),
        message: "Missing JSDoc comment".to_string(),
        quick_fix: None,
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: false,
    }
}

/// Build a Hint-severity violation.
fn make_hint_violation() -> Violation {
    Violation {
        id: "hint-src/app.ts-1".to_string(),
        file: "src/app.ts".to_string(),
        line: 1,
        column: None,
        end_line: None,
        end_column: None,
        severity: Severity::Hint,
        pattern_id: "style".to_string(),
        rule_id: "style/trailing-comma".to_string(),
        message: "Consider adding trailing comma".to_string(),
        quick_fix: None,
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: true,
    }
}

/// Build gate results containing violations with all 4 severities, CWE/OWASP,
/// quick fixes, and both new/baseline violations.
fn make_mixed_gate_results() -> Vec<GateResult> {
    vec![
        GateResult {
            gate_id: GateId::PatternCompliance,
            status: GateStatus::Failed,
            passed: false,
            score: 60.0,
            summary: "Pattern compliance: 60%".to_string(),
            violations: vec![
                make_cwe_owasp_violation(),
                make_warning_violation(),
                make_info_violation(),
                make_hint_violation(),
            ],
            warnings: vec!["Insufficient data for full analysis".to_string()],
            execution_time_ms: 42,
            details: serde_json::Value::Null,
            error: None,
        },
        GateResult::pass(
            GateId::TestCoverage,
            95.0,
            "Test coverage: 95%".to_string(),
        ),
    ]
}

// ─── T10-01: SARIF Taxonomy Placement ──────────────────────────────────

/// T10-01: Taxonomies must be in `runs[0].taxonomies` and relationships
/// in `rules[0].relationships` — NOT in `results[0].taxa`.
#[test]
fn t10_01_sarif_taxonomy_placement() {
    let reporter = reporters::sarif::SarifReporter::new();
    let results = make_mixed_gate_results();
    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    let run = &sarif["runs"][0];

    // Taxonomies MUST be at runs[0].taxonomies (SARIF 2.1.0 §3.14.8)
    let taxonomies = run["taxonomies"].as_array().expect("taxonomies must exist at runs[0].taxonomies");
    let cwe_tax = taxonomies.iter().find(|t| t["name"] == "CWE");
    assert!(cwe_tax.is_some(), "CWE taxonomy must be in runs[0].taxonomies");
    let owasp_tax = taxonomies.iter().find(|t| t["name"] == "OWASP");
    assert!(owasp_tax.is_some(), "OWASP taxonomy must be in runs[0].taxonomies");

    // CWE taxa must contain CWE-89
    let cwe_taxa = cwe_tax.unwrap()["taxa"].as_array().unwrap();
    assert!(
        cwe_taxa.iter().any(|t| t["id"].as_str().unwrap().contains("CWE-89")),
        "CWE taxonomy must include CWE-89"
    );

    // Relationships MUST be on rules, NOT on results
    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules must exist");
    let sql_rule = rules.iter().find(|r| r["id"] == "security/sql-injection");
    assert!(sql_rule.is_some(), "SQL injection rule must exist");
    let relationships = sql_rule.unwrap()["relationships"].as_array()
        .expect("relationships must exist on rule");
    assert!(
        relationships.iter().any(|r| {
            r["target"]["id"].as_str().unwrap_or("").contains("CWE-89")
        }),
        "Rule relationships must reference CWE-89"
    );
    assert!(
        relationships.iter().any(|r| {
            r["target"]["toolComponent"]["name"] == "OWASP"
        }),
        "Rule relationships must reference OWASP"
    );

    // results[*] must NOT have a top-level `taxa` field (old incorrect path)
    let sarif_results = run["results"].as_array().unwrap();
    for result in sarif_results {
        assert!(
            result.get("taxa").is_none() || result["taxa"].is_null(),
            "results[*].taxa must NOT exist — taxonomy belongs on runs[0].taxonomies"
        );
    }
}

// ─── T10-02: JUnit Error/Failure Semantics ─────────────────────────────

/// T10-02: In JUnit XML, errors = infrastructure problems (Error severity),
/// failures = assertion violations (Warning severity). These must NOT be swapped.
#[test]
fn t10_02_junit_error_failure_semantics() {
    let reporter = reporters::junit::JUnitReporter::new();
    let results = make_mixed_gate_results();
    let output = reporter.generate(&results).unwrap();

    // Count Error-severity violations (should map to errors)
    let error_count = results[0]
        .violations
        .iter()
        .filter(|v| !v.suppressed && v.severity == Severity::Error)
        .count();
    // Count Warning-severity violations (should map to failures)
    let warning_count = results[0]
        .violations
        .iter()
        .filter(|v| !v.suppressed && v.severity == Severity::Warning)
        .count();

    assert!(error_count > 0, "Test setup: must have Error-severity violations");
    assert!(warning_count > 0, "Test setup: must have Warning-severity violations");

    // Parse the testsuites element — check root counts
    // The format is: <testsuites ... failures="W" errors="E" ...>
    // errors=Error-severity count, failures=Warning-severity count
    let errors_attr = extract_xml_attr(&output, "testsuites", "errors");
    let failures_attr = extract_xml_attr(&output, "testsuites", "failures");

    assert_eq!(
        errors_attr.parse::<usize>().unwrap(),
        error_count,
        "JUnit 'errors' count must equal Error-severity violation count"
    );
    assert_eq!(
        failures_attr.parse::<usize>().unwrap(),
        warning_count,
        "JUnit 'failures' count must equal Warning-severity violation count"
    );

    // Each violation testcase must have <failure type="..."> where type
    // is the severity category string.
    assert!(
        output.contains("type=\"error\""),
        "Error-severity violations must have failure type='error'"
    );
    assert!(
        output.contains("type=\"warning\""),
        "Warning-severity violations must have failure type='warning'"
    );
}

/// Helper: extract an XML attribute value from the first occurrence of an element.
fn extract_xml_attr(xml: &str, element: &str, attr: &str) -> String {
    let pattern = format!("<{element} ");
    let start = xml.find(&pattern).expect("element not found");
    let tag_end = xml[start..].find('>').unwrap() + start;
    let tag = &xml[start..tag_end];

    let attr_pattern = format!("{attr}=\"");
    let attr_start = tag.find(&attr_pattern).expect("attribute not found") + attr_pattern.len();
    let attr_end = tag[attr_start..].find('"').unwrap() + attr_start;
    tag[attr_start..attr_end].to_string()
}

// ─── T10-03: SonarQube Rules Array ─────────────────────────────────────

/// T10-03: SonarQube report must include `rules` array (required since SonarQube 10.3),
/// not just issues.
#[test]
fn t10_03_sonarqube_rules_array() {
    let reporter = reporters::sonarqube::SonarQubeReporter::new();
    let results = make_mixed_gate_results();
    let output = reporter.generate(&results).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    // Must have top-level `rules` array
    let rules = parsed["rules"].as_array().expect("SonarQube output must have 'rules' array");
    assert!(!rules.is_empty(), "rules array must not be empty when violations exist");

    // Each rule must have required fields for SonarQube 10.3+
    for rule in rules {
        assert!(rule["id"].is_string(), "Rule must have 'id'");
        assert!(rule["name"].is_string(), "Rule must have 'name'");
        assert!(rule["engineId"].is_string(), "Rule must have 'engineId'");
        assert_eq!(rule["engineId"], "drift", "engineId must be 'drift'");
    }

    // Must also have issues
    let issues = parsed["issues"].as_array().expect("SonarQube output must have 'issues' array");
    assert!(!issues.is_empty(), "issues array must not be empty when violations exist");

    // Verify severity mapping: Error→CRITICAL, Warning→MAJOR, Info→MINOR, Hint→INFO
    let severities: Vec<&str> = issues
        .iter()
        .map(|i| i["severity"].as_str().unwrap())
        .collect();
    assert!(severities.contains(&"CRITICAL"), "Error severity must map to CRITICAL");
    assert!(severities.contains(&"MAJOR"), "Warning severity must map to MAJOR");
    assert!(severities.contains(&"MINOR"), "Info severity must map to MINOR");
    assert!(severities.contains(&"INFO"), "Hint severity must map to INFO");

    // Verify issue type classification: CWE → VULNERABILITY, bug- prefix → BUG, else → CODE_SMELL
    let sql_issue = issues.iter().find(|i| i["ruleId"] == "security/sql-injection");
    assert!(sql_issue.is_some(), "SQL injection issue must exist");
    assert_eq!(
        sql_issue.unwrap()["type"], "VULNERABILITY",
        "CWE-bearing violation must be VULNERABILITY"
    );
}

// ─── T10-04: Console Report Readability ────────────────────────────────

/// T10-04: Console report must include severity counts, file grouping,
/// and quick-fix suggestions for 50+ violations.
#[test]
fn t10_04_console_report_readability() {
    // Build 50+ violations across multiple files
    let mut violations: Vec<Violation> = (0..55)
        .map(|i| Violation {
            id: format!("console-test-{i}"),
            file: format!("src/module_{}.ts", i % 5),
            line: (i + 1) as u32,
            column: Some(1),
            end_line: None,
            end_column: None,
            severity: match i % 4 {
                0 => Severity::Error,
                1 => Severity::Warning,
                2 => Severity::Info,
                _ => Severity::Hint,
            },
            pattern_id: "test".to_string(),
            rule_id: format!("rule-{}", i % 10),
            message: format!("Violation {i}"),
            quick_fix: if i % 3 == 0 {
                Some(QuickFix {
                    strategy: QuickFixStrategy::WrapInTryCatch,
                    description: "Add error handling".to_string(),
                    replacement: None,
                })
            } else {
                None
            },
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: i % 2 == 0,
        })
        .collect();

    // Add one with a quick fix to verify fix rendering
    violations.push(Violation {
        id: "with-fix".to_string(),
        file: "src/module_0.ts".to_string(),
        line: 100,
        column: None,
        end_line: None,
        end_column: None,
        severity: Severity::Error,
        pattern_id: "test".to_string(),
        rule_id: "security/xss".to_string(),
        message: "XSS vulnerability".to_string(),
        quick_fix: Some(QuickFix {
            strategy: QuickFixStrategy::WrapInTryCatch,
            description: "Sanitize user input".to_string(),
            replacement: None,
        }),
        cwe_id: None,
        owasp_category: None,
        suppressed: false,
        is_new: true,
    });

    let results = vec![GateResult::fail(
        GateId::PatternCompliance,
        30.0,
        "56 violations found".to_string(),
        violations,
    )];

    let reporter = reporters::console::ConsoleReporter::new(false);
    let output = reporter.generate(&results).unwrap();

    // Must include severity counts in summary
    assert!(output.contains("Summary"), "Console report must have Summary section");
    assert!(
        output.contains("violations"),
        "Console report must mention violation count"
    );

    // Must include file references
    assert!(output.contains("src/module_0.ts"), "Console report must list file paths");

    // Must include quick-fix suggestions
    assert!(
        output.contains("Fix:") || output.contains("💡"),
        "Console report must show quick-fix suggestions"
    );

    // Must show PASSED/FAILED result
    assert!(
        output.contains("FAILED") || output.contains("PASSED"),
        "Console report must show overall result"
    );
}

// ─── T10-05: JSON Report Schema Stability ──────────────────────────────

/// T10-05: JSON report output structure must be stable; field names must not
/// change between runs.
#[test]
fn t10_05_json_report_schema_stability() {
    let reporter = reporters::json::JsonReporter;
    let results = make_mixed_gate_results();

    let output1 = reporter.generate(&results).unwrap();
    let output2 = reporter.generate(&results).unwrap();

    let json1: serde_json::Value = serde_json::from_str(&output1).unwrap();
    let json2: serde_json::Value = serde_json::from_str(&output2).unwrap();

    // Outputs must be identical (deterministic)
    assert_eq!(json1, json2, "JSON report must be deterministic across runs");

    // Verify required top-level fields
    assert!(json1["overall_passed"].is_boolean(), "Must have 'overall_passed'");
    assert!(json1["total_violations"].is_number(), "Must have 'total_violations'");
    assert!(json1["gate_count"].is_number(), "Must have 'gate_count'");
    assert!(json1["gates"].is_array(), "Must have 'gates'");

    // Verify per-gate fields
    let gate = &json1["gates"][0];
    let required_gate_fields = [
        "gate_id", "status", "passed", "score", "summary",
        "violation_count", "violations", "warnings",
        "execution_time_ms", "details", "error",
    ];
    for field in &required_gate_fields {
        assert!(
            !gate[field].is_null() || *field == "details" || *field == "error",
            "Gate must have field '{field}'"
        );
    }

    // Verify per-violation fields
    let violation = &gate["violations"][0];
    let required_violation_fields = [
        "id", "file", "line", "severity", "rule_id", "message",
        "suppressed", "is_new",
    ];
    for field in &required_violation_fields {
        assert!(
            !violation[field].is_null(),
            "Violation must have field '{field}'"
        );
    }

    // Optional fields must still be present (as null)
    let optional_violation_fields = ["column", "end_line", "end_column", "cwe_id", "owasp_category"];
    for field in &optional_violation_fields {
        assert!(
            violation.get(field).is_some(),
            "Violation must include optional field '{field}' (even if null)"
        );
    }
}

// ─── T10-06: GitHub Annotations Format ─────────────────────────────────

/// T10-06: GitHub report must map Error→failure, Warning→warning,
/// Info/Hint→notice. `raw_details` must contain CWE+OWASP when present.
#[test]
fn t10_06_github_annotations_format() {
    let reporter = reporters::github::GitHubCodeQualityReporter::new();
    let results = make_mixed_gate_results();
    let output = reporter.generate(&results).unwrap();
    let annotations: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();

    assert_eq!(annotations.len(), 4, "4 unsuppressed violations must produce 4 annotations");

    // Build a map of rule_id → annotation for easy lookup
    let find_by_rule = |rule: &str| -> &serde_json::Value {
        annotations
            .iter()
            .find(|a| a["title"].as_str().unwrap().contains(rule))
            .unwrap_or_else(|| panic!("Annotation for rule '{rule}' not found"))
    };

    // Error → "failure"
    let error_ann = find_by_rule("security/sql-injection");
    assert_eq!(
        error_ann["annotation_level"], "failure",
        "Error severity must map to 'failure'"
    );

    // Warning → "warning"
    let warning_ann = find_by_rule("naming/camelCase");
    assert_eq!(
        warning_ann["annotation_level"], "warning",
        "Warning severity must map to 'warning'"
    );

    // Info → "notice"
    let info_ann = find_by_rule("docs/missing-jsdoc");
    assert_eq!(
        info_ann["annotation_level"], "notice",
        "Info severity must map to 'notice'"
    );

    // Hint → "notice"
    let hint_ann = find_by_rule("style/trailing-comma");
    assert_eq!(
        hint_ann["annotation_level"], "notice",
        "Hint severity must map to 'notice'"
    );

    // raw_details must contain CWE and OWASP for security violation
    let raw_details = error_ann["raw_details"].as_str()
        .expect("Security annotation must have raw_details");
    assert!(
        raw_details.contains("CWE-89"),
        "raw_details must contain CWE ID: got '{raw_details}'"
    );
    assert!(
        raw_details.contains("A03:2021-Injection"),
        "raw_details must contain OWASP category: got '{raw_details}'"
    );

    // Non-security annotations should NOT have raw_details (or it should be absent)
    assert!(
        warning_ann.get("raw_details").is_none()
            || warning_ann["raw_details"].is_null(),
        "Non-security annotation must not have raw_details"
    );
}

// ─── T10-07: GitLab Code Quality Fingerprints ──────────────────────────

/// T10-07: Two violations on same file:line but different rule_ids must have
/// different fingerprints. Categories must be inferred from rule_id prefix.
#[test]
fn t10_07_gitlab_code_quality_fingerprints() {
    // Create two violations on the SAME file and line but different rule_ids
    let violations = vec![
        Violation {
            id: "v1".to_string(),
            file: "src/shared.ts".to_string(),
            line: 42,
            column: None,
            end_line: None,
            end_column: None,
            severity: Severity::Warning,
            pattern_id: "test".to_string(),
            rule_id: "pattern-consistency".to_string(),
            message: "Pattern inconsistency".to_string(),
            quick_fix: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        },
        Violation {
            id: "v2".to_string(),
            file: "src/shared.ts".to_string(),
            line: 42,
            column: None,
            end_line: None,
            end_column: None,
            severity: Severity::Error,
            pattern_id: "test".to_string(),
            rule_id: "complexity-high".to_string(),
            message: "High complexity".to_string(),
            quick_fix: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        },
        Violation {
            id: "v3".to_string(),
            file: "src/shared.ts".to_string(),
            line: 42,
            column: None,
            end_line: None,
            end_column: None,
            severity: Severity::Warning,
            pattern_id: "test".to_string(),
            rule_id: "bug-null-check".to_string(),
            message: "Potential null dereference".to_string(),
            quick_fix: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        },
        // One with CWE for Security category
        Violation {
            id: "v4".to_string(),
            file: "src/shared.ts".to_string(),
            line: 42,
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
    ];

    let results = vec![GateResult::fail(
        GateId::PatternCompliance,
        50.0,
        "4 violations".to_string(),
        violations,
    )];

    let reporter = reporters::gitlab::GitLabCodeQualityReporter::new();
    let output = reporter.generate(&results).unwrap();
    let issues: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();

    assert_eq!(issues.len(), 4);

    // All fingerprints must differ (hash includes rule_id + file + line)
    let fingerprints: Vec<&str> = issues
        .iter()
        .map(|i| i["fingerprint"].as_str().unwrap())
        .collect();
    let unique_fps: std::collections::HashSet<&str> = fingerprints.iter().copied().collect();
    assert_eq!(
        unique_fps.len(),
        fingerprints.len(),
        "Fingerprints must be unique even for same file:line — got duplicates: {fingerprints:?}"
    );

    // Category inference from rule_id prefix
    let find_by_check = |check_name: &str| -> &serde_json::Value {
        issues
            .iter()
            .find(|i| i["check_name"] == check_name)
            .unwrap_or_else(|| panic!("Issue with check_name '{check_name}' not found"))
    };

    // "pattern-" prefix → "Style"
    let pattern_issue = find_by_check("pattern-consistency");
    let categories = pattern_issue["categories"].as_array().unwrap();
    assert!(
        categories.iter().any(|c| c == "Style"),
        "pattern- prefix must produce Style category"
    );

    // "complexity-" prefix → "Complexity"
    let complexity_issue = find_by_check("complexity-high");
    let categories = complexity_issue["categories"].as_array().unwrap();
    assert!(
        categories.iter().any(|c| c == "Complexity"),
        "complexity- prefix must produce Complexity category"
    );

    // "bug-" prefix → "Bug Risk"
    let bug_issue = find_by_check("bug-null-check");
    let categories = bug_issue["categories"].as_array().unwrap();
    assert!(
        categories.iter().any(|c| c == "Bug Risk"),
        "bug- prefix must produce Bug Risk category"
    );

    // CWE → "Security"
    let security_issue = find_by_check("security-check");
    let categories = security_issue["categories"].as_array().unwrap();
    assert!(
        categories.iter().any(|c| c == "Security"),
        "CWE-bearing violation must produce Security category"
    );
}

// ─── T10-08: HTML Report Generation ────────────────────────────────────

/// T10-08: HTML report with mixed severity violations must produce valid HTML
/// with embedded CSS styling and be viewable in a browser.
#[test]
fn t10_08_html_report_generation() {
    let reporter = reporters::html::HtmlReporter::new();
    let results = make_mixed_gate_results();
    let output = reporter.generate(&results).unwrap();

    // Must produce valid HTML
    assert!(output.starts_with("<!DOCTYPE html>"), "Must start with DOCTYPE");
    assert!(output.contains("<html"), "Must have <html> tag");
    assert!(output.contains("</html>"), "Must have closing </html>");
    assert!(output.contains("<head>"), "Must have <head>");
    assert!(output.contains("</head>"), "Must have </head>");
    assert!(output.contains("<body>"), "Must have <body>");
    assert!(output.contains("</body>"), "Must have </body>");

    // Must have embedded CSS (no external stylesheets)
    assert!(output.contains("<style>"), "Must have inline <style>");
    assert!(output.contains("</style>"), "Must close <style>");

    // Must have embedded JS (no external scripts)
    assert!(output.contains("<script>"), "Must have inline <script>");
    assert!(output.contains("</script>"), "Must close <script>");

    // Must NOT have external resource links
    assert!(!output.contains("href=\"http"), "Must not link external CSS");
    assert!(!output.contains("src=\"http"), "Must not link external JS");

    // Must contain violation data
    assert!(output.contains("src/db.ts"), "Must contain violation file paths");
    assert!(output.contains("security/sql-injection"), "Must contain rule IDs");
    assert!(output.contains("CWE-89"), "Must contain CWE references");

    // Must have severity styling classes
    assert!(output.contains("severity-error"), "Must have error severity CSS class");
    assert!(output.contains("severity-warning"), "Must have warning severity CSS class");

    // Must have gate status classes
    assert!(
        output.contains("status-passed") || output.contains("status-failed"),
        "Must have gate status CSS classes"
    );

    // Must have summary section
    assert!(
        output.contains("PASSED") || output.contains("FAILED"),
        "Must show overall result"
    );

    // Must show quick fix suggestions
    assert!(
        output.contains("Fix:") || output.contains("quick-fix"),
        "Must render quick-fix suggestions"
    );
}

// ─── T10-09: All 8 Formats via Reporter Factory ───────────────────────

/// T10-09: Call create_reporter(format) for each of the 8 formats.
/// Each must return non-empty string and not error. Reporter name must match format string.
#[test]
fn t10_09_all_8_formats_via_factory() {
    let results = make_mixed_gate_results();
    let all_formats = reporters::available_formats();

    assert_eq!(all_formats.len(), 8, "Must have exactly 8 reporter formats");

    let expected_formats = [
        "sarif", "json", "console", "github", "gitlab", "junit", "html", "sonarqube",
    ];
    for fmt in &expected_formats {
        assert!(
            all_formats.contains(fmt),
            "available_formats() must include '{fmt}'"
        );
    }

    for format in all_formats {
        let reporter = reporters::create_reporter(format);
        assert!(
            reporter.is_some(),
            "create_reporter('{format}') must return Some"
        );

        let reporter = reporter.unwrap();

        // Reporter name must match the format string
        assert_eq!(
            reporter.name(),
            *format,
            "Reporter name must match format string"
        );

        // Generate must succeed
        let output = reporter.generate(&results);
        assert!(
            output.is_ok(),
            "Reporter '{format}' failed: {:?}",
            output.err()
        );

        let text = output.unwrap();

        // Output must be non-empty
        assert!(
            !text.is_empty(),
            "Reporter '{format}' produced empty output"
        );

        // For JSON-based formats, verify valid JSON
        match *format {
            "sarif" | "json" | "github" | "gitlab" | "sonarqube" => {
                let parsed: Result<serde_json::Value, _> = serde_json::from_str(&text);
                assert!(
                    parsed.is_ok(),
                    "Reporter '{format}' produced invalid JSON: {:?}",
                    parsed.err()
                );
            }
            "junit" => {
                assert!(
                    text.starts_with("<?xml"),
                    "JUnit reporter must produce XML"
                );
            }
            "html" => {
                assert!(
                    text.starts_with("<!DOCTYPE html>"),
                    "HTML reporter must produce HTML"
                );
            }
            "console" => {
                assert!(
                    text.contains("Quality Gate Report"),
                    "Console reporter must have header"
                );
            }
            _ => {}
        }
    }

    // Unknown format must return None
    assert!(
        reporters::create_reporter("nonexistent").is_none(),
        "Unknown format must return None"
    );
}

// ─── T10-10: SARIF isNew Property ──────────────────────────────────────

/// T10-10: SARIF `properties.isNew` must be true for new violations, false for
/// baseline matches. Quick fixes must appear as `fixes[0].description`.
#[test]
fn t10_10_sarif_is_new_property() {
    let reporter = reporters::sarif::SarifReporter::new();
    let results = make_mixed_gate_results();
    let output = reporter.generate(&results).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&output).unwrap();

    let sarif_results = sarif["runs"][0]["results"].as_array().unwrap();

    // Find the new violation (SQL injection, is_new=true)
    let new_result = sarif_results
        .iter()
        .find(|r| r["ruleId"] == "security/sql-injection")
        .expect("SQL injection result must exist");
    assert_eq!(
        new_result["properties"]["isNew"], true,
        "New violation must have properties.isNew=true"
    );

    // Find the baseline violation (naming, is_new=false)
    let baseline_result = sarif_results
        .iter()
        .find(|r| r["ruleId"] == "naming/camelCase")
        .expect("Naming result must exist");
    assert_eq!(
        baseline_result["properties"]["isNew"], false,
        "Baseline violation must have properties.isNew=false"
    );

    // Quick fix must appear as fixes[0].description for the SQL injection violation
    let fixes = new_result["fixes"].as_array()
        .expect("Violation with quick_fix must have 'fixes' array");
    assert!(!fixes.is_empty(), "fixes array must not be empty");
    let fix_desc = fixes[0]["description"]["text"].as_str()
        .expect("Fix must have description.text");
    assert!(
        fix_desc.contains("parameterized query"),
        "Fix description must contain the quick fix text: got '{fix_desc}'"
    );

    // Violation without quick fix must NOT have fixes array
    let no_fix_result = sarif_results
        .iter()
        .find(|r| r["ruleId"] == "docs/missing-jsdoc")
        .expect("Info result must exist");
    assert!(
        no_fix_result.get("fixes").is_none() || no_fix_result["fixes"].is_null(),
        "Violation without quick_fix must not have 'fixes' array"
    );

    // CWE must be in properties
    assert!(
        new_result["properties"]["cweId"].as_str().unwrap().contains("CWE-89"),
        "CWE ID must be in properties.cweId"
    );

    // OWASP must be in properties
    assert!(
        new_result["properties"]["owaspCategory"]
            .as_str()
            .unwrap()
            .contains("A03:2021"),
        "OWASP category must be in properties.owaspCategory"
    );
}

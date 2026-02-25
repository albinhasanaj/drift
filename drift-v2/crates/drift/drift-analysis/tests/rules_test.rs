//! Phase 6 tests: Rules Engine — Violation Mapping & Suppression
//! T6-RUL-01 through T6-RUL-06

use drift_analysis::enforcement::rules::*;
use std::collections::HashMap;

fn make_pattern(id: &str, category: &str, confidence: f64, cwe_ids: Vec<u32>) -> PatternInfo {
    PatternInfo {
        pattern_id: id.to_string(),
        category: category.to_string(),
        confidence,
        locations: vec![PatternLocation {
            file: "src/main.ts".to_string(),
            line: 10,
            column: Some(1),
        }],
        outliers: vec![OutlierLocation {
            file: "src/utils.ts".to_string(),
            line: 25,
            column: Some(5),
            end_line: None,
            end_column: None,
            deviation_score: 2.5,
            message: format!("Deviates from pattern '{id}'"),
        }],
        cwe_ids,
        owasp_categories: Vec::new(),
    }
}

/// T6-RUL-01: Test rules engine maps patterns + outliers to violations
/// with correct severity and quick fix suggestions.
#[test]
fn test_rules_engine_maps_patterns_to_violations() {
    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: vec![
            make_pattern("naming-camelCase", "naming", 0.85, vec![]),
            make_pattern("sql-injection", "security", 0.95, vec![89]),
        ],
        source_lines: HashMap::new(),
        baseline_violation_ids: std::collections::HashSet::new(),
    };

    let violations = evaluator.evaluate(&input);
    assert!(!violations.is_empty(), "Should produce violations from outliers");

    // Security pattern with CWE-89 should be Error
    let security_v = violations.iter().find(|v| v.cwe_id == Some(89));
    assert!(security_v.is_some(), "Should have CWE-89 violation");
    assert_eq!(security_v.unwrap().severity, Severity::Error);

    // Naming pattern should be Info or Warning
    let naming_v = violations.iter().find(|v| v.pattern_id == "naming-camelCase");
    assert!(naming_v.is_some(), "Should have naming violation");
    assert!(
        naming_v.unwrap().severity == Severity::Info
            || naming_v.unwrap().severity == Severity::Warning
    );
}

/// T6-RUL-02: Test inline suppression (drift-ignore comments).
#[test]
fn test_inline_suppression() {
    let evaluator = RulesEvaluator::new();
    let mut source_lines = HashMap::new();
    source_lines.insert(
        "src/utils.ts".to_string(),
        vec![
            "// some code".to_string(),
            "// drift-ignore".to_string(),       // line 2 (index 1)
            "const x = unsafeQuery(input);".to_string(), // line 3 (index 2) — suppressed
            "const y = anotherUnsafe(input);".to_string(), // line 4 — NOT suppressed
        ],
    );

    // Outlier on line 3 (1-indexed) should be suppressed
    let input = RulesInput {
        patterns: vec![PatternInfo {
            pattern_id: "sql-check".to_string(),
            category: "security".to_string(),
            confidence: 0.9,
            locations: vec![],
            outliers: vec![
                OutlierLocation {
                    file: "src/utils.ts".to_string(),
                    line: 3,
                    column: None,
                    end_line: None,
                    end_column: None,
                    deviation_score: 3.0,
                    message: "Unsafe query".to_string(),
                },
                OutlierLocation {
                    file: "src/utils.ts".to_string(),
                    line: 4,
                    column: None,
                    end_line: None,
                    end_column: None,
                    deviation_score: 3.0,
                    message: "Another unsafe".to_string(),
                },
            ],
            cwe_ids: vec![89],
            owasp_categories: vec![],
        }],
        source_lines,
        baseline_violation_ids: std::collections::HashSet::new(),
    };

    let violations = evaluator.evaluate(&input);
    let suppressed = violations.iter().filter(|v| v.suppressed).count();
    let unsuppressed = violations.iter().filter(|v| !v.suppressed).count();
    assert!(suppressed >= 1, "At least one violation should be suppressed");
    assert!(unsuppressed >= 1, "At least one violation should NOT be suppressed");
}

/// T6-RUL-03: Test drift-ignore with specific rule ID.
#[test]
fn test_suppression_specific_rule_id() {
    let checker = SuppressionChecker::new();
    let mut source_lines = HashMap::new();
    source_lines.insert(
        "src/app.ts".to_string(),
        vec![
            "// drift-ignore security/sql-injection".to_string(),
            "const q = db.query(input);".to_string(),
        ],
    );

    // Should suppress security/sql-injection
    assert!(checker.is_suppressed(
        "src/app.ts",
        2,
        Some("security/sql-injection"),
        &source_lines
    ));

    // Should NOT suppress security/xss
    assert!(!checker.is_suppressed(
        "src/app.ts",
        2,
        Some("security/xss"),
        &source_lines
    ));
}

/// T6-RUL-04: Test all 7 quick fix strategies produce valid suggestions.
#[test]
fn test_quick_fix_strategies() {
    let generator = QuickFixGenerator::new();

    let categories = [
        ("naming", QuickFixStrategy::Rename),
        ("error_handling", QuickFixStrategy::WrapInTryCatch),
        ("import", QuickFixStrategy::AddImport),
        ("type_safety", QuickFixStrategy::AddTypeAnnotation),
        ("documentation", QuickFixStrategy::AddDocumentation),
        ("test_coverage", QuickFixStrategy::AddTest),
        ("complexity", QuickFixStrategy::ExtractFunction),
    ];

    for (category, expected_strategy) in &categories {
        let pattern = PatternInfo {
            pattern_id: format!("{category}-test"),
            category: category.to_string(),
            confidence: 0.9,
            locations: vec![],
            outliers: vec![],
            cwe_ids: vec![],
            owasp_categories: vec![],
        };
        let outlier = OutlierLocation {
            file: "test.ts".to_string(),
            line: 1,
            column: None,
            end_line: None,
            end_column: None,
            deviation_score: 2.0,
            message: "test".to_string(),
        };

        let fix = generator.suggest(&pattern, &outlier);
        assert!(fix.is_some(), "Should suggest fix for category '{category}'");
        assert_eq!(
            fix.as_ref().unwrap().strategy,
            *expected_strategy,
            "Wrong strategy for category '{category}'"
        );
        assert!(
            !fix.as_ref().unwrap().description.is_empty(),
            "Fix description should not be empty"
        );
    }
}

/// T6-RUL-05: Test violation deduplication.
#[test]
fn test_violation_deduplication() {
    let evaluator = RulesEvaluator::new();
    let input = RulesInput {
        patterns: vec![
            PatternInfo {
                pattern_id: "detector-a".to_string(),
                category: "naming".to_string(),
                confidence: 0.8,
                locations: vec![],
                outliers: vec![OutlierLocation {
                    file: "src/app.ts".to_string(),
                    line: 10,
                    column: None,
                    end_line: None,
                    end_column: None,
                    deviation_score: 2.0,
                    message: "Naming violation from detector A".to_string(),
                }],
                cwe_ids: vec![],
                owasp_categories: vec![],
            },
            PatternInfo {
                pattern_id: "detector-b".to_string(),
                category: "naming".to_string(),
                confidence: 0.8,
                locations: vec![],
                outliers: vec![OutlierLocation {
                    file: "src/app.ts".to_string(),
                    line: 10,
                    column: None,
                    end_line: None,
                    end_column: None,
                    deviation_score: 2.0,
                    message: "Naming violation from detector B".to_string(),
                }],
                cwe_ids: vec![],
                owasp_categories: vec![],
            },
        ],
        source_lines: HashMap::new(),
        baseline_violation_ids: std::collections::HashSet::new(),
    };

    let violations = evaluator.evaluate(&input);
    // Both have different rule_ids so both should appear (dedup is by file+line+rule_id)
    assert_eq!(violations.len(), 2, "Different rule_ids should not be deduped");
}

/// T6-RUL-06: Test severity assignment based on CWE.
#[test]
fn test_severity_assignment_by_cwe() {
    let evaluator = RulesEvaluator::new();

    // CWE-89 (SQL injection) → Error
    let input = RulesInput {
        patterns: vec![make_pattern("sql-inj", "security", 0.95, vec![89])],
        source_lines: HashMap::new(),
        baseline_violation_ids: std::collections::HashSet::new(),
    };
    let violations = evaluator.evaluate(&input);
    assert!(violations.iter().all(|v| v.severity == Severity::Error));

    // Naming convention → Warning or Info
    let input2 = RulesInput {
        patterns: vec![make_pattern("camelCase", "naming", 0.8, vec![])],
        source_lines: HashMap::new(),
        baseline_violation_ids: std::collections::HashSet::new(),
    };
    let violations2 = evaluator.evaluate(&input2);
    assert!(violations2.iter().all(|v| v.severity == Severity::Info || v.severity == Severity::Warning));

    // Documentation → Info
    let input3 = RulesInput {
        patterns: vec![make_pattern("jsdoc", "documentation", 0.7, vec![])],
        source_lines: HashMap::new(),
        baseline_violation_ids: std::collections::HashSet::new(),
    };
    let violations3 = evaluator.evaluate(&input3);
    assert!(violations3.iter().all(|v| v.severity == Severity::Info));
}

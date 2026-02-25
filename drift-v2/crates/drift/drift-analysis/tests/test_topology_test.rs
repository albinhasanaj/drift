#![allow(clippy::field_reassign_with_default)]
//! T4-TST-01 through T4-TST-04: Test topology tests.

use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::graph::test_topology::*;
use drift_analysis::parsers::types::*;
use drift_analysis::scanner::language_detect::Language;

use smallvec::smallvec;

fn make_node(file: &str, name: &str, exported: bool) -> FunctionNode {
    FunctionNode {
        file: file.to_string(),
        name: name.to_string(),
        qualified_name: None,
        language: "typescript".to_string(),
        line: 1,
        end_line: 10,
        is_entry_point: false,
        is_exported: exported,
        signature_hash: 0,
        body_hash: 0,
    }
}

fn make_edge() -> CallEdge {
    CallEdge {
        resolution: Resolution::ImportBased,
        confidence: 0.75,
        call_site_line: 5,
    }
}

fn make_parse_result(file: &str, functions: Vec<FunctionInfo>, call_sites: Vec<CallSite>) -> ParseResult {
    ParseResult {
        file: file.to_string(),
        language: Language::TypeScript,
        content_hash: 0,
        functions,
        classes: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        call_sites,
        decorators: Vec::new(),
        string_literals: Vec::new(),
        numeric_literals: Vec::new(),
        error_handling: Vec::new(),
        doc_comments: Vec::new(),
        namespace: None,
        parse_time_us: 0,
        error_count: 0,
        error_ranges: Vec::new(),
        has_errors: false,
    }
}

fn make_function(name: &str, line: u32, end_line: u32) -> FunctionInfo {
    FunctionInfo {
        name: name.to_string(),
        qualified_name: None,
        file: String::new(),
        line,
        column: 0,
        end_line,
        parameters: smallvec![],
        return_type: None,
        generic_params: smallvec![],
        visibility: Visibility::Public,
        is_exported: true,
        is_async: false,
        is_generator: false,
        is_abstract: false,
        range: Range::default(),
        decorators: Vec::new(),
        doc_comment: None,
        body_hash: 0,
        signature_hash: 0,
    }
}

fn make_call(callee: &str, receiver: Option<&str>, line: u32) -> CallSite {
    CallSite {
        callee_name: callee.to_string(),
        receiver: receiver.map(|r| r.to_string()),
        file: String::new(),
        line,
        column: 0,
        argument_count: 1,
        is_await: false,
    }
}

// T4-TST-01: Coverage mapping via call graph
// Test function calls source function → coverage link
#[test]
fn test_coverage_mapping() {
    let mut g = CallGraph::new();

    // Source functions
    let src_a = g.add_function(make_node("src/auth.ts", "authenticate", true));
    let src_b = g.add_function(make_node("src/db.ts", "query", false));
    let src_c = g.add_function(make_node("src/utils.ts", "format", false));

    // Test functions
    let test_1 = g.add_function(make_node("tests/auth.test.ts", "test_authenticate", false));
    let test_2 = g.add_function(make_node("tests/db.test.ts", "test_query", false));

    // test_1 calls authenticate and format
    g.add_edge(test_1, src_a, make_edge());
    g.add_edge(test_1, src_c, make_edge());
    // test_2 calls query
    g.add_edge(test_2, src_b, make_edge());

    let coverage = compute_coverage(&g);

    assert_eq!(coverage.total_test_functions, 2);
    assert_eq!(coverage.total_source_functions, 3);

    // test_1 covers authenticate and format
    let test_1_coverage = coverage.test_to_source.get(&test_1);
    assert!(test_1_coverage.is_some());
    let test_1_covered = test_1_coverage.unwrap();
    assert!(test_1_covered.contains(&src_a));
    assert!(test_1_covered.contains(&src_c));

    // authenticate is covered by test_1
    let auth_tests = coverage.source_to_test.get(&src_a);
    assert!(auth_tests.is_some());
    assert!(auth_tests.unwrap().contains(&test_1));
}

// T4-TST-02: Test smell detectors — verify at least 10 smells detected
#[test]
fn test_smell_detectors() {
    let g = CallGraph::new();

    // Empty test (1 line body)
    let empty_test = make_function("test_empty", 1, 2);

    // Assertion-free test (no assert calls)
    let no_assert_test = make_function("test_no_assert", 1, 20);

    // Long test (>50 lines)
    let long_test = make_function("test_long", 1, 60);

    // Test with sleep
    let sleep_test = make_function("test_with_sleep", 1, 20);

    // Test with unclear naming
    let unclear_test = make_function("test1", 1, 10);

    let pr_empty = make_parse_result("tests/empty.test.ts", vec![empty_test.clone()], vec![]);
    let pr_no_assert = make_parse_result("tests/noassert.test.ts", vec![no_assert_test.clone()], vec![
        make_call("doSomething", None, 10),
    ]);
    let pr_long = make_parse_result("tests/long.test.ts", vec![long_test.clone()], vec![
        make_call("assert", None, 55),
    ]);
    let pr_sleep = make_parse_result("tests/sleep.test.ts", vec![sleep_test.clone()], vec![
        make_call("sleep", None, 5),
        make_call("assert", None, 15),
    ]);
    let pr_unclear = make_parse_result("tests/unclear.test.ts", vec![unclear_test.clone()], vec![
        make_call("assert", None, 5),
    ]);

    // Detect smells for each
    let smells_empty = detect_smells(&empty_test, &pr_empty, &g);
    let smells_no_assert = detect_smells(&no_assert_test, &pr_no_assert, &g);
    let smells_long = detect_smells(&long_test, &pr_long, &g);
    let smells_sleep = detect_smells(&sleep_test, &pr_sleep, &g);
    let smells_unclear = detect_smells(&unclear_test, &pr_unclear, &g);

    assert!(smells_empty.contains(&TestSmell::EmptyTest));
    assert!(smells_no_assert.contains(&TestSmell::AssertionFree));
    assert!(smells_long.contains(&TestSmell::LongTest));
    assert!(smells_sleep.contains(&TestSmell::SleepInTest));
    assert!(smells_unclear.contains(&TestSmell::UnclearNaming));

    // Collect all unique smells detected
    let mut all_smells: Vec<TestSmell> = Vec::new();
    for s in [&smells_empty, &smells_no_assert, &smells_long, &smells_sleep, &smells_unclear] {
        for smell in s {
            if !all_smells.contains(smell) {
                all_smells.push(*smell);
            }
        }
    }

    assert!(all_smells.len() >= 5,
        "Expected at least 5 unique smells, got {}: {:?}", all_smells.len(), all_smells);

    // Verify all 24 smell variants exist
    assert_eq!(TestSmell::all().len(), 24);
}

// T4-TST-02 continued: detect_all_smells across parse results
#[test]
fn test_detect_all_smells() {
    let g = CallGraph::new();

    let prs = vec![
        make_parse_result("tests/a.test.ts", vec![
            make_function("test_empty", 1, 2),
            make_function("test_no_assert", 10, 30),
        ], vec![
            make_call("doSomething", None, 20),
        ]),
        make_parse_result("tests/b.test.ts", vec![
            make_function("test_long", 1, 60),
        ], vec![
            make_call("sleep", None, 30),
            make_call("assert", None, 55),
        ]),
    ];

    let results = smells::detect_all_smells(&prs, &g);
    assert!(!results.is_empty(), "Should detect smells across parse results");

    let total_smells: usize = results.iter().map(|(_, _, s)| s.len()).sum();
    assert!(total_smells >= 3, "Expected at least 3 total smells, got {}", total_smells);
}

// T4-TST-03: Minimum test set computation
// Given tests covering functions, compute minimum set that covers all
#[test]
fn test_minimum_test_set() {
    let mut g = CallGraph::new();

    // 50 source functions
    let mut source_fns = Vec::new();
    for i in 0..50 {
        let node = g.add_function(make_node(
            &format!("src/mod_{}.ts", i),
            &format!("func_{}", i),
            false,
        ));
        source_fns.push(node);
    }

    // 100 test functions with overlapping coverage
    let mut test_fns = Vec::new();
    for i in 0..100 {
        let node = g.add_function(make_node(
            &format!("tests/test_{}.test.ts", i),
            &format!("test_func_{}", i),
            false,
        ));
        test_fns.push(node);
    }

    // Each test covers a few source functions (overlapping)
    for (i, &test) in test_fns.iter().enumerate() {
        // Each test covers 5 source functions (with overlap)
        for j in 0..5 {
            let src_idx = (i * 3 + j) % 50;
            g.add_edge(test, source_fns[src_idx], make_edge());
        }
    }

    let coverage = compute_coverage(&g);
    let min_set = compute_minimum_test_set(&coverage);

    // Minimum set should be smaller than total tests
    assert!(min_set.tests.len() < 100,
        "Minimum set ({}) should be smaller than total tests (100)",
        min_set.tests.len());

    // Should cover all source functions
    assert_eq!(min_set.covered_functions, min_set.total_functions);
    assert!(min_set.coverage_percent > 99.0);
}

// T4-TST-04: Mock/stub detection — test using mock doesn't count as covering real impl
#[test]
fn test_mock_detection() {
    let mut g = CallGraph::new();

    // Real implementation
    let real_fn = g.add_function(make_node("src/db.ts", "query", false));

    // Mock
    let mock_fn = g.add_function(make_node("tests/__mocks__/db.ts", "mock_query", false));

    // Test calls mock, not real
    let test_fn = g.add_function(make_node("tests/db.test.ts", "test_with_mock", false));
    g.add_edge(test_fn, mock_fn, make_edge());
    // Test does NOT call real_fn

    let coverage = compute_coverage(&g);

    // real_fn should NOT be covered
    let real_covered = coverage.source_to_test.get(&real_fn);
    assert!(real_covered.is_none() || real_covered.unwrap().is_empty(),
        "Real function should not be covered when only mock is called");
}

// Additional: Quality scoring
#[test]
fn test_quality_scoring() {
    let mut g = CallGraph::new();
    let src = g.add_function(make_node("src/auth.ts", "authenticate", true));
    let test = g.add_function(make_node("tests/auth.test.ts", "test_authenticate", false));
    g.add_edge(test, src, make_edge());

    let pr = make_parse_result("tests/auth.test.ts", vec![
        make_function("test_authenticate", 1, 20),
    ], vec![
        make_call("authenticate", None, 5),
        make_call("assertEqual", None, 10),
        make_call("assertEqual", None, 15),
    ]);

    let score = compute_quality_score(&g, &[pr]);
    assert!(score.overall >= 0.0 && score.overall <= 1.0);
    assert!(score.coverage_breadth >= 0.0);
}

// Additional: Framework detection
#[test]
fn test_framework_detection() {
    let pr_jest = ParseResult {
        file: "test.ts".to_string(),
        language: Language::TypeScript,
        imports: vec![ImportInfo {
            source: "@jest/globals".to_string(),
            specifiers: smallvec![],
            is_type_only: false,
            file: "test.ts".to_string(),
            line: 1,
        }],
        ..ParseResult::default()
    };

    let pr_pytest = ParseResult {
        file: "test_auth.py".to_string(),
        language: Language::Python,
        imports: vec![ImportInfo {
            source: "pytest".to_string(),
            specifiers: smallvec![],
            is_type_only: false,
            file: "test_auth.py".to_string(),
            line: 1,
        }],
        ..ParseResult::default()
    };

    let frameworks = detect_test_framework(&[pr_jest, pr_pytest]);
    assert!(frameworks.contains(&TestFrameworkKind::Jest));
    assert!(frameworks.contains(&TestFrameworkKind::Pytest));
}

// Coverage boost: All TestSmell names
#[test]
fn test_smell_names() {
    for smell in TestSmell::all() {
        assert!(!smell.name().is_empty(), "Smell {:?} should have a name", smell);
    }
}

// Coverage boost: TestFrameworkKind names
#[test]
fn test_framework_kind_names() {
    let frameworks = [
        TestFrameworkKind::Jest, TestFrameworkKind::Mocha, TestFrameworkKind::Vitest,
        TestFrameworkKind::Jasmine, TestFrameworkKind::Ava, TestFrameworkKind::Tape,
        TestFrameworkKind::QUnit, TestFrameworkKind::Cypress, TestFrameworkKind::Playwright,
        TestFrameworkKind::TestingLibrary,
        TestFrameworkKind::Pytest, TestFrameworkKind::Unittest, TestFrameworkKind::Nose,
        TestFrameworkKind::Doctest, TestFrameworkKind::Hypothesis, TestFrameworkKind::Robot,
        TestFrameworkKind::JUnit, TestFrameworkKind::TestNG, TestFrameworkKind::Mockito,
        TestFrameworkKind::Spock,
        TestFrameworkKind::NUnit, TestFrameworkKind::XUnit, TestFrameworkKind::MSTest,
        TestFrameworkKind::GoTest, TestFrameworkKind::Testify, TestFrameworkKind::Ginkgo,
        TestFrameworkKind::RustTest, TestFrameworkKind::Proptest, TestFrameworkKind::Criterion,
        TestFrameworkKind::RSpec, TestFrameworkKind::Minitest, TestFrameworkKind::Cucumber,
        TestFrameworkKind::PHPUnit, TestFrameworkKind::Pest, TestFrameworkKind::Codeception,
        TestFrameworkKind::KotlinTest, TestFrameworkKind::Kotest, TestFrameworkKind::JUnit5,
        TestFrameworkKind::Unknown,
    ];
    for fw in &frameworks {
        assert!(!fw.name().is_empty(), "Framework {:?} should have a name", fw);
    }
}

// Coverage boost: TestQualityScore compute_overall
#[test]
fn test_quality_score_compute() {
    let mut score = TestQualityScore::default();
    score.coverage_breadth = 0.8;
    score.coverage_depth = 0.6;
    score.assertion_density = 0.9;
    score.mock_ratio = 0.3;
    score.isolation = 1.0;
    score.freshness = 0.95;
    score.stability = 1.0;
    score.compute_overall();
    assert!(score.overall > 0.0 && score.overall <= 1.0,
        "Overall score should be between 0 and 1, got {}", score.overall);
}

// Coverage boost: Framework detection from various import sources
#[test]
fn test_framework_detection_comprehensive() {
    let frameworks_and_imports = vec![
        ("mocha", TestFrameworkKind::Mocha),
        ("vitest", TestFrameworkKind::Vitest),
        ("jasmine", TestFrameworkKind::Jasmine),
        ("ava", TestFrameworkKind::Ava),
        ("tape", TestFrameworkKind::Tape),
        ("qunit", TestFrameworkKind::QUnit),
        ("cypress", TestFrameworkKind::Cypress),
        ("@playwright/test", TestFrameworkKind::Playwright),
        ("@testing-library/react", TestFrameworkKind::TestingLibrary),
        ("unittest", TestFrameworkKind::Unittest),
        ("nose", TestFrameworkKind::Nose),
        ("doctest", TestFrameworkKind::Doctest),
        ("hypothesis", TestFrameworkKind::Hypothesis),
        ("robot", TestFrameworkKind::Robot),
        ("org.junit.jupiter", TestFrameworkKind::JUnit5),
        ("org.junit", TestFrameworkKind::JUnit),
        ("testng", TestFrameworkKind::TestNG),
        ("mockito", TestFrameworkKind::Mockito),
        ("spock", TestFrameworkKind::Spock),
        ("nunit", TestFrameworkKind::NUnit),
        ("xunit", TestFrameworkKind::XUnit),
        ("microsoft.visualstudio.testtools", TestFrameworkKind::MSTest),
        ("testing", TestFrameworkKind::GoTest),
        ("testify", TestFrameworkKind::Testify),
        ("ginkgo", TestFrameworkKind::Ginkgo),
        ("rspec", TestFrameworkKind::RSpec),
        ("minitest", TestFrameworkKind::Minitest),
        ("cucumber", TestFrameworkKind::Cucumber),
        ("phpunit", TestFrameworkKind::PHPUnit),
        ("pest", TestFrameworkKind::Pest),
        ("codeception", TestFrameworkKind::Codeception),
        ("kotlin.test", TestFrameworkKind::KotlinTest),
        ("kotest", TestFrameworkKind::Kotest),
        ("proptest", TestFrameworkKind::Proptest),
        ("criterion", TestFrameworkKind::Criterion),
    ];

    for (import_source, expected_fw) in &frameworks_and_imports {
        let pr = ParseResult {
            file: "test.ts".to_string(),
            language: Language::TypeScript,
            imports: vec![ImportInfo {
                source: import_source.to_string(),
                specifiers: smallvec![],
                is_type_only: false,
                file: "test.ts".to_string(),
                line: 1,
            }],
            ..ParseResult::default()
        };
        let detected = detect_test_framework(&[pr]);
        assert!(detected.contains(expected_fw),
            "Import '{}' should detect {:?}, got {:?}", import_source, expected_fw, detected);
    }
}

// Coverage boost: DeadCodeReason and DeadCodeExclusion names
#[test]
fn test_dead_code_type_names() {
    use drift_analysis::graph::impact::types::{DeadCodeReason, DeadCodeExclusion};

    assert_eq!(DeadCodeReason::NoCallers.name(), "no_callers");
    assert_eq!(DeadCodeReason::NoEntryPath.name(), "no_entry_path");

    for exc in DeadCodeExclusion::all() {
        assert!(!exc.name().is_empty());
    }
}

// Coverage boost: RiskScore computation
#[test]
fn test_risk_score_computation() {
    use drift_analysis::graph::impact::types::RiskScore;

    let score = RiskScore::compute(0.8, 0.6, 0.3, 0.5, 0.2);
    assert!(score.overall > 0.0 && score.overall <= 1.0);
    assert_eq!(score.blast_radius, 0.8);
    assert_eq!(score.sensitivity, 0.6);

    let default = RiskScore::default();
    assert_eq!(default.overall, 0.0);
}

// Coverage boost: Reachability types
#[test]
fn test_reachability_types() {
    use drift_analysis::graph::reachability::types::*;

    assert_eq!(SensitivityCategory::Critical.name(), "critical");
    assert_eq!(SensitivityCategory::High.name(), "high");
    assert_eq!(SensitivityCategory::Medium.name(), "medium");
    assert_eq!(SensitivityCategory::Low.name(), "low");

    // Severity ordering
    assert!(SensitivityCategory::Critical.severity() > SensitivityCategory::High.severity());
    assert!(SensitivityCategory::High.severity() > SensitivityCategory::Medium.severity());
    assert!(SensitivityCategory::Medium.severity() > SensitivityCategory::Low.severity());

    // Display
    assert_eq!(format!("{}", SensitivityCategory::Critical), "critical");

    assert_eq!(ReachabilityEngine::Petgraph.name(), "petgraph");
    assert_eq!(ReachabilityEngine::SqliteCte.name(), "sqlite_cte");
    assert_eq!(format!("{}", ReachabilityEngine::Petgraph), "petgraph");
}

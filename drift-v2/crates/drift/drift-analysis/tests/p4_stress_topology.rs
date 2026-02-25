//! P4 Stress — Test Topology: coverage, smells, quality scorer, minimum set, frameworks
//!
//! Split from p4_graph_stress_test.rs for maintainability.

use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::graph::test_topology;
use drift_analysis::graph::test_topology::*;
use drift_analysis::parsers::types::{
    CallSite, DecoratorInfo, ErrorHandlingInfo, ErrorHandlingKind, FunctionInfo, ImportInfo,
    NumericContext, NumericLiteralInfo, ParseResult, Range, StringContext,
    StringLiteralInfo, Visibility,
};
use drift_analysis::scanner::language_detect::Language;

use smallvec::smallvec;

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

fn node(file: &str, name: &str, exported: bool) -> FunctionNode {
    FunctionNode {
        file: file.to_string(), name: name.to_string(), qualified_name: None,
        language: "typescript".to_string(), line: 1, end_line: 10,
        is_entry_point: false, is_exported: exported, signature_hash: 0, body_hash: 0,
    }
}

fn edge() -> CallEdge {
    CallEdge { resolution: Resolution::ImportBased, confidence: 0.75, call_site_line: 5 }
}

fn func(name: &str, line: u32, end_line: u32) -> FunctionInfo {
    FunctionInfo {
        name: name.to_string(), qualified_name: None, file: String::new(),
        line, column: 0, end_line,
        parameters: smallvec![], return_type: None, generic_params: smallvec![],
        visibility: Visibility::Public, is_exported: true, is_async: false,
        is_generator: false, is_abstract: false, range: Range::default(),
        decorators: Vec::new(), doc_comment: None, body_hash: 0, signature_hash: 0,
    }
}

fn call(callee: &str, receiver: Option<&str>, line: u32) -> CallSite {
    CallSite {
        callee_name: callee.to_string(), receiver: receiver.map(|r| r.to_string()),
        file: String::new(), line, column: 0, argument_count: 1, is_await: false,
    }
}

fn full_pr(file: &str, functions: Vec<FunctionInfo>, calls: Vec<CallSite>) -> ParseResult {
    ParseResult {
        file: file.to_string(), language: Language::TypeScript, content_hash: 0,
        functions, classes: Vec::new(), imports: Vec::new(), exports: Vec::new(),
        call_sites: calls, decorators: Vec::new(), string_literals: Vec::new(),
        numeric_literals: Vec::new(), error_handling: Vec::new(), doc_comments: Vec::new(),
        namespace: None, parse_time_us: 0, error_count: 0, error_ranges: Vec::new(),
        has_errors: false,
    }
}

fn eh_info(kind: ErrorHandlingKind, file: &str, line: u32, end_line: u32,
           caught: Option<&str>, has_body: bool, scope: Option<&str>) -> ErrorHandlingInfo {
    ErrorHandlingInfo {
        kind, file: file.to_string(), line, end_line, range: Range::default(),
        caught_type: caught.map(|s| s.to_string()), has_body,
        function_scope: scope.map(|s| s.to_string()),
    }
}

fn import_pr(file: &str, source: &str) -> ParseResult {
    ParseResult {
        file: file.to_string(), language: Language::TypeScript,
        imports: vec![ImportInfo {
            source: source.to_string(),
            specifiers: smallvec![],
            is_type_only: false,
            file: file.to_string(),
            line: 1,
        }],
        ..ParseResult::default()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Coverage mapping
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_coverage_empty_graph() {
    let g = CallGraph::new();
    let cov = test_topology::coverage::compute_coverage(&g);
    assert_eq!(cov.total_test_functions, 0);
    assert_eq!(cov.total_source_functions, 0);
    assert!(cov.test_to_source.is_empty());
    assert!(cov.source_to_test.is_empty());
}

#[test]
fn stress_coverage_all_tests_no_sources() {
    let mut g = CallGraph::new();
    g.add_function(node("test_a.ts", "test_alpha", false));
    g.add_function(node("test_b.ts", "test_beta", false));
    let cov = test_topology::coverage::compute_coverage(&g);
    assert_eq!(cov.total_test_functions, 2);
    assert_eq!(cov.total_source_functions, 0);
}

#[test]
fn stress_coverage_all_sources_no_tests() {
    let mut g = CallGraph::new();
    g.add_function(node("src/utils.ts", "formatDate", false));
    g.add_function(node("src/math.ts", "calculate", false));
    let cov = test_topology::coverage::compute_coverage(&g);
    assert_eq!(cov.total_test_functions, 0);
    assert_eq!(cov.total_source_functions, 2);
    assert!(cov.source_to_test.is_empty());
}

#[test]
fn stress_coverage_test_covers_source() {
    let mut g = CallGraph::new();
    let test_fn = g.add_function(node("test_utils.ts", "test_formatDate", false));
    let src_fn = g.add_function(node("src/utils.ts", "formatDate", false));
    g.add_edge(test_fn, src_fn, edge());
    let cov = test_topology::coverage::compute_coverage(&g);
    assert_eq!(cov.total_test_functions, 1);
    assert_eq!(cov.total_source_functions, 1);
    assert!(cov.source_to_test.get(&src_fn).unwrap().contains(&test_fn));
    assert!(cov.test_to_source.get(&test_fn).unwrap().contains(&src_fn));
}

#[test]
fn stress_coverage_transitive_coverage() {
    let mut g = CallGraph::new();
    let test_fn = g.add_function(node("test.ts", "test_chain", false));
    let a = g.add_function(node("src/a.ts", "funcA", false));
    let b = g.add_function(node("src/b.ts", "funcB", false));
    let c = g.add_function(node("src/c.ts", "funcC", false));
    g.add_edge(test_fn, a, edge());
    g.add_edge(a, b, edge());
    g.add_edge(b, c, edge());
    let cov = test_topology::coverage::compute_coverage(&g);
    let covered = cov.test_to_source.get(&test_fn).unwrap();
    assert!(covered.contains(&a));
    assert!(covered.contains(&b));
    assert!(covered.contains(&c));
}

#[test]
fn stress_coverage_multiple_tests_same_source() {
    let mut g = CallGraph::new();
    let t1 = g.add_function(node("test1.ts", "test_alpha", false));
    let t2 = g.add_function(node("test2.ts", "test_beta", false));
    let src = g.add_function(node("src/shared.ts", "sharedFunc", false));
    g.add_edge(t1, src, edge());
    g.add_edge(t2, src, edge());
    let cov = test_topology::coverage::compute_coverage(&g);
    let tests_for_src = cov.source_to_test.get(&src).unwrap();
    assert_eq!(tests_for_src.len(), 2);
}

#[test]
fn stress_coverage_is_test_function_heuristics() {
    let test_names = [
        ("test_something", "src/a.ts"),
        ("testSomething", "src/b.ts"),
        ("it_should_work", "src/c.ts"),
        ("spec_behavior", "src/d.ts"),
        ("should_handle_error", "src/e.ts"),
        ("myFunc_test", "src/f.ts"),
        ("myFunc_spec", "src/g.ts"),
        ("it", "src/h.ts"),
        ("describe", "src/i.ts"),
        ("expect", "src/j.ts"),
        ("anyFunc", "test_utils.ts"),
        ("anyFunc", "utils.spec.ts"),
        ("anyFunc", "__tests__/utils.ts"),
        ("anyFunc", "utils.test.ts"),
        ("anyFunc", "utils_test.rs"),
        ("anyFunc", "utils_test.go"),
    ];
    let mut g = CallGraph::new();
    for (name, file) in &test_names {
        g.add_function(node(file, name, false));
    }
    let cov = test_topology::coverage::compute_coverage(&g);
    assert_eq!(cov.total_test_functions, test_names.len(),
        "All {} test patterns should be detected, got {}",
        test_names.len(), cov.total_test_functions);
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: CoverageMapping field access
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_coverage_mapping_default() {
    let cov = CoverageMapping::default();
    assert!(cov.test_to_source.is_empty());
    assert!(cov.source_to_test.is_empty());
    assert_eq!(cov.total_source_functions, 0);
    assert_eq!(cov.total_test_functions, 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Smell detection: all 16 detected smells individually
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_smell_empty_test() {
    let g = CallGraph::new();
    let f = func("test_empty", 1, 2);
    let p = full_pr("test.ts", vec![f.clone()], vec![]);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::EmptyTest));
}

#[test]
fn stress_smell_assertion_free() {
    let g = CallGraph::new();
    let f = func("test_no_assert", 1, 20);
    let p = full_pr("test.ts", vec![f.clone()], vec![call("doWork", None, 5)]);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::AssertionFree));
}

#[test]
fn stress_smell_sleep_in_test() {
    let g = CallGraph::new();
    let f = func("test_with_sleep", 1, 20);
    let p = full_pr("test.ts", vec![f.clone()],
        vec![call("assert", None, 5), call("sleep", None, 10)]);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::SleepInTest));
}

#[test]
fn stress_smell_conditional_test() {
    let g = CallGraph::new();
    let f = func("test_conditional", 1, 30);
    let p = full_pr("test.ts", vec![f.clone()], vec![call("assert", None, 15)]);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::ConditionalTest));
}

#[test]
fn stress_smell_long_test() {
    let g = CallGraph::new();
    let f = func("test_long", 1, 60);
    let p = full_pr("test.ts", vec![f.clone()], vec![call("assert", None, 30)]);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::LongTest));
}

#[test]
fn stress_smell_assertion_roulette() {
    let g = CallGraph::new();
    let f = func("test_roulette", 1, 20);
    let calls: Vec<_> = (0..7).map(|i| call("assertEqual", None, 3 + i)).collect();
    let p = full_pr("test.ts", vec![f.clone()], calls);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::AssertionRoulette));
}

#[test]
fn stress_smell_eager_test() {
    let g = CallGraph::new();
    let f = func("test_eager", 1, 50);
    let mut calls: Vec<_> = (0..12).map(|i| call(&format!("doWork_{i}"), None, 3 + i)).collect();
    calls.push(call("assert", None, 40));
    let p = full_pr("test.ts", vec![f.clone()], calls);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::EagerTest));
}

#[test]
fn stress_smell_lazy_test() {
    let g = CallGraph::new();
    let f = func("test_lazy", 1, 10);
    let p = full_pr("test.ts", vec![f.clone()], vec![call("assert", None, 5)]);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::LazyTest));
}

#[test]
fn stress_smell_mystery_guest() {
    let g = CallGraph::new();
    let f = func("test_mystery", 1, 20);
    let p = full_pr("test.ts", vec![f.clone()],
        vec![call("readFile", Some("fs"), 5), call("assert", None, 15)]);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::MysteryGuest));
}

#[test]
fn stress_smell_global_state() {
    let g = CallGraph::new();
    let f = func("test_global", 1, 20);
    let p = full_pr("test.ts", vec![f.clone()],
        vec![call("getValue", Some("globalThis"), 5), call("assert", None, 15)]);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::GlobalState));
}

#[test]
fn stress_smell_complex_setup() {
    let g = CallGraph::new();
    let f = func("test_complex_setup", 1, 40);
    let mut calls: Vec<_> = (0..12).map(|i| call(&format!("setup_{i}"), None, 3 + i)).collect();
    calls.push(call("assert", None, 30));
    let p = full_pr("test.ts", vec![f.clone()], calls);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::ComplexSetup));
}

#[test]
fn stress_smell_excessive_mocking() {
    let g = CallGraph::new();
    let f = func("test_mocks", 1, 20);
    let mut calls: Vec<_> = (0..7).map(|i| call(&format!("mockService_{i}"), None, 3 + i)).collect();
    calls.push(call("assert", None, 15));
    let p = full_pr("test.ts", vec![f.clone()], calls);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::ExcessiveMocking));
}

#[test]
fn stress_smell_unclear_naming() {
    let g = CallGraph::new();
    let f = func("test1", 1, 10);
    let p = full_pr("test.ts", vec![f.clone()], vec![call("assert", None, 5)]);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::UnclearNaming));
}

#[test]
fn stress_smell_exception_swallowing() {
    let g = CallGraph::new();
    let f = func("test_swallow", 1, 20);
    let mut p = full_pr("test.ts", vec![f.clone()], vec![call("assert", None, 15)]);
    p.error_handling.push(eh_info(ErrorHandlingKind::TryCatch, "test.ts", 5, 10, None, false, Some("test_swallow")));
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::ExceptionSwallowing));
}

#[test]
fn stress_smell_magic_numbers() {
    let g = CallGraph::new();
    let f = func("test_magic", 1, 20);
    let mut p = full_pr("test.ts", vec![f.clone()], vec![call("assert", None, 15)]);
    p.numeric_literals.push(NumericLiteralInfo {
        value: 42.0, raw: "42".into(), context: NumericContext::FunctionArgument,
        file: "test.ts".into(), line: 10, column: 0, range: Range::default(),
    });
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::MagicNumbers));
}

#[test]
fn stress_smell_hardcoded_values() {
    let g = CallGraph::new();
    let f = func("test_hardcoded", 1, 20);
    let mut p = full_pr("test.ts", vec![f.clone()], vec![call("assert", None, 15)]);
    for i in 0..5 {
        p.string_literals.push(StringLiteralInfo {
            value: format!("hardcoded_value_{i}_long_enough"),
            context: StringContext::FunctionArgument,
            file: "test.ts".into(), line: 5 + i, column: 0, range: Range::default(),
        });
    }
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(smells.contains(&TestSmell::HardcodedValues));
}

#[test]
fn stress_smell_all_24_have_names() {
    assert_eq!(TestSmell::all().len(), 24);
    let mut names = std::collections::HashSet::new();
    for smell in TestSmell::all() {
        assert!(!smell.name().is_empty());
        assert!(names.insert(smell.name()), "Duplicate smell name: {}", smell.name());
    }
}

#[test]
fn stress_detect_all_smells_across_files() {
    let g = CallGraph::new();
    let prs = vec![
        full_pr("test_a.ts", vec![func("test_empty_a", 1, 2)], vec![]),
        full_pr("test_b.ts", vec![func("test_empty_b", 1, 2)], vec![]),
    ];
    let results = test_topology::smells::detect_all_smells(&prs, &g);
    assert_eq!(results.len(), 2, "Should detect smells in both files");
}

#[test]
fn stress_smell_clean_test_no_smells() {
    let g = CallGraph::new();
    let f = func("test_clean_behavior", 1, 15);
    let p = full_pr("test.ts", vec![f.clone()],
        vec![call("doWork", None, 5), call("assertEqual", None, 10)]);
    let smells = test_topology::smells::detect_smells(&f, &p, &g);
    assert!(!smells.contains(&TestSmell::EmptyTest));
    assert!(!smells.contains(&TestSmell::SleepInTest));
    assert!(!smells.contains(&TestSmell::LongTest));
    assert!(!smells.contains(&TestSmell::GlobalState));
    assert!(!smells.contains(&TestSmell::ExcessiveMocking));
}

// ═══════════════════════════════════════════════════════════════════════════
// Quality scorer: 7 dimensions, weights, boundaries
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_quality_score_empty_codebase() {
    let g = CallGraph::new();
    let score = test_topology::quality_scorer::compute_quality_score(&g, &[]);
    assert!(score.overall >= 0.0 && score.overall <= 1.0);
}

#[test]
fn stress_quality_score_compute_overall_weights() {
    let mut score = TestQualityScore {
        coverage_breadth: 1.0,
        coverage_depth: 1.0,
        assertion_density: 1.0,
        mock_ratio: 1.0,
        isolation: 1.0,
        freshness: 1.0,
        stability: 1.0,
        overall: 0.0,
        smells: vec![],
    };
    score.compute_overall();
    assert!((score.overall - 1.0).abs() < 0.01);
}

#[test]
fn stress_quality_score_all_zeros() {
    let mut score = TestQualityScore {
        isolation: 0.0,
        freshness: 0.0,
        stability: 0.0,
        ..TestQualityScore::default()
    };
    score.compute_overall();
    assert!((score.overall - 0.0).abs() < 0.01);
}

#[test]
fn stress_quality_score_clamping() {
    let mut score = TestQualityScore {
        coverage_breadth: 2.0,
        coverage_depth: 2.0,
        assertion_density: 2.0,
        mock_ratio: 2.0,
        isolation: 2.0,
        freshness: 2.0,
        stability: 2.0,
        overall: 0.0,
        smells: vec![],
    };
    score.compute_overall();
    assert!(score.overall <= 1.0);
}

#[test]
fn stress_quality_score_with_test_and_source() {
    let mut g = CallGraph::new();
    let test_fn = g.add_function(node("test.ts", "test_something", false));
    let src_fn = g.add_function(node("src/lib.ts", "doWork", false));
    g.add_edge(test_fn, src_fn, edge());
    let prs = vec![
        full_pr("test.ts",
            vec![func("test_something", 1, 15)],
            vec![call("doWork", None, 5), call("assertEqual", None, 10)]),
        full_pr("src/lib.ts",
            vec![func("doWork", 1, 20)],
            vec![]),
    ];
    let score = test_topology::quality_scorer::compute_quality_score(&g, &prs);
    assert!(score.coverage_breadth > 0.0, "Should have some coverage breadth");
    assert!(score.overall > 0.0);
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: TestQualityScore::default() values
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_quality_score_default_values() {
    let score = TestQualityScore::default();
    assert_eq!(score.coverage_breadth, 0.0);
    assert_eq!(score.coverage_depth, 0.0);
    assert_eq!(score.assertion_density, 0.0);
    assert_eq!(score.mock_ratio, 0.0);
    assert_eq!(score.isolation, 1.0); // Assume isolated by default
    assert_eq!(score.freshness, 1.0); // Assume fresh by default
    assert_eq!(score.stability, 1.0); // Assume stable by default
    assert_eq!(score.overall, 0.0);
    assert!(score.smells.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Minimum test set: greedy set cover
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_minimum_set_empty_coverage() {
    let cov = CoverageMapping::default();
    let min_set = test_topology::minimum_set::compute_minimum_test_set(&cov);
    assert!(min_set.tests.is_empty());
    assert_eq!(min_set.total_functions, 0);
    assert_eq!(min_set.covered_functions, 0);
}

#[test]
fn stress_minimum_set_single_test_covers_all() {
    let mut g = CallGraph::new();
    let test_fn = g.add_function(node("test.ts", "test_all", false));
    let s1 = g.add_function(node("src/a.ts", "funcA", false));
    let s2 = g.add_function(node("src/b.ts", "funcB", false));
    let s3 = g.add_function(node("src/c.ts", "funcC", false));
    g.add_edge(test_fn, s1, edge());
    g.add_edge(test_fn, s2, edge());
    g.add_edge(test_fn, s3, edge());
    let cov = test_topology::coverage::compute_coverage(&g);
    let min_set = test_topology::minimum_set::compute_minimum_test_set(&cov);
    assert_eq!(min_set.tests.len(), 1);
    assert_eq!(min_set.covered_functions, 3);
    assert!((min_set.coverage_percent - 100.0).abs() < 0.01);
}

#[test]
fn stress_minimum_set_no_overlap() {
    let mut g = CallGraph::new();
    let t1 = g.add_function(node("test1.ts", "test_a", false));
    let t2 = g.add_function(node("test2.ts", "test_b", false));
    let t3 = g.add_function(node("test3.ts", "test_c", false));
    let s1 = g.add_function(node("src/a.ts", "funcA", false));
    let s2 = g.add_function(node("src/b.ts", "funcB", false));
    let s3 = g.add_function(node("src/c.ts", "funcC", false));
    g.add_edge(t1, s1, edge());
    g.add_edge(t2, s2, edge());
    g.add_edge(t3, s3, edge());
    let cov = test_topology::coverage::compute_coverage(&g);
    let min_set = test_topology::minimum_set::compute_minimum_test_set(&cov);
    assert_eq!(min_set.tests.len(), 3, "Need all 3 tests when no overlap");
    assert_eq!(min_set.covered_functions, 3);
}

#[test]
fn stress_minimum_set_complete_overlap() {
    let mut g = CallGraph::new();
    let t1 = g.add_function(node("test1.ts", "test_a", false));
    let t2 = g.add_function(node("test2.ts", "test_b", false));
    let s1 = g.add_function(node("src/a.ts", "funcA", false));
    let s2 = g.add_function(node("src/b.ts", "funcB", false));
    g.add_edge(t1, s1, edge());
    g.add_edge(t1, s2, edge());
    g.add_edge(t2, s1, edge());
    g.add_edge(t2, s2, edge());
    let cov = test_topology::coverage::compute_coverage(&g);
    let min_set = test_topology::minimum_set::compute_minimum_test_set(&cov);
    assert_eq!(min_set.tests.len(), 1, "Only 1 test needed with complete overlap");
    assert_eq!(min_set.covered_functions, 2);
}

#[test]
fn stress_minimum_set_greedy_optimality() {
    let mut g = CallGraph::new();
    let t1 = g.add_function(node("test1.ts", "test_1", false));
    let t2 = g.add_function(node("test2.ts", "test_2", false));
    let t3 = g.add_function(node("test3.ts", "test_3", false));
    let sa = g.add_function(node("src/a.ts", "funcA", false));
    let sb = g.add_function(node("src/b.ts", "funcB", false));
    let sc = g.add_function(node("src/c.ts", "funcC", false));
    let sd = g.add_function(node("src/d.ts", "funcD", false));
    g.add_edge(t1, sa, edge());
    g.add_edge(t1, sb, edge());
    g.add_edge(t2, sb, edge());
    g.add_edge(t2, sc, edge());
    g.add_edge(t3, sc, edge());
    g.add_edge(t3, sd, edge());
    let cov = test_topology::coverage::compute_coverage(&g);
    let min_set = test_topology::minimum_set::compute_minimum_test_set(&cov);
    assert!(min_set.tests.len() <= 3);
    assert_eq!(min_set.covered_functions, 4);
    assert!((min_set.coverage_percent - 100.0).abs() < 0.01);
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: MinimumTestSet struct fields
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_minimum_test_set_struct_fields() {
    let mut g = CallGraph::new();
    let t = g.add_function(node("test.ts", "test_x", false));
    let s = g.add_function(node("src/x.ts", "funcX", false));
    g.add_edge(t, s, edge());
    let cov = test_topology::coverage::compute_coverage(&g);
    let min_set = test_topology::minimum_set::compute_minimum_test_set(&cov);
    assert_eq!(min_set.tests.len(), 1);
    assert_eq!(min_set.covered_functions, 1);
    assert_eq!(min_set.total_functions, 1);
    assert!((min_set.coverage_percent - 100.0).abs() < 0.01);
}

// ═══════════════════════════════════════════════════════════════════════════
// Framework detection: imports, decorators, file patterns
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_framework_detect_jest() {
    let prs = vec![import_pr("test.ts", "@jest/globals")];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::Jest));
}

#[test]
fn stress_framework_detect_mocha() {
    let prs = vec![import_pr("test.ts", "mocha")];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::Mocha));
}

#[test]
fn stress_framework_detect_vitest() {
    let prs = vec![import_pr("test.ts", "vitest")];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::Vitest));
}

#[test]
fn stress_framework_detect_pytest() {
    let prs = vec![import_pr("test.py", "pytest")];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::Pytest));
}

#[test]
fn stress_framework_detect_junit() {
    let prs = vec![import_pr("Test.java", "org.junit")];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::JUnit));
}

#[test]
fn stress_framework_detect_junit5() {
    let prs = vec![import_pr("Test.java", "org.junit.jupiter")];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::JUnit5));
}

#[test]
fn stress_framework_detect_rspec() {
    let prs = vec![import_pr("spec.rb", "rspec")];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::RSpec));
}

#[test]
fn stress_framework_detect_go_test() {
    let prs = vec![import_pr("main_test.go", "testing")];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::GoTest));
}

#[test]
fn stress_framework_detect_phpunit() {
    let prs = vec![import_pr("Test.php", "phpunit")];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::PHPUnit));
}

#[test]
fn stress_framework_detect_nunit() {
    let prs = vec![import_pr("Test.cs", "nunit")];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::NUnit));
}

#[test]
fn stress_framework_detect_xunit_decorator() {
    let mut p = ParseResult {
        file: "Test.cs".into(), language: Language::TypeScript,
        ..ParseResult::default()
    };
    let mut f = func("TestMethod", 1, 10);
    f.decorators.push(DecoratorInfo {
        name: "Fact".into(),
        arguments: smallvec![],
        raw_text: "[Fact]".into(),
        range: Range::default(),
    });
    p.functions.push(f);
    let fws = test_topology::frameworks::detect_test_framework(&[p]);
    assert!(fws.contains(&TestFrameworkKind::XUnit));
}

#[test]
fn stress_framework_detect_mstest_decorator() {
    let mut p = ParseResult {
        file: "Test.cs".into(), language: Language::TypeScript,
        ..ParseResult::default()
    };
    let mut f = func("TestMethod", 1, 10);
    f.decorators.push(DecoratorInfo {
        name: "TestMethod".into(),
        arguments: smallvec![],
        raw_text: "[TestMethod]".into(),
        range: Range::default(),
    });
    p.functions.push(f);
    let fws = test_topology::frameworks::detect_test_framework(&[p]);
    assert!(fws.contains(&TestFrameworkKind::MSTest));
}

#[test]
fn stress_framework_file_pattern_fallback() {
    let p = ParseResult {
        file: "utils.test.ts".into(), language: Language::TypeScript,
        functions: vec![func("test_something", 1, 10)],
        ..ParseResult::default()
    };
    let fws = test_topology::frameworks::detect_test_framework(&[p]);
    let _ = fws;
}

#[test]
fn stress_framework_import_based_all_languages() {
    let prs = vec![
        import_pr("test.py", "pytest"),
        import_pr("test.ts", "jest"),
        import_pr("test.go", "testing"),
        import_pr("test.rb", "rspec"),
        import_pr("test.rs", "proptest"),
        import_pr("test.php", "phpunit"),
    ];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::Pytest));
    assert!(fws.contains(&TestFrameworkKind::Jest));
    assert!(fws.contains(&TestFrameworkKind::GoTest));
    assert!(fws.contains(&TestFrameworkKind::RSpec));
    assert!(fws.contains(&TestFrameworkKind::Proptest));
    assert!(fws.contains(&TestFrameworkKind::PHPUnit));
}

#[test]
fn stress_framework_multiple_detected() {
    let prs = vec![
        import_pr("test.ts", "jest"),
        import_pr("e2e.ts", "cypress"),
    ];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert!(fws.contains(&TestFrameworkKind::Jest));
    assert!(fws.contains(&TestFrameworkKind::Cypress));
    assert_eq!(fws.len(), 2);
}

#[test]
fn stress_framework_no_duplicates() {
    let prs = vec![
        import_pr("test1.ts", "jest"),
        import_pr("test2.ts", "jest"),
    ];
    let fws = test_topology::frameworks::detect_test_framework(&prs);
    assert_eq!(fws.iter().filter(|&&f| f == TestFrameworkKind::Jest).count(), 1);
}

#[test]
fn stress_all_framework_kinds_have_names() {
    let all = [
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
    assert_eq!(all.len(), 39);
    let mut names = std::collections::HashSet::new();
    for fw in &all {
        assert!(!fw.name().is_empty());
        assert!(names.insert(fw.name()), "Duplicate framework name: {}", fw.name());
    }
}

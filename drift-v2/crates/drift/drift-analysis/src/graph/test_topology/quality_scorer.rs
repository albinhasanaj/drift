//! 7-dimension quality scoring aggregation.

use super::coverage::compute_coverage;
use super::smells::detect_all_smells;
use super::types::{CoverageMapping, TestQualityScore};
use crate::call_graph::types::CallGraph;
use crate::parsers::types::ParseResult;

/// Compute the overall test quality score for a codebase.
pub fn compute_quality_score(
    graph: &CallGraph,
    parse_results: &[ParseResult],
) -> TestQualityScore {
    let coverage = compute_coverage(graph);
    let smells = detect_all_smells(parse_results, graph);

    let coverage_breadth = compute_coverage_breadth(&coverage);
    let coverage_depth = compute_coverage_depth(&coverage);
    let assertion_density = compute_assertion_density(parse_results);
    let mock_ratio = compute_mock_ratio(parse_results);
    let isolation = compute_isolation(parse_results);

    let all_smells: Vec<_> = smells
        .into_iter()
        .flat_map(|(_, _, s)| s)
        .collect();

    let mut score = TestQualityScore {
        coverage_breadth,
        coverage_depth,
        assertion_density,
        mock_ratio,
        isolation,
        freshness: 1.0, // Would need git history
        stability: 1.0, // Would need CI history
        overall: 0.0,
        smells: all_smells,
    };

    score.compute_overall();
    score
}

/// Coverage breadth: % of source functions covered by at least 1 test.
fn compute_coverage_breadth(coverage: &CoverageMapping) -> f32 {
    if coverage.total_source_functions == 0 {
        return 0.0;
    }
    let covered = coverage.source_to_test.len();
    (covered as f32 / coverage.total_source_functions as f32).min(1.0)
}

/// Coverage depth: average number of tests per covered source function.
fn compute_coverage_depth(coverage: &CoverageMapping) -> f32 {
    if coverage.source_to_test.is_empty() {
        return 0.0;
    }
    let total_tests: usize = coverage.source_to_test.values().map(|t| t.len()).sum();
    let avg = total_tests as f32 / coverage.source_to_test.len() as f32;
    // Normalize: 3+ tests per function = 1.0
    (avg / 3.0).min(1.0)
}

/// Assertion density: average assertions per test function.
fn compute_assertion_density(parse_results: &[ParseResult]) -> f32 {
    let mut total_assertions = 0usize;
    let mut total_tests = 0usize;

    let assertion_patterns = ["assert", "expect", "should", "verify"];

    for pr in parse_results {
        for func in &pr.functions {
            let name_lower = func.name.to_lowercase();
            let file_lower = pr.file.to_lowercase();

            let is_test = name_lower.starts_with("test_")
                || name_lower.starts_with("test")
                || file_lower.contains("test")
                || file_lower.contains("spec");

            if is_test {
                total_tests += 1;
                let assertions = pr.call_sites.iter()
                    .filter(|cs| {
                        cs.line >= func.line
                            && cs.line <= func.end_line
                            && assertion_patterns.iter().any(|p| {
                                cs.callee_name.to_lowercase().contains(p)
                            })
                    })
                    .count();
                total_assertions += assertions;
            }
        }
    }

    if total_tests == 0 {
        return 0.0;
    }

    let avg = total_assertions as f32 / total_tests as f32;
    // Normalize: 3+ assertions per test = 1.0
    (avg / 3.0).min(1.0)
}

/// Mock ratio: proportion of test dependencies that are mocked.
fn compute_mock_ratio(parse_results: &[ParseResult]) -> f32 {
    let mut total_calls = 0usize;
    let mut mock_calls = 0usize;

    let mock_patterns = ["mock", "stub", "spy", "fake", "jest.fn", "sinon"];

    for pr in parse_results {
        let file_lower = pr.file.to_lowercase();
        if !file_lower.contains("test") && !file_lower.contains("spec") {
            continue;
        }

        for cs in &pr.call_sites {
            total_calls += 1;
            if mock_patterns.iter().any(|p| cs.callee_name.to_lowercase().contains(p)) {
                mock_calls += 1;
            }
        }
    }

    if total_calls == 0 {
        return 0.5; // Neutral if no data
    }

    let ratio = mock_calls as f32 / total_calls as f32;
    // Optimal mock ratio is 0.2-0.4. Too high or too low is bad.
    // Score peaks at 0.3, drops off at extremes.
    let distance_from_optimal = (ratio - 0.3).abs();
    (1.0 - distance_from_optimal * 2.0).max(0.0)
}

/// Isolation: test independence (shared state detection).
fn compute_isolation(parse_results: &[ParseResult]) -> f32 {
    let mut total_tests = 0usize;
    let mut isolated_tests = 0usize;

    let shared_state_patterns = ["global", "singleton", "static", "shared", "window.", "process."];

    for pr in parse_results {
        let file_lower = pr.file.to_lowercase();
        if !file_lower.contains("test") && !file_lower.contains("spec") {
            continue;
        }

        for func in &pr.functions {
            let name_lower = func.name.to_lowercase();
            if !name_lower.starts_with("test") && !name_lower.starts_with("it") {
                continue;
            }

            total_tests += 1;

            let uses_shared = pr.call_sites.iter().any(|cs| {
                cs.line >= func.line
                    && cs.line <= func.end_line
                    && shared_state_patterns.iter().any(|p| {
                        cs.callee_name.to_lowercase().contains(p)
                            || cs.receiver.as_ref().map(|r| r.to_lowercase().contains(p)).unwrap_or(false)
                    })
            });

            if !uses_shared {
                isolated_tests += 1;
            }
        }
    }

    if total_tests == 0 {
        return 1.0;
    }

    isolated_tests as f32 / total_tests as f32
}

//! Minimum test set computation via greedy set cover algorithm.

use drift_core::types::collections::FxHashSet;
use petgraph::graph::NodeIndex;

use super::types::{CoverageMapping, MinimumTestSet};

/// Compute the minimum test set that covers all source functions.
///
/// Uses a greedy set cover algorithm: repeatedly select the test
/// that covers the most uncovered source functions.
pub fn compute_minimum_test_set(coverage: &CoverageMapping) -> MinimumTestSet {
    let mut uncovered: FxHashSet<NodeIndex> = coverage
        .source_to_test
        .keys()
        .copied()
        .collect();

    let total_functions = uncovered.len();
    let mut selected_tests: Vec<NodeIndex> = Vec::new();

    while !uncovered.is_empty() {
        // Find the test that covers the most uncovered functions
        let best_test = coverage
            .test_to_source
            .iter()
            .max_by_key(|(_, covered)| {
                covered.intersection(&uncovered).count()
            });

        match best_test {
            Some((test_idx, covered)) => {
                let newly_covered: Vec<NodeIndex> = covered
                    .intersection(&uncovered)
                    .copied()
                    .collect();

                if newly_covered.is_empty() {
                    break; // No test can cover remaining functions
                }

                selected_tests.push(*test_idx);
                for func in newly_covered {
                    uncovered.remove(&func);
                }
            }
            None => break,
        }
    }

    let covered_functions = total_functions - uncovered.len();
    let coverage_percent = if total_functions > 0 {
        covered_functions as f32 / total_functions as f32 * 100.0
    } else {
        0.0
    };

    MinimumTestSet {
        tests: selected_tests,
        covered_functions,
        total_functions,
        coverage_percent,
    }
}

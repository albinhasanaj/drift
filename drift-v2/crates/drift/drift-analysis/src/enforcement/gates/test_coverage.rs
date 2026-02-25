//! Gate 4: Test Coverage — Is coverage above threshold?

use super::types::*;
use crate::enforcement::rules::{Severity, Violation};

/// Gate 4: Checks that test coverage meets the configured threshold.
pub struct TestCoverageGate;

impl QualityGate for TestCoverageGate {
    fn id(&self) -> GateId {
        GateId::TestCoverage
    }

    fn name(&self) -> &'static str {
        "Test Coverage"
    }

    fn description(&self) -> &'static str {
        "Verifies that test coverage meets the configured threshold"
    }

    fn evaluate(&self, input: &GateInput) -> GateResult {
        let coverage_input = match &input.test_coverage {
            Some(c) => c,
            None => {
                return GateResult::skipped(
                    GateId::TestCoverage,
                    "No test coverage data available".to_string(),
                );
            }
        };

        let score = coverage_input.overall_coverage;
        let threshold = coverage_input.threshold;

        let mut violations = Vec::new();
        for file in &coverage_input.uncovered_files {
            violations.push(Violation {
                id: format!("test-coverage-{file}"),
                file: file.clone(),
                line: 0,
                column: None,
                end_line: None,
                end_column: None,
                severity: Severity::Warning,
                pattern_id: "test-coverage".to_string(),
                rule_id: "test-coverage/uncovered-file".to_string(),
                message: "File has insufficient test coverage".to_string(),
                quick_fix: None,
                cwe_id: None,
                owasp_category: None,
                suppressed: false,
                is_new: false,
            });
        }

        if score >= threshold {
            GateResult::pass(
                GateId::TestCoverage,
                score,
                format!("Test coverage: {score:.1}% (threshold: {threshold:.1}%)"),
            )
        } else {
            GateResult::fail(
                GateId::TestCoverage,
                score,
                format!(
                    "Test coverage {score:.1}% below threshold {threshold:.1}%"
                ),
                violations,
            )
        }
    }
}

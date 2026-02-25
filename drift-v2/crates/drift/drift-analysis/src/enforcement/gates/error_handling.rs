//! Gate 5: Error Handling — Are errors properly handled?

use super::types::*;
use crate::enforcement::rules::{Severity, Violation};

/// Gate 5: Checks that errors are properly handled throughout the codebase.
pub struct ErrorHandlingGate;

impl QualityGate for ErrorHandlingGate {
    fn id(&self) -> GateId {
        GateId::ErrorHandling
    }

    fn name(&self) -> &'static str {
        "Error Handling"
    }

    fn description(&self) -> &'static str {
        "Verifies that errors are properly handled and not silently swallowed"
    }

    fn evaluate(&self, input: &GateInput) -> GateResult {
        if input.error_gaps.is_empty() {
            return GateResult::skipped(
                GateId::ErrorHandling,
                "No error handling data available".to_string(),
            );
        }

        let mut violations = Vec::new();

        for gap in &input.error_gaps {
            let severity = match gap.gap_type.as_str() {
                "swallowed" | "unhandled" => Severity::Error,
                "generic_catch" | "empty_catch" => Severity::Warning,
                _ => Severity::Info,
            };

            violations.push(Violation {
                id: format!("error-handling-{}-{}", gap.file, gap.line),
                file: gap.file.clone(),
                line: gap.line,
                column: None,
                end_line: None,
                end_column: None,
                severity,
                pattern_id: "error-handling".to_string(),
                rule_id: format!("error-handling/{}", gap.gap_type),
                message: gap.message.clone(),
                quick_fix: None,
                cwe_id: None,
                owasp_category: None,
                suppressed: false,
                is_new: false,
            });
        }

        let error_count = violations
            .iter()
            .filter(|v| v.severity == Severity::Error)
            .count();
        let total = input.error_gaps.len();
        let score = if total > 0 {
            ((total - error_count) as f64 / total as f64) * 100.0
        } else {
            100.0
        };

        if error_count > 0 {
            GateResult::fail(
                GateId::ErrorHandling,
                score,
                format!("{error_count} critical error handling gaps"),
                violations,
            )
        } else if !violations.is_empty() {
            let warnings: Vec<String> = violations
                .iter()
                .take(5)
                .map(|v| v.message.clone())
                .collect();
            GateResult::warn(
                GateId::ErrorHandling,
                score,
                format!("{} error handling warnings", violations.len()),
                warnings,
            )
        } else {
            GateResult::pass(
                GateId::ErrorHandling,
                100.0,
                "No error handling gaps detected".to_string(),
            )
        }
    }
}

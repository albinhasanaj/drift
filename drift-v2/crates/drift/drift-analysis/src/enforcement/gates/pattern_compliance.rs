//! Gate 1: Pattern Compliance — Are approved patterns followed?

use super::types::*;
use crate::enforcement::rules::{Severity, Violation};

/// Gate 1: Checks whether approved patterns are being followed.
pub struct PatternComplianceGate;

impl QualityGate for PatternComplianceGate {
    fn id(&self) -> GateId {
        GateId::PatternCompliance
    }

    fn name(&self) -> &'static str {
        "Pattern Compliance"
    }

    fn description(&self) -> &'static str {
        "Verifies that approved coding patterns are followed consistently"
    }

    fn evaluate(&self, input: &GateInput) -> GateResult {
        let mut violations = Vec::new();
        let mut total_locations = 0usize;
        let mut total_outliers = 0usize;

        for pattern in &input.patterns {
            total_locations += pattern.locations.len();
            total_outliers += pattern.outliers.len();

            for outlier in &pattern.outliers {
                let severity = if pattern.confidence >= 0.9 {
                    Severity::Error
                } else if pattern.confidence >= 0.7 {
                    Severity::Warning
                } else {
                    Severity::Info
                };

                violations.push(Violation {
                    id: format!(
                        "pattern-compliance-{}-{}",
                        outlier.file, outlier.line
                    ),
                    file: outlier.file.clone(),
                    line: outlier.line,
                    column: outlier.column,
                    end_line: None,
                    end_column: None,
                    severity,
                    pattern_id: pattern.pattern_id.clone(),
                    rule_id: format!("pattern-compliance/{}", pattern.pattern_id),
                    message: format!(
                        "Deviates from approved pattern '{}' (confidence: {:.0}%)",
                        pattern.pattern_id,
                        pattern.confidence * 100.0
                    ),
                    quick_fix: None,
                    cwe_id: None,
                    owasp_category: None,
                    suppressed: false,
                    is_new: false,
                });
            }
        }

        let compliance_rate = if total_locations + total_outliers > 0 {
            total_locations as f64 / (total_locations + total_outliers) as f64
        } else {
            1.0
        };

        let score = compliance_rate * 100.0;
        let has_errors = violations.iter().any(|v| v.severity == Severity::Error);

        if has_errors {
            GateResult::fail(
                GateId::PatternCompliance,
                score,
                format!(
                    "Pattern compliance: {:.1}% ({} violations)",
                    score,
                    violations.len()
                ),
                violations,
            )
        } else if !violations.is_empty() {
            let warnings: Vec<String> = violations
                .iter()
                .take(5)
                .map(|v| v.message.clone())
                .collect();
            GateResult::warn(
                GateId::PatternCompliance,
                score,
                format!(
                    "Pattern compliance: {:.1}% ({} warnings)",
                    score,
                    violations.len()
                ),
                warnings,
            )
        } else {
            GateResult::pass(
                GateId::PatternCompliance,
                score,
                format!("Pattern compliance: {:.1}%", score),
            )
        }
    }
}

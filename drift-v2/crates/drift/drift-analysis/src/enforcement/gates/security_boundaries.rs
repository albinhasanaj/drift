//! Gate 3: Security Boundaries — Are sensitive fields protected?

use super::types::*;
use crate::enforcement::rules::{Severity, Violation};

/// Gate 3: Checks that sensitive fields and security boundaries are protected.
pub struct SecurityBoundariesGate;

impl QualityGate for SecurityBoundariesGate {
    fn id(&self) -> GateId {
        GateId::SecurityBoundaries
    }

    fn name(&self) -> &'static str {
        "Security Boundaries"
    }

    fn description(&self) -> &'static str {
        "Verifies that sensitive fields are protected and security boundaries are enforced"
    }

    fn dependencies(&self) -> Vec<GateId> {
        vec![GateId::PatternCompliance]
    }

    fn evaluate(&self, input: &GateInput) -> GateResult {
        if input.security_findings.is_empty() {
            return GateResult::skipped(
                GateId::SecurityBoundaries,
                "No security analysis data available".to_string(),
            );
        }

        let mut violations = Vec::new();

        for finding in &input.security_findings {
            let severity = match finding.severity.as_str() {
                "critical" | "high" => Severity::Error,
                "medium" => Severity::Warning,
                _ => Severity::Info,
            };

            violations.push(Violation {
                id: format!("security-{}-{}", finding.file, finding.line),
                file: finding.file.clone(),
                line: finding.line,
                column: None,
                end_line: None,
                end_column: None,
                severity,
                pattern_id: "security-boundary".to_string(),
                rule_id: format!(
                    "security/{}",
                    finding
                        .cwe_ids
                        .first()
                        .map(|c| format!("CWE-{c}"))
                        .unwrap_or_else(|| "generic".to_string())
                ),
                message: finding.description.clone(),
                quick_fix: None,
                cwe_id: finding.cwe_ids.first().copied(),
                owasp_category: finding.owasp_categories.first().cloned(),
                suppressed: false,
                is_new: false,
            });
        }

        let error_count = violations
            .iter()
            .filter(|v| v.severity == Severity::Error)
            .count();
        let score = if input.security_findings.is_empty() {
            100.0
        } else {
            let safe = input.security_findings.len() - error_count;
            (safe as f64 / input.security_findings.len() as f64) * 100.0
        };

        if error_count > 0 {
            GateResult::fail(
                GateId::SecurityBoundaries,
                score,
                format!(
                    "{} critical/high security findings",
                    error_count
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
                GateId::SecurityBoundaries,
                score,
                format!("{} security findings (non-critical)", violations.len()),
                warnings,
            )
        } else {
            GateResult::pass(
                GateId::SecurityBoundaries,
                100.0,
                "No security boundary violations".to_string(),
            )
        }
    }
}

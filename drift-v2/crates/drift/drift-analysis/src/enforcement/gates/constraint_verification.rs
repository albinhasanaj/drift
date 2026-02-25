//! Gate 2: Constraint Verification — Are architectural constraints met?

use super::types::*;
use crate::enforcement::rules::{Severity, Violation};

/// Gate 2: Verifies that architectural constraints are satisfied.
pub struct ConstraintVerificationGate;

impl QualityGate for ConstraintVerificationGate {
    fn id(&self) -> GateId {
        GateId::ConstraintVerification
    }

    fn name(&self) -> &'static str {
        "Constraint Verification"
    }

    fn description(&self) -> &'static str {
        "Verifies that architectural constraints and invariants are satisfied"
    }

    fn dependencies(&self) -> Vec<GateId> {
        vec![GateId::PatternCompliance]
    }

    fn evaluate(&self, input: &GateInput) -> GateResult {
        if input.constraints.is_empty() {
            return GateResult::skipped(
                GateId::ConstraintVerification,
                "No architectural constraints defined".to_string(),
            );
        }

        let mut violations = Vec::new();
        let total_constraints = input.constraints.len();
        let mut passing = 0usize;

        for constraint in &input.constraints {
            if constraint.passed {
                passing += 1;
            } else {
                for cv in &constraint.violations {
                    violations.push(Violation {
                        id: format!("constraint-{}-{}", constraint.id, cv.file),
                        file: cv.file.clone(),
                        line: cv.line.unwrap_or(0),
                        column: None,
                        end_line: None,
                        end_column: None,
                        severity: Severity::Error,
                        pattern_id: constraint.id.clone(),
                        rule_id: format!("constraint/{}", constraint.id),
                        message: format!(
                            "Constraint '{}' violated: {}",
                            constraint.description, cv.message
                        ),
                        quick_fix: None,
                        cwe_id: None,
                        owasp_category: None,
                        suppressed: false,
                        is_new: false,
                    });
                }
            }
        }

        let score = if total_constraints > 0 {
            (passing as f64 / total_constraints as f64) * 100.0
        } else {
            100.0
        };

        if violations.is_empty() {
            GateResult::pass(
                GateId::ConstraintVerification,
                score,
                format!(
                    "All {} constraints satisfied",
                    total_constraints
                ),
            )
        } else {
            GateResult::fail(
                GateId::ConstraintVerification,
                score,
                format!(
                    "{}/{} constraints passing ({} violations)",
                    passing,
                    total_constraints,
                    violations.len()
                ),
                violations,
            )
        }
    }
}

//! JSON reporter — structured JSON output.

use serde_json::json;

use crate::enforcement::gates::GateResult;
use super::Reporter;

/// JSON reporter for machine-readable output.
pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn name(&self) -> &'static str {
        "json"
    }

    fn generate(&self, results: &[GateResult]) -> Result<String, String> {
        let gates: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                json!({
                    "gate_id": r.gate_id,
                    "status": r.status,
                    "passed": r.passed,
                    "score": r.score,
                    "summary": r.summary,
                    "violation_count": r.violations.len(),
                    "violations": r.violations.iter().map(|v| json!({
                        "id": v.id,
                        "file": v.file,
                        "line": v.line,
                        "column": v.column,
                        "end_line": v.end_line,
                        "end_column": v.end_column,
                        "severity": format!("{}", v.severity),
                        "rule_id": v.rule_id,
                        "message": v.message,
                        "cwe_id": v.cwe_id,
                        "owasp_category": v.owasp_category,
                        "suppressed": v.suppressed,
                        "is_new": v.is_new,
                    })).collect::<Vec<_>>(),
                    "warnings": r.warnings,
                    "execution_time_ms": r.execution_time_ms,
                    "details": r.details,
                    "error": r.error,
                })
            })
            .collect();

        let total_violations: usize = results.iter().map(|r| r.violations.len()).sum();
        let all_passed = results.iter().all(|r| r.passed);

        let output = json!({
            "overall_passed": all_passed,
            "total_violations": total_violations,
            "gate_count": results.len(),
            "gates": gates,
        });

        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }
}

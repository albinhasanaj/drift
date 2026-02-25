//! GitHub Code Quality reporter — JSON format per GitHub's documented schema.
//!
//! Produces output compatible with GitHub's Code Scanning / Code Quality integration.
//! Each violation maps to a GitHub Code Quality annotation.

use serde_json::{json, Value};

use crate::enforcement::gates::GateResult;
use crate::enforcement::rules::Severity;
use super::Reporter;

/// GitHub Code Quality reporter.
///
/// Produces JSON output conforming to GitHub's Code Quality report format.
/// Each violation becomes an annotation with severity, location, and message.
pub struct GitHubCodeQualityReporter;

impl GitHubCodeQualityReporter {
    pub fn new() -> Self {
        Self
    }

    fn severity_to_github(severity: &Severity) -> &'static str {
        match severity {
            Severity::Error => "failure",
            Severity::Warning => "warning",
            Severity::Info => "notice",
            Severity::Hint => "notice",
        }
    }
}

impl Default for GitHubCodeQualityReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for GitHubCodeQualityReporter {
    fn name(&self) -> &'static str {
        "github"
    }

    fn generate(&self, results: &[GateResult]) -> Result<String, String> {
        let mut annotations: Vec<Value> = Vec::new();

        for gate_result in results {
            for violation in &gate_result.violations {
                if violation.suppressed {
                    continue;
                }

                let mut annotation = json!({
                    "path": violation.file,
                    "start_line": violation.line.max(1),
                    "end_line": violation.end_line.unwrap_or(violation.line).max(1),
                    "annotation_level": Self::severity_to_github(&violation.severity),
                    "message": violation.message,
                    "title": format!("[{}] {}", violation.rule_id, gate_result.gate_id),
                });

                if let Some(col) = violation.column {
                    annotation["start_column"] = json!(col);
                }
                if let Some(end_col) = violation.end_column {
                    annotation["end_column"] = json!(end_col);
                }

                // Add raw details for enrichment
                let mut raw_details = String::new();
                if let Some(cwe_id) = violation.cwe_id {
                    raw_details.push_str(&format!("CWE-{cwe_id}"));
                }
                if let Some(ref owasp) = violation.owasp_category {
                    if !raw_details.is_empty() {
                        raw_details.push_str(", ");
                    }
                    raw_details.push_str(owasp);
                }
                if !raw_details.is_empty() {
                    annotation["raw_details"] = json!(raw_details);
                }

                annotations.push(annotation);
            }
        }

        serde_json::to_string_pretty(&annotations).map_err(|e| e.to_string())
    }
}

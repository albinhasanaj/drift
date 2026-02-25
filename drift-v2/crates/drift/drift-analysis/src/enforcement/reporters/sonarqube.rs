//! SonarQube Generic Issue Format reporter.
//!
//! Produces JSON output conforming to SonarQube's Generic Issue Import format.
//! See: https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/
//!
//! Note: Marked P2 (post-launch) but tracked for completeness.

use serde_json::{json, Value};

use crate::enforcement::gates::GateResult;
use crate::enforcement::rules::Severity;
use super::Reporter;

/// SonarQube Generic Issue Format reporter.
///
/// Produces JSON conforming to SonarQube's external issue import format.
/// Each violation maps to a SonarQube issue with type, severity, and location.
pub struct SonarQubeReporter;

impl SonarQubeReporter {
    pub fn new() -> Self {
        Self
    }

    fn severity_to_sonarqube(severity: &Severity) -> &'static str {
        match severity {
            Severity::Error => "CRITICAL",
            Severity::Warning => "MAJOR",
            Severity::Info => "MINOR",
            Severity::Hint => "INFO",
        }
    }

    fn issue_type_for_violation(
        violation: &crate::enforcement::rules::Violation,
    ) -> &'static str {
        if violation.cwe_id.is_some() || violation.owasp_category.is_some() {
            "VULNERABILITY"
        } else if violation.rule_id.starts_with("bug-")
            || violation.rule_id.starts_with("error-")
        {
            "BUG"
        } else {
            "CODE_SMELL"
        }
    }
}

impl Default for SonarQubeReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for SonarQubeReporter {
    fn name(&self) -> &'static str {
        "sonarqube"
    }

    fn generate(&self, results: &[GateResult]) -> Result<String, String> {
        let mut issues: Vec<Value> = Vec::new();

        for gate_result in results {
            for violation in &gate_result.violations {
                if violation.suppressed {
                    continue;
                }

                let mut primary_location = json!({
                    "message": violation.message,
                    "filePath": violation.file,
                    "textRange": {
                        "startLine": violation.line.max(1),
                        "endLine": violation.end_line.unwrap_or(violation.line).max(1)
                    }
                });

                if let Some(col) = violation.column {
                    primary_location["textRange"]["startColumn"] = json!(col.saturating_sub(1));
                }
                if let Some(end_col) = violation.end_column {
                    primary_location["textRange"]["endColumn"] = json!(end_col.saturating_sub(1));
                }

                let issue = json!({
                    "engineId": "drift",
                    "ruleId": violation.rule_id,
                    "severity": Self::severity_to_sonarqube(&violation.severity),
                    "type": Self::issue_type_for_violation(violation),
                    "primaryLocation": primary_location,
                    "effortMinutes": match violation.severity {
                        Severity::Error => 30,
                        Severity::Warning => 15,
                        Severity::Info => 5,
                        Severity::Hint => 2,
                    }
                });

                issues.push(issue);
            }
        }

        // Build rules array (required since SonarQube 10.3)
        let mut rules: Vec<Value> = Vec::new();
        let mut seen_rules = std::collections::HashSet::new();
        for gate_result in results {
            for violation in &gate_result.violations {
                if violation.suppressed {
                    continue;
                }
                if seen_rules.insert(violation.rule_id.clone()) {
                    rules.push(json!({
                        "id": violation.rule_id,
                        "name": violation.rule_id,
                        "description": violation.message,
                        "engineId": "drift",
                        "cleanCodeAttribute": "CONVENTIONAL",
                        "impacts": [{
                            "softwareQuality": if violation.cwe_id.is_some() { "SECURITY" } else { "MAINTAINABILITY" },
                            "severity": Self::severity_to_sonarqube(&violation.severity)
                        }]
                    }));
                }
            }
        }

        let output = json!({
            "rules": rules,
            "issues": issues
        });

        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
    }
}

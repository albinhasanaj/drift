//! GitLab Code Quality reporter — JSON format per GitLab's Code Quality report schema.
//!
//! Produces output compatible with GitLab's Code Quality widget in merge requests.
//! See: https://docs.gitlab.com/ee/ci/testing/code_quality.html

use serde_json::{json, Value};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::enforcement::gates::GateResult;
use crate::enforcement::rules::{Severity, Violation};
use super::Reporter;

/// GitLab Code Quality reporter.
///
/// Produces JSON array conforming to GitLab's Code Quality report format.
/// Each violation becomes a Code Quality issue with fingerprint for deduplication.
pub struct GitLabCodeQualityReporter;

impl GitLabCodeQualityReporter {
    pub fn new() -> Self {
        Self
    }

    fn severity_to_gitlab(severity: &Severity) -> &'static str {
        match severity {
            Severity::Error => "critical",
            Severity::Warning => "major",
            Severity::Info => "minor",
            Severity::Hint => "info",
        }
    }

    /// Generate a stable fingerprint for deduplication across runs.
    fn fingerprint(violation: &Violation) -> String {
        let mut hasher = DefaultHasher::new();
        violation.rule_id.hash(&mut hasher);
        violation.file.hash(&mut hasher);
        violation.line.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

impl Default for GitLabCodeQualityReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for GitLabCodeQualityReporter {
    fn name(&self) -> &'static str {
        "gitlab"
    }

    fn generate(&self, results: &[GateResult]) -> Result<String, String> {
        let mut issues: Vec<Value> = Vec::new();

        for gate_result in results {
            for violation in &gate_result.violations {
                if violation.suppressed {
                    continue;
                }

                let mut description = violation.message.clone();
                if let Some(cwe_id) = violation.cwe_id {
                    description.push_str(&format!(" (CWE-{cwe_id})"));
                }

                let issue = json!({
                    "type": "issue",
                    "check_name": violation.rule_id,
                    "description": description,
                    "categories": Self::categories_for_violation(violation),
                    "severity": Self::severity_to_gitlab(&violation.severity),
                    "fingerprint": Self::fingerprint(violation),
                    "location": {
                        "path": violation.file,
                        "lines": {
                            "begin": violation.line.max(1),
                            "end": violation.end_line.unwrap_or(violation.line).max(1)
                        }
                    }
                });

                issues.push(issue);
            }
        }

        serde_json::to_string_pretty(&issues).map_err(|e| e.to_string())
    }
}

impl GitLabCodeQualityReporter {
    fn categories_for_violation(violation: &Violation) -> Vec<&'static str> {
        let mut categories = Vec::new();

        if violation.cwe_id.is_some() || violation.owasp_category.is_some() {
            categories.push("Security");
        }

        // Infer category from rule_id prefix
        let rule = &violation.rule_id;
        if rule.starts_with("pattern-") {
            categories.push("Style");
        } else if rule.starts_with("complexity-") || rule.starts_with("coupling-") {
            categories.push("Complexity");
        } else if rule.starts_with("bug-") || rule.starts_with("error-") {
            categories.push("Bug Risk");
        }

        if categories.is_empty() {
            categories.push("Style");
        }

        categories
    }
}

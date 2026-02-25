//! JUnit XML reporter — standard JUnit XML schema output.
//!
//! Produces output parseable by Jenkins, GitHub Actions, and other CI systems.
//! Each gate maps to a testsuite, each violation maps to a testcase failure.

use crate::enforcement::gates::{GateResult, GateStatus};
use crate::enforcement::rules::Severity;
use super::Reporter;

/// JUnit XML reporter.
///
/// Produces standard JUnit XML output where:
/// - Each quality gate is a `<testsuite>`
/// - Each violation is a `<testcase>` with a `<failure>` element
/// - Passing gates produce a single passing `<testcase>`
pub struct JUnitReporter;

impl JUnitReporter {
    pub fn new() -> Self {
        Self
    }

    fn escape_xml(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    fn severity_to_type(severity: &Severity) -> &'static str {
        match severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
            Severity::Hint => "hint",
        }
    }
}

impl Default for JUnitReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for JUnitReporter {
    fn name(&self) -> &'static str {
        "junit"
    }

    fn generate(&self, results: &[GateResult]) -> Result<String, String> {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

        // Calculate totals for the root element
        let total_tests: usize = results
            .iter()
            .map(|r| if r.violations.is_empty() { 1 } else { r.violations.len() })
            .sum();
        let total_errors: usize = results
            .iter()
            .map(|r| {
                r.violations
                    .iter()
                    .filter(|v| !v.suppressed && v.severity == Severity::Error)
                    .count()
            })
            .sum();
        let total_failures: usize = results
            .iter()
            .map(|r| {
                r.violations
                    .iter()
                    .filter(|v| !v.suppressed && v.severity == Severity::Warning)
                    .count()
            })
            .sum();
        let total_time: f64 = results.iter().map(|r| r.execution_time_ms as f64 / 1000.0).sum();

        xml.push_str(&format!(
            "<testsuites name=\"Drift Quality Gates\" tests=\"{}\" failures=\"{}\" errors=\"{}\" time=\"{:.3}\">\n",
            total_tests, total_failures, total_errors, total_time
        ));

        for result in results {
            let suite_tests = if result.violations.is_empty() {
                1
            } else {
                result.violations.len()
            };
            let suite_errors = result
                .violations
                .iter()
                .filter(|v| !v.suppressed && v.severity == Severity::Error)
                .count();
            let suite_failures = result
                .violations
                .iter()
                .filter(|v| !v.suppressed && v.severity == Severity::Warning)
                .count();
            let suite_time = result.execution_time_ms as f64 / 1000.0;

            xml.push_str(&format!(
                "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"{}\" time=\"{:.3}\">\n",
                Self::escape_xml(result.gate_id.as_str()),
                suite_tests,
                suite_failures,
                suite_errors,
                suite_time
            ));

            if result.violations.is_empty() {
                // Gate passed with no violations — emit a passing testcase
                xml.push_str(&format!(
                    "    <testcase name=\"{}\" classname=\"drift.gates.{}\" time=\"{:.3}\"",
                    Self::escape_xml(&result.summary),
                    Self::escape_xml(result.gate_id.as_str()),
                    suite_time
                ));

                match result.status {
                    GateStatus::Skipped => {
                        xml.push_str(">\n");
                        xml.push_str("      <skipped />\n");
                        xml.push_str("    </testcase>\n");
                    }
                    _ => {
                        xml.push_str(" />\n");
                    }
                }
            } else {
                for violation in &result.violations {
                    if violation.suppressed {
                        continue;
                    }

                    let classname = format!(
                        "drift.gates.{}",
                        Self::escape_xml(result.gate_id.as_str())
                    );
                    let testname = format!(
                        "{} ({}:{})",
                        Self::escape_xml(&violation.rule_id),
                        Self::escape_xml(&violation.file),
                        violation.line
                    );

                    xml.push_str(&format!(
                        "    <testcase name=\"{}\" classname=\"{}\" time=\"0.000\">\n",
                        testname, classname
                    ));

                    let failure_type = Self::severity_to_type(&violation.severity);
                    let message = Self::escape_xml(&violation.message);
                    let detail = format!(
                        "{}:{}:{}: {}",
                        Self::escape_xml(&violation.file),
                        violation.line,
                        violation.column.unwrap_or(0),
                        message
                    );

                    xml.push_str(&format!(
                        "      <failure type=\"{}\" message=\"{}\">{}</failure>\n",
                        failure_type, message, detail
                    ));

                    xml.push_str("    </testcase>\n");
                }
            }

            xml.push_str("  </testsuite>\n");
        }

        xml.push_str("</testsuites>\n");
        Ok(xml)
    }
}

//! Console reporter — human-readable output with color codes.

use crate::enforcement::gates::{GateResult, GateStatus};
use crate::enforcement::rules::Severity;
use super::Reporter;

/// Console reporter for human-readable terminal output.
pub struct ConsoleReporter {
    pub use_color: bool,
}

impl ConsoleReporter {
    pub fn new(use_color: bool) -> Self {
        Self { use_color }
    }

    fn status_symbol(&self, status: &GateStatus) -> &'static str {
        match status {
            GateStatus::Passed => "✓",
            GateStatus::Failed => "✗",
            GateStatus::Warned => "⚠",
            GateStatus::Skipped => "⊘",
            GateStatus::Errored => "⚡",
        }
    }

    fn severity_prefix(&self, severity: &Severity) -> &'static str {
        match severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
            Severity::Hint => "hint",
        }
    }

    fn color_start(&self, severity: &Severity) -> &'static str {
        if !self.use_color {
            return "";
        }
        match severity {
            Severity::Error => "\x1b[31m",   // red
            Severity::Warning => "\x1b[33m", // yellow
            Severity::Info => "\x1b[36m",    // cyan
            Severity::Hint => "\x1b[90m",    // gray
        }
    }

    fn color_end(&self) -> &'static str {
        if self.use_color {
            "\x1b[0m"
        } else {
            ""
        }
    }
}

impl Default for ConsoleReporter {
    fn default() -> Self {
        Self::new(true)
    }
}

impl Reporter for ConsoleReporter {
    fn name(&self) -> &'static str {
        "console"
    }

    fn generate(&self, results: &[GateResult]) -> Result<String, String> {
        let mut output = String::new();

        output.push_str("╔══════════════════════════════════════════╗\n");
        output.push_str("║         Drift Quality Gate Report        ║\n");
        output.push_str("╚══════════════════════════════════════════╝\n\n");

        for result in results {
            let symbol = self.status_symbol(&result.status);
            output.push_str(&format!(
                "{} {} — {} (score: {:.1})\n",
                symbol,
                result.gate_id,
                result.summary,
                result.score
            ));

            // Show violations
            for violation in &result.violations {
                let prefix = self.severity_prefix(&violation.severity);
                let cs = self.color_start(&violation.severity);
                let ce = self.color_end();
                let new_tag = if violation.is_new { " [NEW]" } else { "" };
                let suppressed_tag = if violation.suppressed { " [suppressed]" } else { "" };
                output.push_str(&format!(
                    "  {}{}:{}: {}:{}:{}: {}{}{}\n",
                    cs,
                    prefix,
                    ce,
                    violation.file,
                    violation.line,
                    violation.column.unwrap_or(0),
                    violation.message,
                    new_tag,
                    suppressed_tag,
                ));
                if let Some(ref fix) = violation.quick_fix {
                    output.push_str(&format!("    💡 Fix: {}\n", fix.description));
                }
            }

            // Show warnings
            for warning in &result.warnings {
                output.push_str(&format!("  ⚠ {warning}\n"));
            }

            output.push('\n');
        }

        // Summary
        let total_violations: usize = results.iter().map(|r| r.violations.len()).sum();
        let passed = results.iter().filter(|r| r.passed).count();
        let total = results.len();
        let all_passed = results.iter().all(|r| r.passed);

        output.push_str(&format!(
            "─── Summary: {passed}/{total} gates passed, {total_violations} violations ───\n"
        ));

        if all_passed {
            output.push_str("Result: PASSED ✓\n");
        } else {
            output.push_str("Result: FAILED ✗\n");
        }

        Ok(output)
    }
}

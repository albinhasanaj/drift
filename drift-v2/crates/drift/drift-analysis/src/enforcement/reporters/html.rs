//! HTML reporter — self-contained HTML report with inline CSS/JS.
//!
//! Produces a single HTML file with no external dependencies that renders
//! a violation list with severity, location, and quick fix suggestions.

use crate::enforcement::gates::{GateResult, GateStatus};
use crate::enforcement::rules::Severity;
use super::Reporter;

/// Self-contained HTML reporter.
///
/// Produces a single HTML file with inline CSS and JavaScript.
/// No external dependencies — the file renders correctly when opened directly.
pub struct HtmlReporter {
    pub title: String,
}

impl HtmlReporter {
    pub fn new() -> Self {
        Self {
            title: "Drift Quality Gate Report".to_string(),
        }
    }

    pub fn with_title(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
        }
    }

    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    fn severity_class(severity: &Severity) -> &'static str {
        match severity {
            Severity::Error => "severity-error",
            Severity::Warning => "severity-warning",
            Severity::Info => "severity-info",
            Severity::Hint => "severity-hint",
        }
    }

    fn status_class(status: &GateStatus) -> &'static str {
        match status {
            GateStatus::Passed => "status-passed",
            GateStatus::Failed => "status-failed",
            GateStatus::Warned => "status-warned",
            GateStatus::Skipped => "status-skipped",
            GateStatus::Errored => "status-errored",
        }
    }

    fn status_icon(status: &GateStatus) -> &'static str {
        match status {
            GateStatus::Passed => "&#x2713;",
            GateStatus::Failed => "&#x2717;",
            GateStatus::Warned => "&#x26A0;",
            GateStatus::Skipped => "&#x2298;",
            GateStatus::Errored => "&#x26A1;",
        }
    }
}

impl Default for HtmlReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for HtmlReporter {
    fn name(&self) -> &'static str {
        "html"
    }

    fn generate(&self, results: &[GateResult]) -> Result<String, String> {
        let total_violations: usize = results
            .iter()
            .map(|r| r.violations.iter().filter(|v| !v.suppressed).count())
            .sum();
        let passed = results.iter().filter(|r| r.passed).count();
        let total = results.len();
        let all_passed = results.iter().all(|r| r.passed);

        let mut html = String::with_capacity(8192);

        // DOCTYPE and head
        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str(&format!("<title>{}</title>\n", Self::escape_html(&self.title)));
        html.push_str("<style>\n");
        html.push_str(INLINE_CSS);
        html.push_str("</style>\n</head>\n<body>\n");

        // Header
        html.push_str("<div class=\"container\">\n");
        html.push_str(&format!("<h1>{}</h1>\n", Self::escape_html(&self.title)));

        // Summary bar
        let overall_class = if all_passed { "summary-pass" } else { "summary-fail" };
        html.push_str(&format!(
            "<div class=\"summary {}\">\n",
            overall_class
        ));
        html.push_str(&format!(
            "<span class=\"summary-result\">{}</span>\n",
            if all_passed { "PASSED" } else { "FAILED" }
        ));
        html.push_str(&format!(
            "<span class=\"summary-detail\">{passed}/{total} gates passed &middot; {total_violations} violations</span>\n"
        ));
        html.push_str("</div>\n");

        // Gate sections
        for result in results {
            let status_cls = Self::status_class(&result.status);
            let icon = Self::status_icon(&result.status);
            html.push_str(&format!(
                "<div class=\"gate {}\">\n",
                status_cls
            ));
            html.push_str(&format!(
                "<h2>{} {} <span class=\"score\">Score: {:.1}</span></h2>\n",
                icon,
                Self::escape_html(result.gate_id.as_str()),
                result.score
            ));
            html.push_str(&format!(
                "<p class=\"gate-summary\">{}</p>\n",
                Self::escape_html(&result.summary)
            ));

            let active_violations: Vec<_> = result
                .violations
                .iter()
                .filter(|v| !v.suppressed)
                .collect();

            if active_violations.is_empty() {
                html.push_str("<p class=\"no-violations\">No violations</p>\n");
            } else {
                html.push_str("<table class=\"violations\">\n");
                html.push_str("<thead><tr><th>Severity</th><th>Location</th><th>Rule</th><th>Message</th></tr></thead>\n");
                html.push_str("<tbody>\n");

                for violation in &active_violations {
                    let sev_cls = Self::severity_class(&violation.severity);
                    html.push_str(&format!(
                        "<tr class=\"{}\">\n",
                        sev_cls
                    ));
                    let new_badge = if violation.is_new {
                        " <span class=\"badge badge-new\">NEW</span>"
                    } else {
                        ""
                    };
                    html.push_str(&format!(
                        "<td><span class=\"badge {}\">{}</span>{}</td>\n",
                        sev_cls,
                        violation.severity,
                        new_badge
                    ));
                    html.push_str(&format!(
                        "<td class=\"location\">{}:{}:{}</td>\n",
                        Self::escape_html(&violation.file),
                        violation.line,
                        violation.column.unwrap_or(0)
                    ));
                    html.push_str(&format!(
                        "<td class=\"rule\">{}</td>\n",
                        Self::escape_html(&violation.rule_id)
                    ));

                    let mut msg = Self::escape_html(&violation.message);
                    if let Some(ref fix) = violation.quick_fix {
                        msg.push_str(&format!(
                            "<br><span class=\"quick-fix\">Fix: {}</span>",
                            Self::escape_html(&fix.description)
                        ));
                    }
                    if let Some(cwe_id) = violation.cwe_id {
                        msg.push_str(&format!(
                            " <span class=\"tag\">CWE-{cwe_id}</span>"
                        ));
                    }
                    if let Some(ref owasp) = violation.owasp_category {
                        msg.push_str(&format!(
                            " <span class=\"tag\">{}</span>",
                            Self::escape_html(owasp)
                        ));
                    }
                    html.push_str(&format!("<td>{msg}</td>\n"));
                    html.push_str("</tr>\n");
                }

                html.push_str("</tbody>\n</table>\n");
            }

            // Warnings
            if !result.warnings.is_empty() {
                html.push_str("<div class=\"warnings\">\n");
                for warning in &result.warnings {
                    html.push_str(&format!(
                        "<p class=\"warning-item\">&#x26A0; {}</p>\n",
                        Self::escape_html(warning)
                    ));
                }
                html.push_str("</div>\n");
            }

            html.push_str("</div>\n");
        }

        // Footer
        html.push_str("<footer>Generated by Drift v2.0.0</footer>\n");
        html.push_str("</div>\n");

        // Inline JS for filtering
        html.push_str("<script>\n");
        html.push_str(INLINE_JS);
        html.push_str("</script>\n");

        html.push_str("</body>\n</html>\n");
        Ok(html)
    }
}

const INLINE_CSS: &str = r#"
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
h1 { margin-bottom: 16px; font-size: 24px; }
h2 { font-size: 18px; margin-bottom: 8px; }
.summary { padding: 16px; border-radius: 8px; margin-bottom: 24px; display: flex; align-items: center; gap: 16px; }
.summary-pass { background: #d4edda; border: 1px solid #c3e6cb; }
.summary-fail { background: #f8d7da; border: 1px solid #f5c6cb; }
.summary-result { font-size: 20px; font-weight: 700; }
.summary-detail { font-size: 14px; color: #555; }
.gate { background: #fff; border-radius: 8px; padding: 16px; margin-bottom: 16px; border: 1px solid #ddd; }
.status-passed { border-left: 4px solid #28a745; }
.status-failed { border-left: 4px solid #dc3545; }
.status-warned { border-left: 4px solid #ffc107; }
.status-skipped { border-left: 4px solid #6c757d; }
.status-errored { border-left: 4px solid #fd7e14; }
.score { float: right; font-size: 14px; color: #666; font-weight: 400; }
.gate-summary { color: #555; margin-bottom: 12px; font-size: 14px; }
.no-violations { color: #28a745; font-style: italic; }
.violations { width: 100%; border-collapse: collapse; font-size: 13px; }
.violations th { text-align: left; padding: 8px; background: #f8f9fa; border-bottom: 2px solid #dee2e6; }
.violations td { padding: 8px; border-bottom: 1px solid #eee; vertical-align: top; }
.badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
.severity-error .badge { background: #f8d7da; color: #721c24; }
.severity-warning .badge { background: #fff3cd; color: #856404; }
.severity-info .badge { background: #d1ecf1; color: #0c5460; }
.severity-hint .badge { background: #e2e3e5; color: #383d41; }
.badge-new { background: #007bff; color: #fff; margin-left: 4px; }
.location { font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 12px; white-space: nowrap; }
.rule { font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 12px; color: #6f42c1; }
.quick-fix { color: #28a745; font-size: 12px; }
.tag { display: inline-block; padding: 1px 6px; border-radius: 3px; background: #e9ecef; font-size: 11px; margin-left: 4px; }
.warnings { margin-top: 8px; }
.warning-item { color: #856404; font-size: 13px; padding: 4px 0; }
footer { text-align: center; color: #999; font-size: 12px; margin-top: 32px; padding: 16px 0; }
"#;

const INLINE_JS: &str = r#"
// Minimal interactivity: click gate header to collapse/expand
document.querySelectorAll('.gate h2').forEach(function(h) {
    h.style.cursor = 'pointer';
    h.addEventListener('click', function() {
        var gate = h.parentElement;
        var table = gate.querySelector('.violations');
        if (table) {
            table.style.display = table.style.display === 'none' ? '' : 'none';
        }
    });
});
"#;

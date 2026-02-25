//! Security detector — injection, XSS, CSRF, auth bypass, secrets.

use smallvec::SmallVec;

use crate::detectors::traits::{Detector, DetectorCategory, DetectorVariant};
use crate::engine::types::{DetectionMethod, PatternCategory, PatternMatch};
use crate::engine::visitor::DetectionContext;

pub struct SecurityDetector;

impl Detector for SecurityDetector {
    fn id(&self) -> &str { "security-base" }
    fn category(&self) -> DetectorCategory { DetectorCategory::Security }
    fn variant(&self) -> DetectorVariant { DetectorVariant::Base }
    fn is_critical(&self) -> bool { true }

    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Detect eval() usage
        for call in ctx.call_sites {
            if call.callee_name == "eval" {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "SEC-EVAL-001".to_string(),
                    confidence: 0.90,
                    cwe_ids: SmallVec::from_buf([95, 0]),
                    owasp: Some("A03:2021".to_string()),
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Security,
                    matched_text: format!("eval() call at {}:{}", call.line, call.column),
                });
            }

            // Detect exec/spawn for command injection (all languages)
            if matches!(call.callee_name.as_str(),
                // JS/TS
                "exec" | "execSync" | "spawn" | "execFile" | "fork"
                // Python
                | "system" | "popen" | "call" | "run" | "check_output" | "check_call"
                // Java
                | "getRuntime" | "ProcessBuilder"
                // C#
                | "Start"  // Process.Start
                // Go
                | "Command" | "CombinedOutput" | "Output"  // exec.Command
                // Ruby (system already listed above)
                | "backtick" | "Open3"
                // PHP
                | "shell_exec" | "passthru" | "proc_open"
                // Rust (Command/spawn already listed above)
                | "output"  // std::process::Command
            ) {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "SEC-CMDI-001".to_string(),
                    confidence: 0.75,
                    cwe_ids: SmallVec::from_buf([78, 0]),
                    owasp: Some("A03:2021".to_string()),
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Security,
                    matched_text: format!("{}() — potential command injection", call.callee_name),
                });
            }

            // Detect XSS patterns (expanded beyond innerHTML)
            if call.callee_name.contains("innerHTML") || call.callee_name.contains("dangerouslySetInnerHTML")
                || call.callee_name.contains("outerHTML") || call.callee_name == "document.write"
                || call.callee_name == "document.writeln"
                || call.callee_name == "html_safe"  // Ruby
                || call.callee_name == "raw"  // Ruby/PHP
                || call.callee_name == "mark_safe"  // Python Django
                || call.callee_name == "HtmlString"  // C#
                || call.callee_name == "Markup"  // Python Jinja2
            {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: call.line,
                    column: call.column,
                    pattern_id: "SEC-XSS-001".to_string(),
                    confidence: 0.80,
                    cwe_ids: SmallVec::from_buf([79, 0]),
                    owasp: Some("A03:2021".to_string()),
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Security,
                    matched_text: format!("{} — potential XSS", call.callee_name),
                });
            }
        }

        // Detect hardcoded secrets in string literals
        for lit in &ctx.parse_result.string_literals {
            let lower = lit.value.to_lowercase();
            if (lower.contains("password") || lower.contains("secret") || lower.contains("api_key")
                || lower.contains("apikey") || lower.contains("token"))
                && lit.value.len() > 8
            {
                matches.push(PatternMatch {
                    file: ctx.file.to_string(),
                    line: lit.line,
                    column: lit.column,
                    pattern_id: "SEC-SECRET-001".to_string(),
                    confidence: 0.70,
                    cwe_ids: SmallVec::from_buf([798, 0]),
                    owasp: Some("A07:2021".to_string()),
                    detection_method: DetectionMethod::AstVisitor,
                    category: PatternCategory::Security,
                    matched_text: "potential hardcoded secret".to_string(),
                });
            }
        }

        matches
    }
}

//! Inline suppression system — `drift-ignore` comments.

use std::collections::HashMap;

/// Checks whether violations are suppressed via inline `// drift-ignore` comments.
pub struct SuppressionChecker;

impl SuppressionChecker {
    pub fn new() -> Self {
        Self
    }

    /// Check if a violation at the given file:line is suppressed.
    ///
    /// Supports:
    /// - `// drift-ignore` — suppress all rules on the next line
    /// - `// drift-ignore security/sql-injection` — suppress specific rule
    /// - `// drift-ignore security/sql-injection, naming/camelCase` — suppress multiple rules
    pub fn is_suppressed(
        &self,
        file: &str,
        line: u32,
        rule_id: Option<&str>,
        source_lines: &HashMap<String, Vec<String>>,
    ) -> bool {
        let lines = match source_lines.get(file) {
            Some(l) => l,
            None => return false,
        };

        if line == 0 {
            return false;
        }
        let idx = (line - 1) as usize; // 0-indexed

        // Check the current line for inline suppressions (e.g. `# noqa`)
        if idx < lines.len() && self.line_suppresses(&lines[idx], rule_id) {
            return true;
        }

        // Check the line immediately above for next-line directives
        // (e.g. `drift-ignore`, `eslint-disable-next-line`, `@SuppressWarnings`)
        if idx > 0 && (idx - 1) < lines.len() && self.line_suppresses(&lines[idx - 1], rule_id) {
            return true;
        }

        false
    }

    /// Parse a line for any suppression directive.
    ///
    /// Supports:
    /// - `// drift-ignore` / `// drift-ignore rule1, rule2`
    /// - `# noqa` / `# noqa: rule1, rule2` (Python/flake8)
    /// - `// eslint-disable-next-line` / `// eslint-disable-next-line rule1, rule2` (JS/TS)
    /// - `@SuppressWarnings("rule")` (Java/Kotlin)
    fn line_suppresses(&self, line: &str, rule_id: Option<&str>) -> bool {
        let trimmed = line.trim();

        // Check drift-ignore
        if let Some(result) = self.check_drift_ignore(trimmed, rule_id) {
            return result;
        }

        // Check # noqa (Python/flake8)
        if let Some(result) = self.check_noqa(trimmed, rule_id) {
            return result;
        }

        // Check eslint-disable-next-line (JS/TS)
        if let Some(result) = self.check_eslint_disable(trimmed, rule_id) {
            return result;
        }

        // Check @SuppressWarnings (Java/Kotlin)
        if let Some(result) = self.check_suppress_warnings(trimmed, rule_id) {
            return result;
        }

        false
    }

    /// Check for `drift-ignore` directive.
    fn check_drift_ignore(&self, trimmed: &str, rule_id: Option<&str>) -> Option<bool> {
        let marker = "drift-ignore";
        let pos = trimmed.find(marker)?;

        let before = &trimmed[..pos];
        let is_comment = before.contains("//")
            || before.contains('#')
            || before.contains("--")
            || before.contains("/*");
        if !is_comment {
            return None;
        }

        let after = trimmed[pos + marker.len()..].trim();
        if after.is_empty() || after.starts_with("--") {
            return Some(true);
        }

        Some(match rule_id {
            None => true,
            Some(rid) => after.split(',').map(|s| s.trim()).any(|r| r == rid),
        })
    }

    /// Check for `# noqa` directive (Python/flake8).
    fn check_noqa(&self, trimmed: &str, rule_id: Option<&str>) -> Option<bool> {
        let pos = trimmed.find("# noqa")?;
        let after = trimmed[pos + 6..].trim();

        // `# noqa` alone suppresses everything
        if after.is_empty() {
            return Some(true);
        }

        // `# noqa: E501, W503` — check specific rules
        if let Some(rules_str) = after.strip_prefix(':') {
            return Some(match rule_id {
                None => true,
                Some(rid) => rules_str.split(',').map(|s| s.trim()).any(|r| r == rid),
            });
        }

        Some(true)
    }

    /// Check for `// eslint-disable-next-line` directive (JS/TS).
    fn check_eslint_disable(&self, trimmed: &str, rule_id: Option<&str>) -> Option<bool> {
        let marker = "eslint-disable-next-line";
        let pos = trimmed.find(marker)?;

        let before = &trimmed[..pos];
        if !before.contains("//") && !before.contains("/*") {
            return None;
        }

        let after = trimmed[pos + marker.len()..].trim();
        if after.is_empty() {
            return Some(true);
        }

        Some(match rule_id {
            None => true,
            Some(rid) => after.split(',').map(|s| s.trim()).any(|r| r == rid),
        })
    }

    /// Check for `@SuppressWarnings` annotation (Java/Kotlin).
    fn check_suppress_warnings(&self, trimmed: &str, rule_id: Option<&str>) -> Option<bool> {
        let marker = "@SuppressWarnings";
        let pos = trimmed.find(marker)?;

        let after = trimmed[pos + marker.len()..].trim();

        // @SuppressWarnings("all") or @SuppressWarnings("unchecked")
        if let Some(inner) = after.strip_prefix('(') {
            let inner = inner.trim_end_matches(')');
            let inner = inner.trim_matches('"').trim_matches('{').trim_matches('}');

            if inner == "all" {
                return Some(true);
            }

            return Some(match rule_id {
                None => true,
                Some(rid) => inner.split(',').map(|s| s.trim().trim_matches('"')).any(|r| r == rid),
            });
        }

        Some(true)
    }

    /// Extract all suppression directives from source lines.
    pub fn extract_suppressions(
        &self,
        file: &str,
        lines: &[String],
    ) -> Vec<SuppressionDirective> {
        let mut directives = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if let Some(directive) = self.parse_directive(file, i as u32 + 1, line) {
                directives.push(directive);
            }
        }
        directives
    }

    fn parse_directive(
        &self,
        file: &str,
        line_num: u32,
        line: &str,
    ) -> Option<SuppressionDirective> {
        let trimmed = line.trim();
        let marker = "drift-ignore";
        let pos = trimmed.find(marker)?;

        let before = &trimmed[..pos];
        let is_comment = before.contains("//")
            || before.contains('#')
            || before.contains("--")
            || before.contains("/*");
        if !is_comment {
            return None;
        }

        let after = trimmed[pos + marker.len()..].trim();
        let rule_ids = if after.is_empty() {
            Vec::new()
        } else {
            after.split(',').map(|s| s.trim().to_string()).collect()
        };

        Some(SuppressionDirective {
            file: file.to_string(),
            line: line_num,
            applies_to_line: line_num + 1,
            rule_ids,
        })
    }
}

impl Default for SuppressionChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// A parsed suppression directive.
#[derive(Debug, Clone)]
pub struct SuppressionDirective {
    pub file: String,
    pub line: u32,
    pub applies_to_line: u32,
    pub rule_ids: Vec<String>,
}

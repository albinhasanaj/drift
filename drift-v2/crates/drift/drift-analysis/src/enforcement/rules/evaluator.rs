//! Rules evaluator — maps detected patterns + outliers to actionable violations.

use std::collections::HashMap;

use super::quick_fixes::QuickFixGenerator;
use super::suppression::SuppressionChecker;
use super::types::*;

/// The rules evaluator maps patterns and outliers to violations with severity and quick fixes.
pub struct RulesEvaluator {
    fix_generator: QuickFixGenerator,
    suppression_checker: SuppressionChecker,
    /// FP rates per detector/pattern_id (0.0-1.0). If > 0.20, severity is downgraded.
    fp_rates: HashMap<String, f64>,
}

impl RulesEvaluator {
    pub fn new() -> Self {
        Self {
            fix_generator: QuickFixGenerator::new(),
            suppression_checker: SuppressionChecker::new(),
            fp_rates: HashMap::new(),
        }
    }

    /// Set FP rates per pattern_id for severity adjustment.
    pub fn with_fp_rates(mut self, fp_rates: HashMap<String, f64>) -> Self {
        self.fp_rates = fp_rates;
        self
    }

    /// Evaluate all patterns and produce violations.
    pub fn evaluate(&self, input: &RulesInput) -> Vec<Violation> {
        let mut violations = Vec::new();

        for pattern in &input.patterns {
            // Map outliers to violations (deviations from the pattern)
            for outlier in &pattern.outliers {
                let severity = self.assign_severity(pattern, outlier);
                let rule_id = format!("{}/{}", pattern.category, pattern.pattern_id);
                let id = format!("{}-{}-{}", rule_id, outlier.file, outlier.line);

                let quick_fix = self.fix_generator.suggest(pattern, outlier);

                let suppressed = self.suppression_checker.is_suppressed(
                    &outlier.file,
                    outlier.line,
                    Some(&rule_id),
                    &input.source_lines,
                );

                // Downgrade severity if FP rate > 20% for this pattern
                let severity = if let Some(&fp_rate) = self.fp_rates.get(&pattern.pattern_id) {
                    if fp_rate > 0.20 {
                        Self::downgrade_severity(severity)
                    } else {
                        severity
                    }
                } else {
                    severity
                };

                // Determine is_new from baseline
                let violation_key = format!("{}:{}:{}", outlier.file, outlier.line, rule_id);
                let is_new = !input.baseline_violation_ids.is_empty()
                    && !input.baseline_violation_ids.contains(&violation_key);

                violations.push(Violation {
                    id,
                    file: outlier.file.clone(),
                    line: outlier.line,
                    column: outlier.column,
                    end_line: outlier.end_line,
                    end_column: outlier.end_column,
                    severity,
                    pattern_id: pattern.pattern_id.clone(),
                    rule_id,
                    message: outlier.message.clone(),
                    quick_fix,
                    cwe_id: pattern.cwe_ids.first().copied(),
                    owasp_category: pattern.owasp_categories.first().cloned(),
                    suppressed,
                    is_new,
                });
            }
        }

        // Deduplicate: same file+line+rule_id → keep highest severity
        self.deduplicate(&mut violations);
        violations
    }

    /// Assign severity based on pattern category and CWE mapping.
    fn assign_severity(&self, pattern: &PatternInfo, outlier: &OutlierLocation) -> Severity {
        // Security-related patterns with CWE IDs → Error
        if !pattern.cwe_ids.is_empty() {
            return match pattern.cwe_ids[0] {
                // CWE-89 SQL injection, CWE-79 XSS, CWE-78 OS command injection
                89 | 79 | 78 | 22 | 94 | 502 | 611 | 918 | 327 | 798 => Severity::Error,
                _ => Severity::Warning,
            };
        }

        // Category-based severity
        match pattern.category.as_str() {
            "security" | "taint" | "crypto" => Severity::Error,
            "error_handling" | "constraint" | "boundary" => Severity::Warning,
            "naming" | "convention" | "style" => {
                if outlier.deviation_score > 3.0 {
                    Severity::Warning
                } else {
                    Severity::Info
                }
            }
            "documentation" => Severity::Info,
            _ => {
                if outlier.deviation_score > 3.0 {
                    Severity::Warning
                } else {
                    Severity::Info
                }
            }
        }
    }

    /// Deduplicate violations: same file+line from multiple detectors → keep highest severity.
    fn deduplicate(&self, violations: &mut Vec<Violation>) {
        violations.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.severity.cmp(&b.severity))
        });

        let mut seen = std::collections::HashSet::new();
        violations.retain(|v| {
            let key = format!("{}:{}:{}", v.file, v.line, v.rule_id);
            seen.insert(key)
        });
    }
}

impl RulesEvaluator {
    /// Downgrade severity by one level.
    fn downgrade_severity(severity: Severity) -> Severity {
        match severity {
            Severity::Error => Severity::Warning,
            Severity::Warning => Severity::Info,
            Severity::Info => Severity::Hint,
            Severity::Hint => Severity::Hint,
        }
    }
}

impl Default for RulesEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

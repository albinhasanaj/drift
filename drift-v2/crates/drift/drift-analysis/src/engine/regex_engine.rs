//! Regex matching on extracted strings (Phase 3 of the pipeline).
//!
//! Uses `RegexSet` for efficient multi-pattern matching with timeout protection.
//! Detects SQL patterns, URL patterns, secret patterns, env patterns, and log patterns.

use std::time::{Duration, Instant};

use regex::RegexSet;
use smallvec::SmallVec;

use super::string_extraction::ExtractedString;
use super::types::{DetectionMethod, PatternCategory, PatternMatch};

/// A regex-based pattern definition.
#[derive(Debug, Clone)]
pub struct RegexPattern {
    pub id: String,
    pub pattern: String,
    pub category: PatternCategory,
    pub confidence: f32,
    pub cwe_ids: SmallVec<[u32; 2]>,
    pub owasp: Option<String>,
    pub description: String,
}

/// The regex matching engine.
pub struct RegexEngine {
    patterns: Vec<RegexPattern>,
    regex_set: Option<RegexSet>,
    timeout: Duration,
}

impl RegexEngine {
    /// Create a new regex engine with default patterns.
    pub fn new() -> Self {
        let patterns = default_patterns();
        let regex_strs: Vec<&str> = patterns.iter().map(|p| p.pattern.as_str()).collect();
        let regex_set = RegexSet::new(&regex_strs).ok();

        Self {
            patterns,
            regex_set,
            timeout: Duration::from_millis(500),
        }
    }

    /// Create with custom patterns.
    pub fn with_patterns(patterns: Vec<RegexPattern>) -> Self {
        let regex_strs: Vec<&str> = patterns.iter().map(|p| p.pattern.as_str()).collect();
        let regex_set = RegexSet::new(&regex_strs).ok();

        Self {
            patterns,
            regex_set,
            timeout: Duration::from_millis(500),
        }
    }

    /// Set the timeout for regex matching.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Match extracted strings against all patterns.
    /// Returns pattern matches with timeout protection.
    pub fn match_strings(&self, strings: &[ExtractedString]) -> Vec<PatternMatch> {
        let regex_set = match &self.regex_set {
            Some(rs) => rs,
            None => return Vec::new(),
        };

        let start = Instant::now();
        let mut matches = Vec::new();

        for extracted in strings {
            if start.elapsed() > self.timeout {
                tracing::warn!("regex engine timeout after {:?}", self.timeout);
                break;
            }

            let matched_indices: Vec<usize> = regex_set.matches(&extracted.value).into_iter().collect();
            for idx in matched_indices {
                if let Some(pattern) = self.patterns.get(idx) {
                    matches.push(PatternMatch {
                        file: extracted.file.clone(),
                        line: extracted.line,
                        column: extracted.column,
                        pattern_id: pattern.id.clone(),
                        confidence: pattern.confidence,
                        cwe_ids: pattern.cwe_ids.clone(),
                        owasp: pattern.owasp.clone(),
                        detection_method: DetectionMethod::StringRegex,
                        category: pattern.category,
                        matched_text: truncate(&extracted.value, 200),
                    });
                }
            }
        }

        matches
    }

    /// Number of loaded patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

impl Default for RegexEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Default regex patterns for common security and code quality issues.
fn default_patterns() -> Vec<RegexPattern> {
    vec![
        // SQL injection patterns
        RegexPattern {
            id: "sql-injection-concat".to_string(),
            pattern: r#"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+.*\$\{"#.to_string(),
            category: PatternCategory::Security,
            confidence: 0.85,
            cwe_ids: SmallVec::from_buf([89, 0]),
            owasp: Some("A03:2021".to_string()),
            description: "Potential SQL injection via string concatenation".to_string(),
        },
        RegexPattern {
            id: "sql-raw-query".to_string(),
            // Only flag SQL with dynamic content: f-strings, .format(), #{}, %s, or + concat.
            // Static parameterized SQL (e.g., rusqlite ?1, JDBC ?, sqlx $1) is safe.
            pattern: r#"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*(FROM|INTO|SET|WHERE)\s+.*(\{[^}]*\}|#\{|\%s|\bformat\b|\+\s*\w)"#.to_string(),
            category: PatternCategory::Security,
            confidence: 0.75,
            cwe_ids: SmallVec::from_buf([89, 0]),
            owasp: Some("A03:2021".to_string()),
            description: "SQL query with dynamic string interpolation".to_string(),
        },
        // Secret patterns
        RegexPattern {
            id: "hardcoded-secret".to_string(),
            pattern: r#"(?i)(password|secret|api[_-]?key|token|auth)\s*[:=]\s*["'][^"']{8,}"#.to_string(),
            category: PatternCategory::Security,
            confidence: 0.80,
            cwe_ids: SmallVec::from_buf([798, 0]),
            owasp: Some("A07:2021".to_string()),
            description: "Potential hardcoded secret or credential".to_string(),
        },
        // URL patterns
        RegexPattern {
            id: "http-url".to_string(),
            pattern: r#"http://[^\s"'`]+"#.to_string(),
            category: PatternCategory::Security,
            confidence: 0.50,
            cwe_ids: SmallVec::from_buf([319, 0]),
            owasp: Some("A02:2021".to_string()),
            description: "HTTP URL (non-HTTPS)".to_string(),
        },
        // Environment variable patterns
        RegexPattern {
            id: "env-access".to_string(),
            pattern: r#"(?i)(process\.env|os\.environ|env::var|getenv)\s*[\[\(]"#.to_string(),
            category: PatternCategory::Config,
            confidence: 0.70,
            cwe_ids: SmallVec::new(),
            owasp: None,
            description: "Environment variable access".to_string(),
        },
        // Logging patterns
        RegexPattern {
            id: "console-log".to_string(),
            pattern: r#"console\.(log|warn|error|debug|info)\s*\("#.to_string(),
            category: PatternCategory::Logging,
            confidence: 0.90,
            cwe_ids: SmallVec::new(),
            owasp: None,
            description: "Console logging statement".to_string(),
        },
        // TODO/FIXME patterns
        RegexPattern {
            id: "todo-comment".to_string(),
            pattern: r#"(?i)(TODO|FIXME|HACK|XXX|BUG)\s*:"#.to_string(),
            category: PatternCategory::Documentation,
            confidence: 0.95,
            cwe_ids: SmallVec::new(),
            owasp: None,
            description: "TODO/FIXME comment marker".to_string(),
        },
        // Eval patterns
        RegexPattern {
            id: "eval-usage".to_string(),
            pattern: r#"(?i)\beval\s*\("#.to_string(),
            category: PatternCategory::Security,
            confidence: 0.90,
            cwe_ids: SmallVec::from_buf([95, 0]),
            owasp: Some("A03:2021".to_string()),
            description: "Use of eval() — potential code injection".to_string(),
        },
    ]
}

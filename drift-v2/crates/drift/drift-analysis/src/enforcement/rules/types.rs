//! Core types for the rules engine.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity levels for violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
    Hint,
}

impl Severity {
    /// Penalty points for gate scoring (preserved from v1).
    pub fn penalty(&self) -> u32 {
        match self {
            Self::Error => 10,
            Self::Warning => 3,
            Self::Info => 1,
            Self::Hint => 0,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error => write!(f, "error"),
            Self::Warning => write!(f, "warning"),
            Self::Info => write!(f, "info"),
            Self::Hint => write!(f, "hint"),
        }
    }
}

/// A quick-fix suggestion attached to a violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickFix {
    pub strategy: QuickFixStrategy,
    pub description: String,
    /// The replacement text, if applicable.
    pub replacement: Option<String>,
}

/// The 8 quick-fix strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuickFixStrategy {
    AddImport,
    Rename,
    ExtractFunction,
    WrapInTryCatch,
    AddTypeAnnotation,
    AddTest,
    AddDocumentation,
    UseParameterizedQuery,
}

impl fmt::Display for QuickFixStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddImport => write!(f, "add_import"),
            Self::Rename => write!(f, "rename"),
            Self::ExtractFunction => write!(f, "extract_function"),
            Self::WrapInTryCatch => write!(f, "wrap_in_try_catch"),
            Self::AddTypeAnnotation => write!(f, "add_type_annotation"),
            Self::AddTest => write!(f, "add_test"),
            Self::AddDocumentation => write!(f, "add_documentation"),
            Self::UseParameterizedQuery => write!(f, "use_parameterized_query"),
        }
    }
}

/// A single violation produced by the rules engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Unique ID: "{rule_id}-{file}-{line}"
    pub id: String,
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    pub severity: Severity,
    pub pattern_id: String,
    pub rule_id: String,
    pub message: String,
    pub quick_fix: Option<QuickFix>,
    /// CWE ID if applicable.
    pub cwe_id: Option<u32>,
    /// OWASP category if applicable.
    pub owasp_category: Option<String>,
    /// Whether this violation is suppressed via drift-ignore.
    pub suppressed: bool,
    /// Whether this violation was introduced by the current change.
    pub is_new: bool,
}

/// Input data for the rules evaluator.
#[derive(Debug, Clone, Default)]
pub struct RulesInput {
    /// Detected patterns with their locations and outliers.
    pub patterns: Vec<PatternInfo>,
    /// Source file contents for suppression checking.
    pub source_lines: std::collections::HashMap<String, Vec<String>>,
    /// Baseline violation keys (format: "file:line:rule_id") for is_new detection.
    pub baseline_violation_ids: std::collections::HashSet<String>,
}

/// Information about a detected pattern for rule evaluation.
#[derive(Debug, Clone)]
pub struct PatternInfo {
    pub pattern_id: String,
    pub category: String,
    pub confidence: f64,
    pub locations: Vec<PatternLocation>,
    pub outliers: Vec<OutlierLocation>,
    /// CWE IDs associated with this pattern.
    pub cwe_ids: Vec<u32>,
    /// OWASP categories associated with this pattern.
    pub owasp_categories: Vec<String>,
}

/// A location where a pattern was detected.
#[derive(Debug, Clone)]
pub struct PatternLocation {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
}

/// A location where an outlier (deviation from pattern) was detected.
#[derive(Debug, Clone, Default)]
pub struct OutlierLocation {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    /// End line of the outlier span (if known).
    pub end_line: Option<u32>,
    /// End column of the outlier span (if known).
    pub end_column: Option<u32>,
    pub deviation_score: f64,
    pub message: String,
}

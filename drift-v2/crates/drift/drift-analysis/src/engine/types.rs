//! Core types for the analysis engine.

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::scanner::language_detect::Language;

/// Result of analyzing a single file through all 4 phases.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub file: String,
    pub language: Language,
    pub matches: Vec<PatternMatch>,
    pub strings_extracted: usize,
    pub regex_matches: usize,
    pub resolution_entries: usize,
    pub analysis_time_us: u64,
    pub phase_times_us: [u64; 4],
}

/// A single pattern detection result — the universal output type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub pattern_id: String,
    pub confidence: f32,
    pub cwe_ids: SmallVec<[u32; 2]>,
    pub owasp: Option<String>,
    pub detection_method: DetectionMethod,
    pub category: PatternCategory,
    pub matched_text: String,
}

/// How the pattern was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionMethod {
    /// AST visitor pattern matching (Phase 1).
    AstVisitor,
    /// String literal regex matching (Phase 2-3).
    StringRegex,
    /// TOML-defined declarative pattern.
    TomlPattern,
    /// Learning-based convention deviation.
    LearningDeviation,
    /// Semantic analysis.
    Semantic,
}

/// The 16 pattern categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derive(Default)]
pub enum PatternCategory {
    Api,
    Auth,
    Components,
    Config,
    Contracts,
    DataAccess,
    Documentation,
    Errors,
    Logging,
    Performance,
    Security,
    #[default]
    Structural,
    Styling,
    Testing,
    Types,
    Accessibility,
}

impl PatternCategory {
    /// All 16 categories.
    pub fn all() -> &'static [PatternCategory] {
        &[
            Self::Api, Self::Auth, Self::Components, Self::Config,
            Self::Contracts, Self::DataAccess, Self::Documentation, Self::Errors,
            Self::Logging, Self::Performance, Self::Security, Self::Structural,
            Self::Styling, Self::Testing, Self::Types, Self::Accessibility,
        ]
    }

    /// Category name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Auth => "auth",
            Self::Components => "components",
            Self::Config => "config",
            Self::Contracts => "contracts",
            Self::DataAccess => "data_access",
            Self::Documentation => "documentation",
            Self::Errors => "errors",
            Self::Logging => "logging",
            Self::Performance => "performance",
            Self::Security => "security",
            Self::Structural => "structural",
            Self::Styling => "styling",
            Self::Testing => "testing",
            Self::Types => "types",
            Self::Accessibility => "accessibility",
        }
    }

    /// Parse from string.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "api" => Some(Self::Api),
            "auth" => Some(Self::Auth),
            "components" => Some(Self::Components),
            "config" => Some(Self::Config),
            "contracts" => Some(Self::Contracts),
            "data_access" => Some(Self::DataAccess),
            "documentation" => Some(Self::Documentation),
            "errors" => Some(Self::Errors),
            "logging" => Some(Self::Logging),
            "performance" => Some(Self::Performance),
            "security" => Some(Self::Security),
            "structural" => Some(Self::Structural),
            "styling" => Some(Self::Styling),
            "testing" => Some(Self::Testing),
            "types" => Some(Self::Types),
            "accessibility" => Some(Self::Accessibility),
            _ => None,
        }
    }
}

impl std::fmt::Display for PatternCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}


/// The 4 phases of per-file analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalysisPhase {
    /// Phase 1: AST pattern detection via single-pass visitor.
    AstDetection,
    /// Phase 2: String literal extraction.
    StringExtraction,
    /// Phase 3: Regex matching on extracted strings.
    RegexMatching,
    /// Phase 4: Resolution index building.
    ResolutionBuilding,
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self {
            file: String::new(),
            language: Language::TypeScript,
            matches: Vec::new(),
            strings_extracted: 0,
            regex_matches: 0,
            resolution_entries: 0,
            analysis_time_us: 0,
            phase_times_us: [0; 4],
        }
    }
}

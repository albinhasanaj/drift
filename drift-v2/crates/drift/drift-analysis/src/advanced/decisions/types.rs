//! Decision mining types — decisions, categories, ADR records, temporal correlations.

use serde::{Deserialize, Serialize};

/// 12 decision categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionCategory {
    Architecture,
    Technology,
    Pattern,
    Convention,
    Security,
    Performance,
    Testing,
    Deployment,
    DataModel,
    ApiDesign,
    ErrorHandling,
    Documentation,
}

impl DecisionCategory {
    pub const ALL: &'static [DecisionCategory] = &[
        Self::Architecture, Self::Technology, Self::Pattern, Self::Convention,
        Self::Security, Self::Performance, Self::Testing, Self::Deployment,
        Self::DataModel, Self::ApiDesign, Self::ErrorHandling, Self::Documentation,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Self::Architecture => "architecture",
            Self::Technology => "technology",
            Self::Pattern => "pattern",
            Self::Convention => "convention",
            Self::Security => "security",
            Self::Performance => "performance",
            Self::Testing => "testing",
            Self::Deployment => "deployment",
            Self::DataModel => "data_model",
            Self::ApiDesign => "api_design",
            Self::ErrorHandling => "error_handling",
            Self::Documentation => "documentation",
        }
    }
}

impl std::fmt::Display for DecisionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A mined decision from the codebase history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub id: String,
    pub category: DecisionCategory,
    pub description: String,
    pub commit_sha: Option<String>,
    pub timestamp: i64,
    pub confidence: f64,
    #[serde(default)]
    pub low_confidence: bool,
    pub related_patterns: Vec<String>,
    pub author: Option<String>,
    pub files_changed: Vec<String>,
}

/// ADR status lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdrStatus {
    Proposed,
    Accepted,
    Deprecated,
    Superseded,
}

impl AdrStatus {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "proposed" => Some(Self::Proposed),
            "accepted" | "approved" => Some(Self::Accepted),
            "deprecated" => Some(Self::Deprecated),
            "superseded" | "superseded by" => Some(Self::Superseded),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Accepted => "accepted",
            Self::Deprecated => "deprecated",
            Self::Superseded => "superseded",
        }
    }
}

/// An Architecture Decision Record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdrRecord {
    pub title: String,
    pub status: AdrStatus,
    pub context: String,
    pub decision: String,
    pub consequences: String,
    pub file_path: String,
}

/// Temporal correlation between a decision and a pattern change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalCorrelation {
    pub decision_id: String,
    pub pattern_change_id: String,
    /// Time delta in seconds (positive = pattern change after decision).
    pub time_delta: i64,
    /// Correlation strength (0.0-1.0).
    pub correlation_strength: f64,
}

/// A commit summary for decision mining.
#[derive(Debug, Clone)]
pub struct CommitSummary {
    pub sha: String,
    pub message: String,
    pub author: String,
    pub timestamp: i64,
    pub files_changed: Vec<String>,
    pub insertions: u32,
    pub deletions: u32,
}

/// Result of decision mining.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecisionMiningResult {
    pub decisions: Vec<Decision>,
    pub adr_records: Vec<AdrRecord>,
    pub correlations: Vec<TemporalCorrelation>,
    pub commits_analyzed: usize,
    pub categories_found: Vec<DecisionCategory>,
}

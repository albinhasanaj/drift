use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// The 18 intent types across 3 categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    // Domain-agnostic (7)
    Create,
    Investigate,
    Decide,
    Recall,
    Learn,
    Summarize,
    Compare,
    // Code-specific (8)
    AddFeature,
    FixBug,
    Refactor,
    SecurityAudit,
    UnderstandCode,
    AddTest,
    ReviewCode,
    DeployMigrate,
    // Universal (3)
    SpawnAgent,
    ExecuteWorkflow,
    TrackProgress,
}

impl Intent {
    /// Total number of intent types.
    pub const COUNT: usize = 18;

    /// All variants for iteration.
    pub const ALL: [Intent; 18] = [
        Self::Create,
        Self::Investigate,
        Self::Decide,
        Self::Recall,
        Self::Learn,
        Self::Summarize,
        Self::Compare,
        Self::AddFeature,
        Self::FixBug,
        Self::Refactor,
        Self::SecurityAudit,
        Self::UnderstandCode,
        Self::AddTest,
        Self::ReviewCode,
        Self::DeployMigrate,
        Self::SpawnAgent,
        Self::ExecuteWorkflow,
        Self::TrackProgress,
    ];

    /// Category label.
    pub fn category(&self) -> &'static str {
        match self {
            Self::Create
            | Self::Investigate
            | Self::Decide
            | Self::Recall
            | Self::Learn
            | Self::Summarize
            | Self::Compare => "domain_agnostic",
            Self::AddFeature
            | Self::FixBug
            | Self::Refactor
            | Self::SecurityAudit
            | Self::UnderstandCode
            | Self::AddTest
            | Self::ReviewCode
            | Self::DeployMigrate => "code_specific",
            Self::SpawnAgent | Self::ExecuteWorkflow | Self::TrackProgress => "universal",
        }
    }
}

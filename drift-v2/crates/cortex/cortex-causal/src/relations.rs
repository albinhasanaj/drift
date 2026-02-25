//! 8 causal relation types with semantics, strength scoring, and evidence requirements.
//! Extended with cross-agent relation support for multi-agent memory.

use cortex_core::models::cross_agent::CrossAgentRelation;
use serde::{Deserialize, Serialize};

/// The 8 causal relation types, plus cross-agent relations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalRelation {
    /// X directly caused Y.
    Caused,
    /// X made Y possible (necessary but not sufficient).
    Enabled,
    /// X prevented Y from happening.
    Prevented,
    /// X and Y are in conflict.
    Contradicts,
    /// X replaces Y (newer version).
    Supersedes,
    /// X provides evidence for Y.
    Supports,
    /// Y was derived from X (transformation).
    DerivedFrom,
    /// X triggered Y (event-based).
    TriggeredBy,
    /// Cross-agent relationship (multi-agent memory).
    CrossAgent(CrossAgentRelation),
}

impl CausalRelation {
    /// Total number of base relation types (excluding CrossAgent).
    pub const COUNT: usize = 8;

    /// All base variants for iteration (excluding CrossAgent).
    pub const ALL: [CausalRelation; 8] = [
        Self::Caused,
        Self::Enabled,
        Self::Prevented,
        Self::Contradicts,
        Self::Supersedes,
        Self::Supports,
        Self::DerivedFrom,
        Self::TriggeredBy,
    ];

    /// Minimum evidence items required to establish this relation.
    pub fn min_evidence(&self) -> usize {
        match self {
            Self::Caused | Self::Prevented => 2,
            Self::Contradicts | Self::Supersedes => 1,
            Self::Enabled | Self::Supports | Self::DerivedFrom | Self::TriggeredBy => 1,
            Self::CrossAgent(_) => 1,
        }
    }

    /// Default minimum strength threshold for this relation type.
    pub fn min_strength(&self) -> f64 {
        match self {
            Self::Caused => 0.5,
            Self::Enabled => 0.3,
            Self::Prevented => 0.4,
            Self::Contradicts => 0.4,
            Self::Supersedes => 0.6,
            Self::Supports => 0.2,
            Self::DerivedFrom => 0.3,
            Self::TriggeredBy => 0.4,
            Self::CrossAgent(_) => 0.3,
        }
    }

    /// Whether this relation implies a strong directional dependency.
    pub fn is_strong_dependency(&self) -> bool {
        matches!(self, Self::Caused | Self::Supersedes | Self::DerivedFrom)
    }

    /// Parse from string (matching the serde rename).
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "caused" => Some(Self::Caused),
            "enabled" => Some(Self::Enabled),
            "prevented" => Some(Self::Prevented),
            "contradicts" => Some(Self::Contradicts),
            "supersedes" => Some(Self::Supersedes),
            "supports" => Some(Self::Supports),
            "derived_from" => Some(Self::DerivedFrom),
            "triggered_by" => Some(Self::TriggeredBy),
            "cross_agent" => Some(Self::CrossAgent(CrossAgentRelation::InformedBy)),
            _ => None,
        }
    }

    /// String name for this relation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Caused => "caused",
            Self::Enabled => "enabled",
            Self::Prevented => "prevented",
            Self::Contradicts => "contradicts",
            Self::Supersedes => "supersedes",
            Self::Supports => "supports",
            Self::DerivedFrom => "derived_from",
            Self::TriggeredBy => "triggered_by",
            Self::CrossAgent(_) => "cross_agent",
        }
    }
}

impl std::fmt::Display for CausalRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

//! SpecCorrection → CausalEngine edge creation.
//! 7 CorrectionRootCause variants, each maps to a specific causal relation type.

use cortex_causal::CausalRelation;
use serde::{Deserialize, Serialize};

use super::attribution::DataSourceAttribution;

/// Which spec section was corrected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpecSection {
    Overview,
    PublicApi,
    DataModel,
    DataFlow,
    BusinessLogic,
    Dependencies,
    Conventions,
    Security,
    Constraints,
    TestRequirements,
    MigrationNotes,
}

impl SpecSection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::PublicApi => "public_api",
            Self::DataModel => "data_model",
            Self::DataFlow => "data_flow",
            Self::BusinessLogic => "business_logic",
            Self::Dependencies => "dependencies",
            Self::Conventions => "conventions",
            Self::Security => "security",
            Self::Constraints => "constraints",
            Self::TestRequirements => "test_requirements",
            Self::MigrationNotes => "migration_notes",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "overview" => Some(Self::Overview),
            "public_api" => Some(Self::PublicApi),
            "data_model" => Some(Self::DataModel),
            "data_flow" => Some(Self::DataFlow),
            "business_logic" => Some(Self::BusinessLogic),
            "dependencies" => Some(Self::Dependencies),
            "conventions" => Some(Self::Conventions),
            "security" => Some(Self::Security),
            "constraints" => Some(Self::Constraints),
            "test_requirements" => Some(Self::TestRequirements),
            "migration_notes" => Some(Self::MigrationNotes),
            _ => None,
        }
    }
}

/// A correction to a specification section, with causal metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecCorrection {
    /// The correction itself (stored as migration_corrections in drift.db).
    pub correction_id: String,
    /// The module being corrected.
    pub module_id: String,
    /// Which spec section was corrected.
    pub section: SpecSection,
    /// What structural data led to the incorrect generation.
    pub root_cause: CorrectionRootCause,
    /// Which upstream modules' data contributed to the error.
    pub upstream_modules: Vec<String>,
    /// Which Drift subsystems produced the data that was wrong.
    pub data_sources: Vec<DataSourceAttribution>,
}

/// 7 root cause variants for spec corrections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrectionRootCause {
    /// The call graph missed a relationship.
    MissingCallEdge { from: String, to: String },
    /// The boundary detection missed a data access pattern.
    MissingBoundary { table: String, orm: String },
    /// The convention detection was wrong about a pattern.
    WrongConvention { expected: String, actual: String },
    /// The LLM synthesis hallucinated business logic.
    LlmHallucination { claim: String, reality: String },
    /// The data flow analysis missed a transformation step.
    MissingDataFlow { source: String, sink: String },
    /// The taint analysis missed a sensitive field.
    MissingSensitiveField { table: String, field: String },
    /// Human domain knowledge not capturable by static analysis.
    DomainKnowledge { description: String },
}

impl CorrectionRootCause {
    /// Map this root cause to the appropriate CausalRelation type.
    pub fn to_causal_relation(&self) -> CausalRelation {
        match self {
            Self::MissingCallEdge { .. } => CausalRelation::Caused,
            Self::MissingBoundary { .. } => CausalRelation::Caused,
            Self::WrongConvention { .. } => CausalRelation::Contradicts,
            Self::LlmHallucination { .. } => CausalRelation::Contradicts,
            Self::MissingDataFlow { .. } => CausalRelation::Caused,
            Self::MissingSensitiveField { .. } => CausalRelation::Caused,
            Self::DomainKnowledge { .. } => CausalRelation::Supports,
        }
    }

    /// Get the name of this root cause variant.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::MissingCallEdge { .. } => "MissingCallEdge",
            Self::MissingBoundary { .. } => "MissingBoundary",
            Self::WrongConvention { .. } => "WrongConvention",
            Self::LlmHallucination { .. } => "LlmHallucination",
            Self::MissingDataFlow { .. } => "MissingDataFlow",
            Self::MissingSensitiveField { .. } => "MissingSensitiveField",
            Self::DomainKnowledge { .. } => "DomainKnowledge",
        }
    }

    /// Get metadata for the causal edge.
    pub fn metadata(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::json!({}))
    }
}

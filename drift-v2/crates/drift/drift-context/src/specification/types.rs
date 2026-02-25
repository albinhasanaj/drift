//! Specification engine types — SpecSection, LogicalModule, SpecOutput.

use serde::{Deserialize, Serialize};

/// 11 specification sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    /// All 11 sections in order.
    pub const ALL: &'static [SpecSection] = &[
        Self::Overview, Self::PublicApi, Self::DataModel, Self::DataFlow,
        Self::BusinessLogic, Self::Dependencies, Self::Conventions,
        Self::Security, Self::Constraints, Self::TestRequirements,
        Self::MigrationNotes,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::PublicApi => "Public API",
            Self::DataModel => "Data Model",
            Self::DataFlow => "Data Flow",
            Self::BusinessLogic => "Business Logic",
            Self::Dependencies => "Dependencies",
            Self::Conventions => "Conventions",
            Self::Security => "Security",
            Self::Constraints => "Constraints",
            Self::TestRequirements => "Test Requirements",
            Self::MigrationNotes => "Migration Notes",
        }
    }

    /// Weight key for this section.
    pub fn weight_key(&self) -> &'static str {
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

    /// Whether this is a narrative section (vs. structured data).
    pub fn is_narrative(&self) -> bool {
        matches!(self, Self::Overview | Self::BusinessLogic | Self::MigrationNotes)
    }
}

impl std::fmt::Display for SpecSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A public function in a module.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct PublicFunction {
    pub name: String,
    pub signature: String,
    pub callers: Vec<String>,
    pub description: Option<String>,
}

/// A data dependency (table/model).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct DataDependency {
    pub table_name: String,
    pub orm_framework: String,
    pub operations: Vec<String>,
    pub sensitive_fields: Vec<String>,
}

/// A logical module for spec generation.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct LogicalModule {
    pub name: String,
    pub description: String,
    pub public_functions: Vec<PublicFunction>,
    pub data_dependencies: Vec<DataDependency>,
    pub conventions: Vec<String>,
    pub constraints: Vec<String>,
    pub security_findings: Vec<String>,
    pub dependencies: Vec<String>,
    pub test_coverage: f64,
    pub error_handling_patterns: Vec<String>,
}

/// Complete specification output.
#[derive(Debug, Clone)]
pub struct SpecOutput {
    pub module_name: String,
    pub sections: Vec<(SpecSection, String)>,
    pub total_token_count: usize,
}

impl SpecOutput {
    /// Check that all 11 sections are present.
    pub fn has_all_sections(&self) -> bool {
        SpecSection::ALL.iter().all(|expected| {
            self.sections.iter().any(|(s, _)| s == expected)
        })
    }

    /// Get content for a specific section.
    pub fn get_section(&self, section: SpecSection) -> Option<&str> {
        self.sections.iter()
            .find(|(s, _)| *s == section)
            .map(|(_, content)| content.as_str())
    }
}

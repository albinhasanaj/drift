//! Decomposition types — D1 compliant (no Cortex imports).

use serde::{Deserialize, Serialize};

/// A decomposition decision (prior from external source or computed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompositionDecision {
    /// The boundary adjustment to apply.
    pub adjustment: BoundaryAdjustment,
    /// Confidence in this decision (0.0-1.0).
    pub confidence: f64,
    /// DNA similarity score between source and target (0.0-1.0).
    pub dna_similarity: f64,
    /// Human-readable narrative explaining the decision.
    pub narrative: String,
}

/// Types of boundary adjustments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BoundaryAdjustment {
    /// Split a module into multiple modules.
    Split { module: String, into: Vec<String> },
    /// Merge multiple modules into one.
    Merge { modules: Vec<String>, into: String },
    /// Reclassify a module into a different category.
    Reclassify { module: String, new_category: String },
}

/// Record of a prior that was applied during decomposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedPrior {
    /// DNA hash of the source project that provided this prior.
    pub source_dna_hash: String,
    /// The adjustment that was applied.
    pub adjustment: BoundaryAdjustment,
    /// Weight at which the prior was applied (confidence × dna_similarity).
    pub applied_weight: f64,
    /// Human-readable narrative.
    pub narrative: String,
}

/// A logical module produced by decomposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalModule {
    /// Module name (derived from directory or cluster).
    pub name: String,
    /// Files belonging to this module.
    pub files: Vec<String>,
    /// Public interface: functions callable from outside this module.
    pub public_interface: Vec<String>,
    /// Internal functions (not called from outside).
    pub internal_functions: Vec<String>,
    /// Data dependencies (tables, APIs, etc.).
    pub data_dependencies: Vec<DataDependency>,
    /// Convention profile for this module.
    pub convention_profile: ConventionProfile,
    /// Cohesion score (0.0-1.0). Higher = more cohesive.
    pub cohesion: f64,
    /// Coupling score (0.0-1.0). Lower = less coupled.
    pub coupling: f64,
    /// Estimated complexity (total lines across files).
    pub estimated_complexity: u64,
    /// Applied priors (if any).
    pub applied_priors: Vec<AppliedPrior>,
}

/// A data dependency of a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataDependency {
    /// Name of the data source (table, API, etc.).
    pub name: String,
    /// Kind of dependency.
    pub kind: DataDependencyKind,
    /// Operations performed (Read, Write, ReadWrite).
    pub operations: Vec<String>,
    /// Sensitive fields accessed.
    pub sensitive_fields: Vec<String>,
}

/// Kind of data dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataDependencyKind {
    Database,
    Api,
    FileSystem,
    Cache,
    MessageQueue,
}

/// Convention profile for a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConventionProfile {
    /// Naming convention (camelCase, snake_case, PascalCase).
    pub naming_convention: String,
    /// Error handling style (try-catch, Result, error codes).
    pub error_handling: String,
    /// Logging approach (structured, console, framework).
    pub logging: String,
}

/// Dependency between two modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleDependency {
    pub from: String,
    pub to: String,
    /// Number of cross-module calls.
    pub call_count: u32,
}

/// Thresholds for prior application.
pub struct DecompositionThresholds;

impl DecompositionThresholds {
    /// Minimum weight for Split priors.
    pub const SPLIT_THRESHOLD: f64 = 0.4;
    /// Minimum weight for Merge priors.
    pub const MERGE_THRESHOLD: f64 = 0.5;
    /// Minimum weight for Reclassify priors.
    pub const RECLASSIFY_THRESHOLD: f64 = 0.3;
}

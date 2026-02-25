//! Constraint system types — invariants, verification results.

use serde::{Deserialize, Serialize};

/// A structural constraint (architectural invariant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    /// Unique constraint identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// The invariant type.
    pub invariant_type: InvariantType,
    /// Target pattern or expression (AST-based, not regex).
    pub target: String,
    /// Optional scope (file glob, module name).
    pub scope: Option<String>,
    /// Whether this constraint was auto-synthesized or manually defined.
    pub source: ConstraintSource,
    /// Whether the constraint is currently enabled.
    pub enabled: bool,
}

/// The 12 invariant types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InvariantType {
    /// A symbol/pattern must exist in the codebase.
    MustExist,
    /// A symbol/pattern must NOT exist.
    MustNotExist,
    /// Symbol A must appear before symbol B (ordering).
    MustPrecede,
    /// Symbol A must appear after symbol B (ordering).
    MustFollow,
    /// Symbols must be in the same module/file.
    MustColocate,
    /// Symbols must be in different modules/files.
    MustSeparate,
    /// Data must flow through a specific path.
    DataFlow,
    /// Names must follow a convention (camelCase, snake_case, etc.).
    NamingConvention,
    /// Dependencies must flow in a specific direction (no cycles, layering).
    DependencyDirection,
    /// Code must respect layer boundaries (e.g., UI cannot import DB).
    LayerBoundary,
    /// Module/file/function must not exceed a size limit.
    SizeLimit,
    /// Cyclomatic complexity must not exceed a threshold.
    ComplexityLimit,
}

impl InvariantType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::MustExist => "must_exist",
            Self::MustNotExist => "must_not_exist",
            Self::MustPrecede => "must_precede",
            Self::MustFollow => "must_follow",
            Self::MustColocate => "must_colocate",
            Self::MustSeparate => "must_separate",
            Self::DataFlow => "data_flow",
            Self::NamingConvention => "naming_convention",
            Self::DependencyDirection => "dependency_direction",
            Self::LayerBoundary => "layer_boundary",
            Self::SizeLimit => "size_limit",
            Self::ComplexityLimit => "complexity_limit",
        }
    }

    pub fn all() -> &'static [InvariantType] {
        &[
            Self::MustExist, Self::MustNotExist, Self::MustPrecede, Self::MustFollow,
            Self::MustColocate, Self::MustSeparate, Self::DataFlow, Self::NamingConvention,
            Self::DependencyDirection, Self::LayerBoundary, Self::SizeLimit, Self::ComplexityLimit,
        ]
    }
}

impl std::fmt::Display for InvariantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// How a constraint was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConstraintSource {
    /// Manually defined by a developer.
    Manual,
    /// Auto-synthesized from code patterns.
    Synthesized,
    /// Frozen from a baseline snapshot.
    Frozen,
}

/// Result of verifying a single constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub constraint_id: String,
    pub passed: bool,
    pub violations: Vec<ConstraintViolation>,
}

/// A single constraint violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintViolation {
    pub file: String,
    pub line: Option<u32>,
    pub message: String,
    pub expected: String,
    pub actual: String,
}

/// A frozen baseline snapshot for regression detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenBaseline {
    pub snapshot_id: String,
    pub constraints: Vec<Constraint>,
    pub timestamp: u64,
}

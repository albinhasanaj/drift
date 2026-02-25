//! GroundingDataSource: the 12 Drift subsystems that can provide grounding evidence.
//!
//! ## Mapping to EvidenceType
//!
//! 11 of 12 data sources have a corresponding `EvidenceType` variant with an
//! evidence collector in `grounding/evidence/collector.rs`. The mapping:
//!
//! | GroundingDataSource | EvidenceType            | Collector? |
//! |---------------------|-------------------------|------------|
//! | Patterns            | PatternConfidence + PatternOccurrence + FalsePositiveRate | Yes |
//! | Conventions         | (subsumed by PatternOccurrence) | Yes (via Patterns) |
//! | Constraints         | ConstraintVerification  | Yes |
//! | Coupling            | CouplingMetric          | Yes |
//! | Dna                 | DnaHealth               | Yes |
//! | TestTopology        | TestCoverage            | Yes |
//! | ErrorHandling       | ErrorHandlingGaps       | Yes |
//! | Decisions           | DecisionEvidence        | Yes |
//! | Boundaries          | BoundaryData            | Yes |
//! | Taint               | TaintAnalysis           | Yes |
//! | CallGraph           | CallGraphCoverage       | Yes |
//! | **Security**        | **(none)**              | **No** |
//!
//! ### Security exclusion rationale (P3-6)
//!
//! `Security` is intentionally excluded from the grounding evidence system.
//! It is used only in the intent resolver (`intents/resolver.rs`) to route
//! `security_audit` and `performance_audit` intents to relevant drift.db
//! tables (`crypto_findings`, `owasp_findings`). Adding a grounding evidence
//! collector for Security would require:
//! - A new `EvidenceType::Security` variant (13th)
//! - A collector that aggregates severity/counts from `crypto_findings` +
//!   `owasp_findings` per file
//! - A meaningful "support score" derivation (unclear — security findings
//!   indicate risk, not memory validity)
//!
//! The cost/benefit does not justify implementation at this time. If product
//! requirements change (e.g., "memories about security should be grounded
//! against actual vulnerability data"), revisit this decision.

use serde::{Deserialize, Serialize};

/// The Drift subsystems that can provide grounding evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GroundingDataSource {
    /// Pattern detection engine.
    Patterns,
    /// Convention detection engine.
    Conventions,
    /// Constraint enforcement engine.
    Constraints,
    /// Coupling analysis engine.
    Coupling,
    /// DNA fingerprinting engine.
    Dna,
    /// Test topology engine.
    TestTopology,
    /// Error handling analysis engine.
    ErrorHandling,
    /// Decision mining engine.
    Decisions,
    /// Boundary detection engine.
    Boundaries,
    /// Taint analysis engine.
    Taint,
    /// Call graph engine.
    CallGraph,
    /// Security analysis engine (intent resolver only — no grounding evidence collector).
    Security,
}

impl GroundingDataSource {
    /// All 12 data sources.
    pub const ALL: [GroundingDataSource; 12] = [
        Self::Patterns,
        Self::Conventions,
        Self::Constraints,
        Self::Coupling,
        Self::Dna,
        Self::TestTopology,
        Self::ErrorHandling,
        Self::Decisions,
        Self::Boundaries,
        Self::Taint,
        Self::CallGraph,
        Self::Security,
    ];

    /// String representation for storage/display.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Patterns => "patterns",
            Self::Conventions => "conventions",
            Self::Constraints => "constraints",
            Self::Coupling => "coupling",
            Self::Dna => "dna",
            Self::TestTopology => "test_topology",
            Self::ErrorHandling => "error_handling",
            Self::Decisions => "decisions",
            Self::Boundaries => "boundaries",
            Self::Taint => "taint",
            Self::CallGraph => "call_graph",
            Self::Security => "security",
        }
    }
}

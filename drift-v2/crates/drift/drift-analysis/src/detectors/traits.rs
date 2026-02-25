//! Detector trait and category/variant enums.

use crate::engine::types::PatternMatch;
use crate::engine::visitor::DetectionContext;

/// Trait that every detector must implement.
pub trait Detector: Send + Sync {
    /// Unique identifier for this detector.
    fn id(&self) -> &str;

    /// The category this detector belongs to.
    fn category(&self) -> DetectorCategory;

    /// The variant of this detector.
    fn variant(&self) -> DetectorVariant;

    /// Run detection on the given context.
    fn detect(&self, ctx: &DetectionContext) -> Vec<PatternMatch>;

    /// Whether this detector is critical (must always run).
    fn is_critical(&self) -> bool {
        false
    }
}

/// The 16 detector categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectorCategory {
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
    Structural,
    Styling,
    Testing,
    Types,
    Accessibility,
}

impl DetectorCategory {
    pub fn all() -> &'static [DetectorCategory] {
        &[
            Self::Api, Self::Auth, Self::Components, Self::Config,
            Self::Contracts, Self::DataAccess, Self::Documentation, Self::Errors,
            Self::Logging, Self::Performance, Self::Security, Self::Structural,
            Self::Styling, Self::Testing, Self::Types, Self::Accessibility,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Api => "api", Self::Auth => "auth", Self::Components => "components",
            Self::Config => "config", Self::Contracts => "contracts",
            Self::DataAccess => "data_access", Self::Documentation => "documentation",
            Self::Errors => "errors", Self::Logging => "logging",
            Self::Performance => "performance", Self::Security => "security",
            Self::Structural => "structural", Self::Styling => "styling",
            Self::Testing => "testing", Self::Types => "types",
            Self::Accessibility => "accessibility",
        }
    }
}

/// Detector variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectorVariant {
    /// Base pattern matching.
    Base,
    /// Two-pass learning detector.
    Learning,
    /// Semantic analysis detector.
    Semantic,
}

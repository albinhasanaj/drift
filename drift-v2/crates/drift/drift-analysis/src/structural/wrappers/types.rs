//! Wrapper detection types.

use serde::{Deserialize, Serialize};

/// A detected wrapper function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wrapper {
    /// Function name.
    pub name: String,
    /// File where defined.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Category of the wrapper.
    pub category: WrapperCategory,
    /// Wrapped primitive(s).
    pub wrapped_primitives: Vec<String>,
    /// Framework the primitive belongs to.
    pub framework: String,
    /// Confidence score (0-1).
    pub confidence: f64,
    /// Whether this is a multi-primitive wrapper.
    pub is_multi_primitive: bool,
    /// Whether this is exported/public.
    pub is_exported: bool,
    /// Number of call sites using this wrapper.
    pub usage_count: u32,
}

/// The 16 wrapper categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WrapperCategory {
    StateManagement,
    DataFetching,
    FormHandling,
    Routing,
    Authentication,
    ErrorBoundary,
    Caching,
    Styling,
    Animation,
    Accessibility,
    Logging,
    ApiClient,
    Middleware,
    Testing,
    Internationalization,
    Other,
}

impl WrapperCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::StateManagement => "state_management",
            Self::DataFetching => "data_fetching",
            Self::FormHandling => "form_handling",
            Self::Routing => "routing",
            Self::Authentication => "authentication",
            Self::ErrorBoundary => "error_boundary",
            Self::Caching => "caching",
            Self::Styling => "styling",
            Self::Animation => "animation",
            Self::Accessibility => "accessibility",
            Self::Logging => "logging",
            Self::ApiClient => "api_client",
            Self::Middleware => "middleware",
            Self::Testing => "testing",
            Self::Internationalization => "internationalization",
            Self::Other => "other",
        }
    }

    pub fn all() -> &'static [WrapperCategory] {
        &[
            Self::StateManagement, Self::DataFetching, Self::FormHandling,
            Self::Routing, Self::Authentication, Self::ErrorBoundary,
            Self::Caching, Self::Styling, Self::Animation, Self::Accessibility,
            Self::Logging, Self::ApiClient, Self::Middleware, Self::Testing,
            Self::Internationalization, Self::Other,
        ]
    }

    /// Whether this is a security-relevant category.
    pub fn is_security(&self) -> bool {
        matches!(self, Self::Authentication | Self::ErrorBoundary)
    }
}

impl std::fmt::Display for WrapperCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Wrapper health metrics for a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperHealth {
    /// Consistency: how uniformly wrappers are used (0-100).
    pub consistency: f64,
    /// Coverage: what fraction of primitive calls go through wrappers (0-100).
    pub coverage: f64,
    /// Abstraction depth: average wrapper nesting depth (lower is better).
    pub abstraction_depth: f64,
    /// Overall health score (0-100).
    pub overall: f64,
}

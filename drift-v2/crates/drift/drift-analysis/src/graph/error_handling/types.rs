//! Error handling analysis types.

use serde::{Deserialize, Serialize};

/// Classification of error types per language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorType {
    /// The error/exception type name.
    pub name: String,
    /// Language this error type belongs to.
    pub language: String,
    /// Whether this is a checked exception (Java) or unchecked.
    pub is_checked: bool,
    /// Parent error type (inheritance).
    pub parent: Option<String>,
}

/// A detected error handler in the code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorHandler {
    /// File containing the handler.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// End line.
    pub end_line: u32,
    /// Function containing this handler.
    pub function: String,
    /// Type of handler.
    pub handler_type: HandlerType,
    /// Error types caught by this handler.
    pub caught_types: Vec<String>,
    /// Whether the handler body is empty (anti-pattern).
    pub is_empty: bool,
    /// Whether the error is re-thrown.
    pub rethrows: bool,
}

/// Types of error handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerType {
    /// try/catch (JS, Java, C#, PHP, Kotlin)
    TryCatch,
    /// try/except (Python)
    TryExcept,
    /// Result pattern matching (Rust)
    ResultMatch,
    /// Error callback (Node.js callback pattern)
    ErrorCallback,
    /// Promise .catch() handler
    PromiseCatch,
    /// React ErrorBoundary
    ErrorBoundary,
    /// Express error middleware
    ExpressMiddleware,
    /// Framework-specific handler
    FrameworkHandler,
    /// Rescue block (Ruby)
    Rescue,
    /// Defer/recover (Go)
    DeferRecover,
}

impl HandlerType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::TryCatch => "try_catch",
            Self::TryExcept => "try_except",
            Self::ResultMatch => "result_match",
            Self::ErrorCallback => "error_callback",
            Self::PromiseCatch => "promise_catch",
            Self::ErrorBoundary => "error_boundary",
            Self::ExpressMiddleware => "express_middleware",
            Self::FrameworkHandler => "framework_handler",
            Self::Rescue => "rescue",
            Self::DeferRecover => "defer_recover",
        }
    }
}

/// An error propagation chain through the call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationChain {
    /// Ordered list of functions in the propagation path.
    pub functions: Vec<PropagationNode>,
    /// The error type being propagated.
    pub error_type: Option<String>,
    /// Whether the chain ends in a handler.
    pub is_handled: bool,
}

/// A node in a propagation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationNode {
    pub file: String,
    pub function: String,
    pub line: u32,
    /// Whether this function handles the error.
    pub handles_error: bool,
    /// Whether this function propagates the error.
    pub propagates_error: bool,
}

/// An unhandled error path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnhandledPath {
    /// Function that throws/returns an error.
    pub source_file: String,
    pub source_function: String,
    pub source_line: u32,
    /// The error type.
    pub error_type: Option<String>,
    /// The propagation chain showing where handling is missing.
    pub chain: PropagationChain,
}

/// An error handling gap (anti-pattern).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorGap {
    /// File containing the gap.
    pub file: String,
    /// Function containing the gap.
    pub function: String,
    /// Line number.
    pub line: u32,
    /// Type of gap.
    pub gap_type: GapType,
    /// The error type involved.
    pub error_type: Option<String>,
    /// Framework context (if applicable).
    pub framework: Option<String>,
    /// CWE mapping.
    pub cwe_id: Option<u32>,
    /// Severity level.
    pub severity: GapSeverity,
    /// Remediation suggestion.
    pub remediation: Option<String>,
}

/// Types of error handling gaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GapType {
    /// Empty catch/except block.
    EmptyCatch,
    /// Error caught but not logged or re-thrown.
    SwallowedError,
    /// Catching generic Exception/Error instead of specific type.
    GenericCatch,
    /// Error thrown but never caught in any caller.
    Unhandled,
    /// Async error without .catch() or try/catch.
    UnhandledAsync,
    /// Missing error middleware in framework.
    MissingMiddleware,
    /// Inconsistent error handling pattern.
    InconsistentPattern,
}

impl GapType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::EmptyCatch => "empty_catch",
            Self::SwallowedError => "swallowed_error",
            Self::GenericCatch => "generic_catch",
            Self::Unhandled => "unhandled",
            Self::UnhandledAsync => "unhandled_async",
            Self::MissingMiddleware => "missing_middleware",
            Self::InconsistentPattern => "inconsistent_pattern",
        }
    }
}

/// Severity of an error handling gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GapSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl GapSeverity {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

impl std::fmt::Display for GapSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Complete result of error handling analysis.
#[derive(Debug, Clone, Default)]
pub struct ErrorHandlingResult {
    pub handlers: Vec<ErrorHandler>,
    pub gaps: Vec<ErrorGap>,
    pub unhandled_paths: Vec<UnhandledPath>,
    pub propagation_chains: Vec<PropagationChain>,
}

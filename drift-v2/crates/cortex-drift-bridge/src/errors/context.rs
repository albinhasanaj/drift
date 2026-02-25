//! ErrorContext: attach file/line/span metadata to any BridgeError.

use std::fmt;

/// Rich error context for debugging multi-step operations.
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// Source file where the error originated.
    pub file: &'static str,
    /// Line number where the error originated.
    pub line: u32,
    /// Tracing span name (if inside an instrumented function).
    pub span: Option<String>,
    /// Operation that failed.
    pub operation: String,
    /// Additional key-value metadata.
    pub metadata: Vec<(String, String)>,
}

impl ErrorContext {
    /// Create a new error context at the current location.
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            file: "",
            line: 0,
            span: None,
            operation: operation.into(),
            metadata: Vec::new(),
        }
    }

    /// Attach file and line info.
    pub fn at(mut self, file: &'static str, line: u32) -> Self {
        self.file = file;
        self.line = line;
        self
    }

    /// Attach a tracing span name.
    pub fn in_span(mut self, span: impl Into<String>) -> Self {
        self.span = Some(span.into());
        self
    }

    /// Attach a key-value metadata pair.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.operation)?;
        if !self.file.is_empty() {
            write!(f, " at {}:{}", self.file, self.line)?;
        }
        if let Some(ref span) = self.span {
            write!(f, " in span '{}'", span)?;
        }
        for (k, v) in &self.metadata {
            write!(f, " {}={}", k, v)?;
        }
        Ok(())
    }
}

/// Convenience macro to create an ErrorContext with file/line auto-filled.
#[macro_export]
macro_rules! error_context {
    ($op:expr) => {
        $crate::errors::ErrorContext::new($op).at(file!(), line!())
    };
    ($op:expr, $($key:expr => $val:expr),+ $(,)?) => {
        $crate::errors::ErrorContext::new($op)
            .at(file!(), line!())
            $(.with($key, $val))+
    };
}

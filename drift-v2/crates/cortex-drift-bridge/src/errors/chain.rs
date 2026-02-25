//! Error chain builder for multi-step operations.
//!
//! Collects non-fatal errors during a batch operation so the caller
//! can inspect all failures rather than stopping at the first one.

use super::bridge_error::BridgeError;
use super::context::ErrorContext;

/// A single link in an error chain.
#[derive(Debug)]
pub struct ChainedError {
    /// The error that occurred.
    pub error: BridgeError,
    /// Context about where/why it occurred.
    pub context: Option<ErrorContext>,
    /// Step index in the multi-step operation (0-based).
    pub step: usize,
}

/// Accumulates errors from a multi-step operation.
///
/// Use this when processing a batch (e.g., grounding 500 memories)
/// where individual failures should not abort the entire batch.
#[derive(Debug, Default)]
pub struct ErrorChain {
    errors: Vec<ChainedError>,
}

impl ErrorChain {
    /// Create a new empty error chain.
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Record an error at a given step.
    pub fn push(&mut self, step: usize, error: BridgeError) {
        self.errors.push(ChainedError {
            error,
            context: None,
            step,
        });
    }

    /// Record an error with context at a given step.
    pub fn push_with_context(&mut self, step: usize, error: BridgeError, context: ErrorContext) {
        self.errors.push(ChainedError {
            error,
            context: Some(context),
            step,
        });
    }

    /// Whether any errors were recorded.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Number of errors recorded.
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Iterate over all recorded errors.
    pub fn iter(&self) -> impl Iterator<Item = &ChainedError> {
        self.errors.iter()
    }

    /// Consume the chain and return the collected errors.
    pub fn into_errors(self) -> Vec<ChainedError> {
        self.errors
    }

    /// Return the first error, if any, consuming the chain.
    pub fn into_first(mut self) -> Option<BridgeError> {
        if self.errors.is_empty() {
            None
        } else {
            Some(self.errors.remove(0).error)
        }
    }
}

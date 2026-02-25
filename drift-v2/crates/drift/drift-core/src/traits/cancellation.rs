//! Cooperative cancellation token.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Cooperative cancellation token wrapping an `AtomicBool`.
///
/// Used by long-running operations (scan, analysis) to check
/// whether the user has requested cancellation.
pub trait Cancellable {
    /// Check if cancellation has been requested.
    fn is_cancelled(&self) -> bool;

    /// Request cancellation.
    fn cancel(&self);
}

/// Default implementation of a cancellation token.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a new cancellation token (not cancelled).
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl Cancellable for CancellationToken {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

//! Cancellation support for scan operations.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A cancellation handle for scan operations.
///
/// Wraps an `AtomicBool` that can be shared across threads.
/// Workers check `is_cancelled()` between files.
#[derive(Debug, Clone)]
pub struct ScanCancellation {
    flag: Arc<AtomicBool>,
}

impl ScanCancellation {
    /// Create a new cancellation handle (not cancelled).
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    /// Reset the cancellation flag (for reuse).
    pub fn reset(&self) {
        self.flag.store(false, Ordering::SeqCst);
    }

    /// Get a reference to the inner AtomicBool for use with the walker.
    pub fn as_atomic(&self) -> &AtomicBool {
        &self.flag
    }
}

impl Default for ScanCancellation {
    fn default() -> Self {
        Self::new()
    }
}

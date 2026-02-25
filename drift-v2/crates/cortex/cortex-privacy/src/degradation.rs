//! Graceful degradation for the privacy engine.
//!
//! If a regex pattern fails to compile, we skip it, log a warning,
//! and continue with the remaining patterns. The audit log records the gap.

/// Record of a pattern that failed to compile or execute.
#[derive(Debug, Clone)]
pub struct PatternFailure {
    pub pattern_name: String,
    pub category: String,
    pub error: String,
}

/// Degradation tracker — accumulates failures during a sanitization pass.
#[derive(Debug, Default)]
pub struct DegradationTracker {
    failures: Vec<PatternFailure>,
}

impl DegradationTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a pattern failure. The engine continues with remaining patterns.
    pub fn record_failure(&mut self, pattern_name: &str, category: &str, error: &str) {
        self.failures.push(PatternFailure {
            pattern_name: pattern_name.to_string(),
            category: category.to_string(),
            error: error.to_string(),
        });
    }

    /// Whether any patterns failed during this pass.
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    /// Get all recorded failures.
    pub fn failures(&self) -> &[PatternFailure] {
        &self.failures
    }

    /// Count of failed patterns.
    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }
}

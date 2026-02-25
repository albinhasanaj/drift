//! Optional LLM enhancement (rephrase only, not consolidation logic).
//! Tracks polished vs unpolished rates.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Tracks LLM polish statistics.
pub struct PolishTracker {
    polished: AtomicUsize,
    unpolished: AtomicUsize,
}

impl PolishTracker {
    pub fn new() -> Self {
        Self {
            polished: AtomicUsize::new(0),
            unpolished: AtomicUsize::new(0),
        }
    }

    /// Record a polished summary.
    pub fn record_polished(&self) {
        self.polished.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an unpolished summary.
    pub fn record_unpolished(&self) {
        self.unpolished.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the polish rate (fraction of summaries that were polished).
    pub fn polish_rate(&self) -> f64 {
        let p = self.polished.load(Ordering::Relaxed) as f64;
        let u = self.unpolished.load(Ordering::Relaxed) as f64;
        let total = p + u;
        if total < f64::EPSILON {
            0.0
        } else {
            p / total
        }
    }

    pub fn polished_count(&self) -> usize {
        self.polished.load(Ordering::Relaxed)
    }

    pub fn unpolished_count(&self) -> usize {
        self.unpolished.load(Ordering::Relaxed)
    }
}

impl Default for PolishTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for optional LLM polish providers.
/// Implementations can call an LLM to rephrase summaries.
pub trait LlmPolisher: Send + Sync {
    /// Rephrase a summary for clarity. Returns None if LLM is unavailable.
    fn polish(&self, summary: &str) -> Option<String>;
}

/// No-op polisher that always returns None (LLM unavailable).
pub struct NoOpPolisher;

impl LlmPolisher for NoOpPolisher {
    fn polish(&self, _summary: &str) -> Option<String> {
        None
    }
}

/// Polish a summary using the provided polisher, tracking statistics.
pub fn polish_summary(
    summary: &str,
    polisher: &dyn LlmPolisher,
    tracker: &PolishTracker,
) -> String {
    match polisher.polish(summary) {
        Some(polished) => {
            tracker.record_polished();
            polished
        }
        None => {
            tracker.record_unpolished();
            summary.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_polisher_returns_none() {
        let polisher = NoOpPolisher;
        assert!(polisher.polish("test").is_none());
    }

    #[test]
    fn tracker_counts_correctly() {
        let tracker = PolishTracker::new();
        tracker.record_polished();
        tracker.record_polished();
        tracker.record_unpolished();
        assert_eq!(tracker.polished_count(), 2);
        assert_eq!(tracker.unpolished_count(), 1);
        assert!((tracker.polish_rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn polish_summary_uses_fallback() {
        let polisher = NoOpPolisher;
        let tracker = PolishTracker::new();
        let result = polish_summary("original", &polisher, &tracker);
        assert_eq!(result, "original");
        assert_eq!(tracker.unpolished_count(), 1);
    }
}

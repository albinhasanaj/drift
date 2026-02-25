//! Active sessions, avg duration, dedup savings, intent distribution.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Session-level metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionMetrics {
    /// Currently active session count.
    pub active_sessions: u64,
    /// Completed session durations in seconds.
    durations_secs: Vec<u64>,
    /// Tokens saved by deduplication.
    pub tokens_saved_by_dedup: u64,
    /// Total tokens that would have been sent without dedup.
    pub tokens_before_dedup: u64,
    /// Intent distribution across sessions.
    pub intent_distribution: HashMap<String, u64>,
}

impl SessionMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a session start.
    pub fn session_started(&mut self) {
        self.active_sessions += 1;
    }

    /// Record a session end with its duration.
    pub fn session_ended(&mut self, duration: Duration) {
        self.active_sessions = self.active_sessions.saturating_sub(1);
        self.durations_secs.push(duration.as_secs());
        if self.durations_secs.len() > 10_000 {
            self.durations_secs
                .drain(..self.durations_secs.len() - 10_000);
        }
    }

    /// Record dedup savings for a retrieval.
    pub fn record_dedup(&mut self, tokens_before: u64, tokens_after: u64) {
        self.tokens_before_dedup += tokens_before;
        self.tokens_saved_by_dedup += tokens_before.saturating_sub(tokens_after);
    }

    /// Record an intent occurrence.
    pub fn record_intent(&mut self, intent: &str) {
        *self
            .intent_distribution
            .entry(intent.to_string())
            .or_default() += 1;
    }

    /// Average session duration.
    pub fn avg_duration(&self) -> Duration {
        if self.durations_secs.is_empty() {
            return Duration::ZERO;
        }
        let sum: u64 = self.durations_secs.iter().sum();
        Duration::from_secs(sum / self.durations_secs.len() as u64)
    }

    /// Dedup savings as a fraction (0.0–1.0).
    pub fn dedup_savings_rate(&self) -> f64 {
        if self.tokens_before_dedup == 0 {
            return 0.0;
        }
        self.tokens_saved_by_dedup as f64 / self.tokens_before_dedup as f64
    }
}

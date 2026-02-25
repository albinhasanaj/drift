//! Query performance logging: query text, intent, latency, result count, token budget used, cache hits.

use std::time::Duration;

use cortex_core::intent::Intent;
use serde::{Deserialize, Serialize};

/// A single query log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    pub query: String,
    pub intent: Option<Intent>,
    pub latency: Duration,
    pub result_count: usize,
    pub token_budget: usize,
    pub tokens_used: usize,
    pub cache_hits: usize,
    pub timestamp_epoch_ms: i64,
}

impl QueryLogEntry {
    /// Create a new entry with the timestamp set to now.
    pub fn new(
        query: impl Into<String>,
        intent: Option<Intent>,
        latency: Duration,
        result_count: usize,
        token_budget: usize,
        tokens_used: usize,
        cache_hits: usize,
    ) -> Self {
        Self {
            query: query.into(),
            intent,
            latency,
            result_count,
            token_budget,
            tokens_used,
            cache_hits,
            timestamp_epoch_ms: chrono::Utc::now().timestamp_millis(),
        }
    }
}

/// Append-only query log for retrieval performance analysis.
#[derive(Debug, Clone, Default)]
pub struct QueryLog {
    entries: Vec<QueryLogEntry>,
    /// Maximum entries to retain (ring buffer behavior).
    max_entries: usize,
}

impl QueryLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: 50_000,
        }
    }

    /// Create with a custom capacity.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    /// Record a query.
    pub fn record(&mut self, entry: QueryLogEntry) {
        tracing::debug!(
            event = "query_logged",
            query = %entry.query,
            intent = ?entry.intent,
            latency_ms = entry.latency.as_millis() as u64,
            result_count = entry.result_count,
            tokens_used = entry.tokens_used,
            cache_hits = entry.cache_hits,
            "query logged"
        );

        self.entries.push(entry);
        if self.entries.len() > self.max_entries {
            self.entries.drain(..self.entries.len() - self.max_entries);
        }
    }

    /// Get all entries.
    pub fn entries(&self) -> &[QueryLogEntry] {
        &self.entries
    }

    /// Average latency across all logged queries.
    pub fn avg_latency(&self) -> Duration {
        if self.entries.is_empty() {
            return Duration::ZERO;
        }
        let total: Duration = self.entries.iter().map(|e| e.latency).sum();
        total / self.entries.len() as u32
    }

    /// Latency at the given percentile (0.0–1.0).
    pub fn latency_percentile(&self, p: f64) -> Duration {
        if self.entries.is_empty() {
            return Duration::ZERO;
        }
        let mut latencies: Vec<Duration> = self.entries.iter().map(|e| e.latency).collect();
        latencies.sort();
        let idx = ((p * (latencies.len() - 1) as f64).round() as usize).min(latencies.len() - 1);
        latencies[idx]
    }

    /// Total number of logged queries.
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

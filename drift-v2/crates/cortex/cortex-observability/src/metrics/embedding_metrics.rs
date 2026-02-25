//! Cache hit rates (L1/L2/L3), inference latency, migration progress, provider usage.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Embedding subsystem metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmbeddingMetrics {
    /// Cache hits per level.
    pub l1_hits: u64,
    pub l2_hits: u64,
    pub l3_hits: u64,
    /// Total cache lookups.
    pub total_lookups: u64,
    /// Inference latency samples in microseconds.
    latency_samples_us: Vec<u64>,
    /// Migration progress: (completed, total).
    pub migration_completed: u64,
    pub migration_total: u64,
    /// Provider usage counts.
    pub provider_usage: HashMap<String, u64>,
}

impl EmbeddingMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cache lookup result.
    pub fn record_lookup(&mut self, hit_level: Option<u8>) {
        self.total_lookups += 1;
        match hit_level {
            Some(1) => self.l1_hits += 1,
            Some(2) => self.l2_hits += 1,
            Some(3) => self.l3_hits += 1,
            _ => {}
        }
    }

    /// Record an inference latency.
    pub fn record_latency(&mut self, duration: Duration) {
        self.latency_samples_us.push(duration.as_micros() as u64);
        if self.latency_samples_us.len() > 10_000 {
            self.latency_samples_us
                .drain(..self.latency_samples_us.len() - 10_000);
        }
    }

    /// Record provider usage.
    pub fn record_provider(&mut self, provider: &str) {
        *self.provider_usage.entry(provider.to_string()).or_default() += 1;
    }

    /// Update migration progress.
    pub fn set_migration_progress(&mut self, completed: u64, total: u64) {
        self.migration_completed = completed;
        self.migration_total = total;
    }

    /// L1 cache hit rate.
    pub fn l1_hit_rate(&self) -> f64 {
        if self.total_lookups == 0 {
            0.0
        } else {
            self.l1_hits as f64 / self.total_lookups as f64
        }
    }

    /// L2 cache hit rate.
    pub fn l2_hit_rate(&self) -> f64 {
        if self.total_lookups == 0 {
            0.0
        } else {
            self.l2_hits as f64 / self.total_lookups as f64
        }
    }

    /// L3 cache hit rate.
    pub fn l3_hit_rate(&self) -> f64 {
        if self.total_lookups == 0 {
            0.0
        } else {
            self.l3_hits as f64 / self.total_lookups as f64
        }
    }

    /// Combined cache hit rate across all levels.
    pub fn combined_hit_rate(&self) -> f64 {
        if self.total_lookups == 0 {
            return 0.0;
        }
        (self.l1_hits + self.l2_hits + self.l3_hits) as f64 / self.total_lookups as f64
    }

    /// Inference latency at the given percentile (0.0–1.0).
    pub fn latency_percentile(&self, p: f64) -> Duration {
        if self.latency_samples_us.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.latency_samples_us.clone();
        sorted.sort_unstable();
        let idx = ((p * (sorted.len() - 1) as f64).round() as usize).min(sorted.len() - 1);
        Duration::from_micros(sorted[idx])
    }

    /// Migration progress as a fraction (0.0–1.0).
    pub fn migration_progress(&self) -> f64 {
        if self.migration_total == 0 {
            1.0
        } else {
            self.migration_completed as f64 / self.migration_total as f64
        }
    }
}

//! DB size, fragmentation, growth rate, time-to-threshold.

use serde::{Deserialize, Serialize};

/// Storage-level metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageMetrics {
    /// Current database size in bytes.
    pub db_size_bytes: u64,
    /// Estimated fragmentation ratio (0.0–1.0).
    pub fragmentation: f64,
    /// Historical size samples for growth rate calculation: (unix_ts, bytes).
    samples: Vec<(i64, u64)>,
}

impl StorageMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a size sample at the given unix timestamp.
    pub fn record_size(&mut self, timestamp: i64, size_bytes: u64) {
        self.db_size_bytes = size_bytes;
        self.samples.push((timestamp, size_bytes));
        // Keep last 1000 samples.
        if self.samples.len() > 1000 {
            self.samples.drain(..self.samples.len() - 1000);
        }
    }

    /// Update fragmentation estimate.
    pub fn set_fragmentation(&mut self, ratio: f64) {
        self.fragmentation = ratio.clamp(0.0, 1.0);
    }

    /// Growth rate in bytes per day, computed from the oldest and newest samples.
    pub fn growth_rate_bytes_per_day(&self) -> f64 {
        if self.samples.len() < 2 {
            return 0.0;
        }
        let first = self.samples.first().unwrap();
        let last = self.samples.last().unwrap();
        let elapsed_secs = (last.0 - first.0) as f64;
        if elapsed_secs <= 0.0 {
            return 0.0;
        }
        let delta_bytes = last.1 as f64 - first.1 as f64;
        let secs_per_day = 86_400.0;
        delta_bytes * secs_per_day / elapsed_secs
    }

    /// Estimated days until the given threshold is reached, or `None` if not growing.
    pub fn days_to_threshold(&self, threshold_bytes: u64) -> Option<f64> {
        let rate = self.growth_rate_bytes_per_day();
        if rate <= 0.0 || self.db_size_bytes >= threshold_bytes {
            return None;
        }
        let remaining = (threshold_bytes - self.db_size_bytes) as f64;
        Some(remaining / rate)
    }
}

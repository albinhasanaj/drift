//! Metered usage tracking for Community tier features.
//!
//! Tracks per-feature invocation counts with configurable limits.
//! Resets daily. Persisted in bridge_metrics table.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rusqlite::Connection;

/// Per-feature usage limits for Community tier.
pub struct UsageLimits {
    /// Feature name → max invocations per day.
    pub limits: HashMap<&'static str, u64>,
}

impl UsageLimits {
    /// Default Community tier limits.
    pub fn community_defaults() -> Self {
        let mut limits = HashMap::new();
        limits.insert("grounding_basic", 50);
        limits.insert("causal_edges", 200);
        limits.insert("drift_grounding_check", 100);
        Self { limits }
    }

    /// Get the limit for a feature. Returns None if unlimited.
    pub fn limit_for(&self, feature: &str) -> Option<u64> {
        self.limits.get(feature).copied()
    }
}

/// In-memory usage counter with daily reset.
pub struct UsageTracker {
    /// Feature name → invocation count.
    counts: Mutex<HashMap<String, u64>>,
    /// When the current period started.
    period_start: Mutex<Instant>,
    /// Period duration (default: 24 hours).
    period_duration: Duration,
    /// Limits configuration.
    limits: UsageLimits,
    /// Total invocations across all features (atomic for fast read).
    total_invocations: AtomicU64,
}

impl UsageTracker {
    /// Create a new tracker with Community defaults.
    pub fn new() -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
            period_start: Mutex::new(Instant::now()),
            period_duration: Duration::from_secs(86400), // 24 hours
            limits: UsageLimits::community_defaults(),
            total_invocations: AtomicU64::new(0),
        }
    }

    /// Create with custom limits and period.
    pub fn with_config(limits: UsageLimits, period: Duration) -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
            period_start: Mutex::new(Instant::now()),
            period_duration: period,
            limits,
            total_invocations: AtomicU64::new(0),
        }
    }

    /// Record a feature invocation. Returns Ok(()) if under limit, Err with remaining count if over.
    pub fn record(&self, feature: &str) -> Result<(), UsageLimitExceeded> {
        self.maybe_reset();

        let limit = self.limits.limit_for(feature);

        let mut counts = self.counts.lock().unwrap();
        let count = counts.entry(feature.to_string()).or_insert(0);
        *count += 1;
        self.total_invocations.fetch_add(1, Ordering::Relaxed);

        if let Some(max) = limit {
            if *count > max {
                return Err(UsageLimitExceeded {
                    feature: feature.to_string(),
                    limit: max,
                    current: *count,
                });
            }
        }

        Ok(())
    }

    /// Check if a feature is at or over its limit (without incrementing).
    pub fn is_at_limit(&self, feature: &str) -> bool {
        self.maybe_reset();

        let limit = match self.limits.limit_for(feature) {
            Some(l) => l,
            None => return false,
        };

        let counts = self.counts.lock().unwrap();
        counts.get(feature).copied().unwrap_or(0) >= limit
    }

    /// Get current usage count for a feature.
    pub fn usage_count(&self, feature: &str) -> u64 {
        let counts = self.counts.lock().unwrap();
        counts.get(feature).copied().unwrap_or(0)
    }

    /// Get remaining invocations for a feature. Returns None if unlimited.
    pub fn remaining(&self, feature: &str) -> Option<u64> {
        let limit = self.limits.limit_for(feature)?;
        let counts = self.counts.lock().unwrap();
        let used = counts.get(feature).copied().unwrap_or(0);
        Some(limit.saturating_sub(used))
    }

    /// Total invocations across all features.
    pub fn total_invocations(&self) -> u64 {
        self.total_invocations.load(Ordering::Relaxed)
    }

    /// Reset all counters.
    pub fn reset(&self) {
        let mut counts = self.counts.lock().unwrap();
        counts.clear();
        let mut start = self.period_start.lock().unwrap();
        *start = Instant::now();
        self.total_invocations.store(0, Ordering::Relaxed);
    }

    /// Persist current usage counts to bridge_metrics table.
    /// Each feature count is stored as `usage:{feature_name}`.
    ///
    /// Cleans up stale `usage:*` rows before inserting to prevent unbounded
    /// row accumulation (bridge_metrics has no unique constraint on metric_name).
    pub fn persist(&self, conn: &Connection) -> Result<(), rusqlite::Error> {
        let counts = self.counts.lock().unwrap();
        // Remove previous usage rows to avoid accumulation
        conn.execute(
            "DELETE FROM bridge_metrics WHERE metric_name LIKE 'usage:%'",
            [],
        )?;
        for (feature, count) in counts.iter() {
            conn.execute(
                "INSERT INTO bridge_metrics (metric_name, metric_value) VALUES (?1, ?2)",
                rusqlite::params![format!("usage:{}", feature), *count as f64],
            )?;
        }
        Ok(())
    }

    /// Load persisted usage counts from bridge_metrics table.
    /// Reads the latest `usage:*` metrics and restores counts.
    pub fn load(&self, conn: &Connection) -> Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare(
            "SELECT metric_name, metric_value FROM bridge_metrics \
             WHERE metric_name LIKE 'usage:%' \
             ORDER BY recorded_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
        })?;

        let mut counts = self.counts.lock().unwrap();
        let mut total = 0u64;
        for row in rows {
            let (name, value) = row?;
            if let Some(feature) = name.strip_prefix("usage:") {
                // Only take the first (most recent) value per feature
                counts.entry(feature.to_string()).or_insert_with(|| {
                    let v = value as u64;
                    total += v;
                    v
                });
            }
        }
        self.total_invocations.store(total, Ordering::Relaxed);
        Ok(())
    }

    /// Check if the period has elapsed and reset if so.
    fn maybe_reset(&self) {
        let start = self.period_start.lock().unwrap();
        if start.elapsed() >= self.period_duration {
            drop(start); // Release lock before calling reset
            self.reset();
        }
    }
}

impl Default for UsageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Error when a usage limit is exceeded.
#[derive(Debug, Clone)]
pub struct UsageLimitExceeded {
    pub feature: String,
    pub limit: u64,
    pub current: u64,
}

impl std::fmt::Display for UsageLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Usage limit exceeded for '{}': {}/{} invocations",
            self.feature, self.current, self.limit
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_under_limit() {
        let tracker = UsageTracker::new();
        assert!(tracker.record("grounding_basic").is_ok());
        assert_eq!(tracker.usage_count("grounding_basic"), 1);
    }

    #[test]
    fn test_record_at_limit() {
        let mut limits = HashMap::new();
        limits.insert("test_feature", 3u64);
        let tracker = UsageTracker::with_config(
            UsageLimits { limits },
            Duration::from_secs(86400),
        );

        assert!(tracker.record("test_feature").is_ok());
        assert!(tracker.record("test_feature").is_ok());
        assert!(tracker.record("test_feature").is_ok());
        assert!(tracker.record("test_feature").is_err()); // 4th exceeds limit of 3
    }

    #[test]
    fn test_unlimited_feature() {
        let tracker = UsageTracker::new();
        // Features not in the limits map are unlimited
        for _ in 0..1000 {
            assert!(tracker.record("unlimited_feature").is_ok());
        }
    }

    #[test]
    fn test_remaining() {
        let tracker = UsageTracker::new();
        let initial = tracker.remaining("grounding_basic").unwrap();
        assert_eq!(initial, 50);

        tracker.record("grounding_basic").unwrap();
        assert_eq!(tracker.remaining("grounding_basic").unwrap(), 49);
    }

    #[test]
    fn test_remaining_unlimited() {
        let tracker = UsageTracker::new();
        assert!(tracker.remaining("unlimited_feature").is_none());
    }

    #[test]
    fn test_reset() {
        let tracker = UsageTracker::new();
        tracker.record("grounding_basic").unwrap();
        assert_eq!(tracker.usage_count("grounding_basic"), 1);

        tracker.reset();
        assert_eq!(tracker.usage_count("grounding_basic"), 0);
        assert_eq!(tracker.total_invocations(), 0);
    }

    #[test]
    fn test_period_auto_reset() {
        let mut limits = HashMap::new();
        limits.insert("test_feature", 2u64);
        let tracker = UsageTracker::with_config(
            UsageLimits { limits },
            Duration::from_millis(10), // Very short period
        );

        tracker.record("test_feature").unwrap();
        tracker.record("test_feature").unwrap();
        assert!(tracker.record("test_feature").is_err());

        // Wait for period to expire
        std::thread::sleep(Duration::from_millis(20));

        // Should be reset now
        assert!(tracker.record("test_feature").is_ok());
    }

    #[test]
    fn test_is_at_limit() {
        let mut limits = HashMap::new();
        limits.insert("test_feature", 1u64);
        let tracker = UsageTracker::with_config(
            UsageLimits { limits },
            Duration::from_secs(86400),
        );

        assert!(!tracker.is_at_limit("test_feature"));
        tracker.record("test_feature").unwrap();
        assert!(tracker.is_at_limit("test_feature"));
    }
}

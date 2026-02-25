//! Momentum tracking: trend detection (rising/falling/stable), temporal decay.
//!
//! Tracks pattern frequency across consecutive scans to detect trends.
//! Temporal decay: pattern not seen for 30 days drops ≥1 tier.

use super::types::MomentumDirection;

/// Momentum tracker for a single pattern across scans.
#[derive(Debug, Clone)]
pub struct MomentumTracker {
    /// History of occurrence counts per scan (most recent last).
    scan_history: Vec<u64>,
    /// Maximum history length to retain.
    max_history: usize,
}

impl MomentumTracker {
    /// Create a new tracker with default history length (10 scans).
    pub fn new() -> Self {
        Self {
            scan_history: Vec::new(),
            max_history: 10,
        }
    }

    /// Create a tracker with custom history length.
    pub fn with_history_length(max_history: usize) -> Self {
        Self {
            scan_history: Vec::new(),
            max_history: max_history.max(2),
        }
    }

    /// Record a new scan observation.
    pub fn record(&mut self, occurrence_count: u64) {
        self.scan_history.push(occurrence_count);
        if self.scan_history.len() > self.max_history {
            self.scan_history.remove(0);
        }
    }

    /// Compute the current momentum direction.
    ///
    /// Uses linear regression slope on the last N scans.
    /// Rising: slope > threshold, Falling: slope < -threshold, Stable: otherwise.
    pub fn direction(&self) -> MomentumDirection {
        if self.scan_history.len() < 2 {
            return MomentumDirection::Stable;
        }

        let slope = self.compute_slope();
        let threshold = 0.1; // 10% change per scan is significant

        // Normalize slope by mean to get relative change
        let mean = self.scan_history.iter().sum::<u64>() as f64 / self.scan_history.len() as f64;
        if mean <= 0.0 {
            return MomentumDirection::Stable;
        }

        let relative_slope = slope / mean;

        if relative_slope > threshold {
            MomentumDirection::Rising
        } else if relative_slope < -threshold {
            MomentumDirection::Falling
        } else {
            MomentumDirection::Stable
        }
    }

    /// Compute linear regression slope on scan history.
    fn compute_slope(&self) -> f64 {
        let n = self.scan_history.len() as f64;
        if n < 2.0 {
            return 0.0;
        }

        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;

        for (i, &count) in self.scan_history.iter().enumerate() {
            let x = i as f64;
            let y = count as f64;
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
        }

        let denom = n * sum_x2 - sum_x * sum_x;
        if denom.abs() < 1e-10 {
            return 0.0;
        }

        (n * sum_xy - sum_x * sum_y) / denom
    }

    /// Get the scan history.
    pub fn history(&self) -> &[u64] {
        &self.scan_history
    }
}

impl Default for MomentumTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute temporal decay factor based on days since last seen.
///
/// Pattern not seen for 30+ days → decay factor drops confidence by ≥1 tier.
/// Returns a multiplier in [0.0, 1.0] to apply to alpha.
pub fn temporal_decay(days_since_last_seen: u64) -> f64 {
    const DECAY_START_DAYS: u64 = 7;
    const FULL_DECAY_DAYS: u64 = 90;

    if days_since_last_seen <= DECAY_START_DAYS {
        return 1.0; // No decay within first week
    }

    if days_since_last_seen >= FULL_DECAY_DAYS {
        return 0.1; // Minimum retention
    }

    // Linear decay from 1.0 to 0.1 over the decay window
    let decay_window = (FULL_DECAY_DAYS - DECAY_START_DAYS) as f64;
    let elapsed = (days_since_last_seen - DECAY_START_DAYS) as f64;
    let decay = 1.0 - (elapsed / decay_window) * 0.9;
    decay.clamp(0.1, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_momentum_stable_insufficient_data() {
        let tracker = MomentumTracker::new();
        assert_eq!(tracker.direction(), MomentumDirection::Stable);
    }

    #[test]
    fn test_momentum_rising() {
        let mut tracker = MomentumTracker::new();
        for i in 0..10 {
            tracker.record(10 + i * 5);
        }
        assert_eq!(tracker.direction(), MomentumDirection::Rising);
    }

    #[test]
    fn test_momentum_falling() {
        let mut tracker = MomentumTracker::new();
        for i in 0..10 {
            tracker.record(100 - i * 10);
        }
        assert_eq!(tracker.direction(), MomentumDirection::Falling);
    }

    #[test]
    fn test_momentum_stable() {
        let mut tracker = MomentumTracker::new();
        for _ in 0..10 {
            tracker.record(50);
        }
        assert_eq!(tracker.direction(), MomentumDirection::Stable);
    }

    #[test]
    fn test_temporal_decay_recent() {
        assert_eq!(temporal_decay(0), 1.0);
        assert_eq!(temporal_decay(7), 1.0);
    }

    #[test]
    fn test_temporal_decay_30_days() {
        let decay = temporal_decay(30);
        assert!(decay < 0.8, "30 days should cause significant decay: {}", decay);
    }

    #[test]
    fn test_temporal_decay_90_days() {
        let decay = temporal_decay(90);
        assert!((decay - 0.1).abs() < 1e-10);
    }
}

//! Yield between batches to prevent write-starvation.

use std::time::Duration;

/// Default yield duration between consolidation batches.
const DEFAULT_YIELD_MS: u64 = 50;
/// Maximum batch size before yielding.
const DEFAULT_BATCH_SIZE: usize = 10;

/// Throttle configuration for consolidation batches.
#[derive(Debug, Clone)]
pub struct ThrottleConfig {
    /// How long to yield between batches.
    pub yield_duration: Duration,
    /// Maximum items per batch before yielding.
    pub batch_size: usize,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            yield_duration: Duration::from_millis(DEFAULT_YIELD_MS),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

/// A throttle that tracks progress and determines when to yield.
#[derive(Debug)]
pub struct Throttle {
    config: ThrottleConfig,
    items_in_batch: usize,
}

impl Throttle {
    pub fn new(config: ThrottleConfig) -> Self {
        Self {
            config,
            items_in_batch: 0,
        }
    }

    /// Record that an item was processed. Returns true if the caller should yield.
    pub fn tick(&mut self) -> bool {
        self.items_in_batch += 1;
        if self.items_in_batch >= self.config.batch_size {
            self.items_in_batch = 0;
            true
        } else {
            false
        }
    }

    /// Get the yield duration.
    pub fn yield_duration(&self) -> Duration {
        self.config.yield_duration
    }

    /// Reset the batch counter.
    pub fn reset(&mut self) {
        self.items_in_batch = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yields_after_batch_size() {
        let mut throttle = Throttle::new(ThrottleConfig {
            yield_duration: Duration::from_millis(10),
            batch_size: 3,
        });
        assert!(!throttle.tick());
        assert!(!throttle.tick());
        assert!(throttle.tick()); // 3rd item triggers yield
        assert!(!throttle.tick()); // resets
    }

    #[test]
    fn reset_clears_counter() {
        let mut throttle = Throttle::new(ThrottleConfig::default());
        throttle.tick();
        throttle.tick();
        throttle.reset();
        // Should need full batch_size again.
        for _ in 0..DEFAULT_BATCH_SIZE - 1 {
            assert!(!throttle.tick());
        }
        assert!(throttle.tick());
    }
}

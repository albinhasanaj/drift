//! Backpressure controller for live projection subscriptions.
//!
//! Transitions between sync modes based on queue utilization:
//! - Queue > 80% capacity → Batched mode
//! - Queue < 50% capacity → Streaming mode

use tracing::info;

/// Sync mode for a live projection subscription.
#[derive(Debug, Clone, PartialEq)]
pub enum SyncMode {
    /// Real-time delta streaming.
    Streaming,
    /// Batched delivery at intervals (backpressure active).
    Batched { interval_secs: u64 },
    /// Full catch-up sync needed.
    CatchUp,
}

/// Backpressure controller that manages sync mode transitions.
pub struct BackpressureController {
    /// High watermark threshold (fraction, e.g., 0.8).
    pub high_watermark: f64,
    /// Low watermark threshold (fraction, e.g., 0.5).
    pub low_watermark: f64,
    /// Batch interval when in Batched mode.
    pub batch_interval_secs: u64,
}

impl BackpressureController {
    /// Create a new controller with default thresholds.
    pub fn new(batch_interval_secs: u64) -> Self {
        Self {
            high_watermark: 0.8,
            low_watermark: 0.5,
            batch_interval_secs,
        }
    }

    /// Check backpressure and return the appropriate sync mode.
    pub fn check_backpressure(
        &self,
        queue_depth: usize,
        max_queue_size: usize,
        current_mode: &SyncMode,
    ) -> SyncMode {
        if max_queue_size == 0 {
            return SyncMode::Streaming;
        }

        let utilization = queue_depth as f64 / max_queue_size as f64;

        if utilization > self.high_watermark {
            if !matches!(current_mode, SyncMode::Batched { .. }) {
                info!(
                    utilization = format!("{:.1}%", utilization * 100.0),
                    "backpressure: switching to Batched mode"
                );
            }
            SyncMode::Batched {
                interval_secs: self.batch_interval_secs,
            }
        } else if utilization < self.low_watermark {
            if *current_mode != SyncMode::Streaming {
                info!(
                    utilization = format!("{:.1}%", utilization * 100.0),
                    "backpressure: recovering to Streaming mode"
                );
            }
            SyncMode::Streaming
        } else {
            // In the middle zone — keep current mode.
            current_mode.clone()
        }
    }
}

impl Default for BackpressureController {
    fn default() -> Self {
        Self::new(30)
    }
}

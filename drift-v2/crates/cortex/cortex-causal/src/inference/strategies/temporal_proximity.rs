//! Temporal proximity inference strategy (weight 0.2).
//! Memories created close together in time are more likely causally related.

use cortex_core::memory::BaseMemory;

/// Weight for this strategy in composite scoring.
pub const WEIGHT: f64 = 0.2;

/// Maximum time window (in seconds) for temporal proximity.
const MAX_WINDOW_SECS: f64 = 86400.0; // 24 hours

/// Score temporal proximity between two memories.
/// Returns 0.0–1.0 where 1.0 means created at the same instant.
pub fn score(source: &BaseMemory, target: &BaseMemory) -> f64 {
    let delta = (source.transaction_time - target.transaction_time)
        .num_seconds()
        .unsigned_abs() as f64;

    if delta >= MAX_WINDOW_SECS {
        return 0.0;
    }

    // Exponential decay: closer in time → higher score.
    (-delta / (MAX_WINDOW_SECS / 3.0)).exp()
}

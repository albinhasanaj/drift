//! Confidence adjustment based on validation scores.

use cortex_core::memory::BaseMemory;
use cortex_core::memory::Confidence;

/// Adjust a memory's confidence based on its validation score.
///
/// The adjustment blends the current confidence toward the validation score,
/// weighted by `adjustment_strength` (0.0 = no change, 1.0 = full replacement).
pub fn adjust(memory: &mut BaseMemory, validation_score: f64, adjustment_strength: f64) {
    let current = memory.confidence.value();
    let strength = adjustment_strength.clamp(0.0, 1.0);
    let new_value = current * (1.0 - strength) + validation_score * strength;
    memory.confidence = Confidence::new(new_value);
}

/// Apply a direct delta to a memory's confidence.
pub fn apply_delta(memory: &mut BaseMemory, delta: f64) {
    let new_value = memory.confidence.value() + delta;
    memory.confidence = Confidence::new(new_value);
}

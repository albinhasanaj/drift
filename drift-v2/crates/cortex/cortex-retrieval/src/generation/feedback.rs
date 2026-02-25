//! Generation outcome tracking: accepted/modified/rejected → adjust confidence
//! of influencing memories.

use cortex_core::errors::CortexResult;
use cortex_core::memory::Confidence;
use cortex_core::traits::IMemoryStorage;

/// Outcome of a generation that was influenced by memories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationOutcome {
    /// The generated output was accepted as-is.
    Accepted,
    /// The generated output was modified before use.
    Modified,
    /// The generated output was rejected.
    Rejected,
}

/// Confidence adjustment deltas per outcome.
const ACCEPTED_DELTA: f64 = 0.05;
const MODIFIED_DELTA: f64 = 0.0; // Neutral.
const REJECTED_DELTA: f64 = -0.10;

/// Apply feedback from a generation outcome to the influencing memories.
///
/// Adjusts confidence of each memory based on whether the generation was
/// accepted, modified, or rejected.
pub fn apply_feedback(
    storage: &dyn IMemoryStorage,
    memory_ids: &[String],
    outcome: GenerationOutcome,
) -> CortexResult<usize> {
    let delta = match outcome {
        GenerationOutcome::Accepted => ACCEPTED_DELTA,
        GenerationOutcome::Modified => MODIFIED_DELTA,
        GenerationOutcome::Rejected => REJECTED_DELTA,
    };

    if delta == 0.0 {
        return Ok(0);
    }

    let mut updated = 0;
    for id in memory_ids {
        if let Some(mut memory) = storage.get(id)? {
            let new_conf = memory.confidence.value() + delta;
            memory.confidence = Confidence::new(new_conf);
            memory.access_count += 1;
            storage.update(&memory)?;
            updated += 1;
        }
    }

    Ok(updated)
}

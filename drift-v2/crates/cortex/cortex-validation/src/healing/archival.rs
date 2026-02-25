//! Archive memories with reason tracking.

use cortex_core::memory::BaseMemory;
use cortex_core::memory::Confidence;

/// Reason for archiving a memory.
#[derive(Debug, Clone)]
pub struct ArchivalReason {
    pub memory_id: String,
    pub reason: String,
    pub final_confidence: f64,
}

/// Check if a memory should be archived based on its confidence.
///
/// Memories below the archival threshold (0.15) are candidates.
pub fn should_archive(memory: &BaseMemory) -> bool {
    memory.confidence.is_archival()
}

/// Archive a memory: set archived flag and record the reason.
///
/// Returns the archival reason for audit logging.
pub fn archive(memory: &mut BaseMemory, reason: &str) -> ArchivalReason {
    let final_confidence = memory.confidence.value();
    memory.archived = true;
    // Set confidence to minimum to prevent retrieval.
    memory.confidence = Confidence::new(0.0);

    ArchivalReason {
        memory_id: memory.id.clone(),
        reason: reason.to_string(),
        final_confidence,
    }
}

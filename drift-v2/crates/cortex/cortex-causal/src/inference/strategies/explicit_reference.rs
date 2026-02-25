//! Explicit reference inference strategy (weight 0.4).
//! Detects when one memory explicitly references another via supersedes/superseded_by links.

use cortex_core::memory::BaseMemory;

/// Weight for this strategy in composite scoring.
pub const WEIGHT: f64 = 0.4;

/// Score explicit references between two memories.
pub fn score(source: &BaseMemory, target: &BaseMemory) -> f64 {
    // Direct supersession link.
    if source.supersedes.as_deref() == Some(&target.id) {
        return 1.0;
    }
    if source.superseded_by.as_deref() == Some(&target.id) {
        return 1.0;
    }

    // Check if target is referenced in source's tags (convention: "ref:<id>").
    let ref_prefix = format!("ref:{}", target.id);
    if source.tags.iter().any(|t| t == &ref_prefix) {
        return 0.8;
    }

    // Check short ID prefix match in tags.
    let short_id = &target.id[..target.id.len().min(8)];
    if source.tags.iter().any(|t| t.contains(short_id)) {
        return 0.4;
    }

    0.0
}

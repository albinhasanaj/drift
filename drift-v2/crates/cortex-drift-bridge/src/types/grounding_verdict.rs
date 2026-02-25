//! GroundingVerdict: outcome of comparing memory against reality.

use serde::{Deserialize, Serialize};

/// Grounding verdict — the outcome of comparing memory against reality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroundingVerdict {
    /// Memory is strongly supported by Drift data (score >= 0.7).
    Validated,
    /// Memory is partially supported (0.4 <= score < 0.7).
    Partial,
    /// Memory is weakly supported (0.2 <= score < 0.4).
    Weak,
    /// Memory is contradicted by Drift data (score < 0.2).
    Invalidated,
    /// Memory type is not groundable.
    NotGroundable,
    /// Insufficient Drift data to ground this memory.
    InsufficientData,
    /// An error occurred during grounding.
    Error,
}

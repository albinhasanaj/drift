//! ConfidenceAdjustment + AdjustmentMode: how to adjust memory confidence after grounding.

use serde::{Deserialize, Serialize};

/// How to adjust memory confidence based on grounding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceAdjustment {
    /// The adjustment mode.
    pub mode: AdjustmentMode,
    /// The delta to apply (for Boost/Penalize mode).
    pub delta: Option<f64>,
    /// Reason for the adjustment.
    pub reason: String,
}

/// Adjustment mode variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdjustmentMode {
    /// No change to confidence.
    NoChange,
    /// Boost confidence (positive delta).
    Boost,
    /// Penalize confidence (negative delta).
    Penalize,
    /// Flag for human review (no automatic adjustment).
    FlagForReview,
    /// Set confidence to a specific absolute value.
    Set,
}

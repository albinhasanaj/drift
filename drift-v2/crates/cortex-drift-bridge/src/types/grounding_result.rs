//! GroundingResult: full result of grounding a single memory against Drift scan data.

use serde::{Deserialize, Serialize};

use super::confidence_adjustment::ConfidenceAdjustment;
use super::grounding_verdict::GroundingVerdict;
use crate::grounding::GroundingEvidence;

/// Result of grounding a single memory against Drift scan data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundingResult {
    /// The memory being grounded.
    pub memory_id: String,
    /// The grounding verdict.
    pub verdict: GroundingVerdict,
    /// Grounding score: 0.0 (completely ungrounded) to 1.0 (fully grounded).
    pub grounding_score: f64,
    /// Previous grounding score (for trend detection).
    pub previous_score: Option<f64>,
    /// Score delta (current - previous). Negative = drifting.
    pub score_delta: Option<f64>,
    /// Confidence adjustment to apply to the memory.
    pub confidence_adjustment: ConfidenceAdjustment,
    /// Evidence supporting the grounding verdict.
    pub evidence: Vec<GroundingEvidence>,
    /// Whether a contradiction should be generated.
    pub generates_contradiction: bool,
    /// Duration of the grounding check in milliseconds.
    pub duration_ms: u32,
}

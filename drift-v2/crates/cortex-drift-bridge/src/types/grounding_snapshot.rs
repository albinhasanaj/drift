//! GroundingSnapshot: point-in-time summary of grounding state across all memories.

use serde::{Deserialize, Serialize};

/// Snapshot of grounding state across all groundable memories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundingSnapshot {
    pub total_checked: u32,
    pub validated: u32,
    pub partial: u32,
    pub weak: u32,
    pub invalidated: u32,
    pub not_groundable: u32,
    pub insufficient_data: u32,
    pub avg_grounding_score: f64,
    pub contradictions_generated: u32,
    pub duration_ms: u32,
    /// Number of non-fatal errors encountered during the grounding loop.
    /// Individual error details are collected via ErrorChain in the runner.
    #[serde(default)]
    pub error_count: u32,
    /// Trigger type that initiated this grounding loop.
    #[serde(default)]
    pub trigger_type: Option<String>,
}

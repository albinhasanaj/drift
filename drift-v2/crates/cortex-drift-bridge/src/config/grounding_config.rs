//! GroundingConfig: thresholds, intervals, limits for the grounding system.
//!
//! Extracted from grounding/mod.rs for centralized configuration.
//! Re-exported from grounding/mod.rs for backward compatibility.

/// Configuration for the grounding system.
#[derive(Debug, Clone)]
pub struct GroundingConfig {
    /// Whether grounding is enabled.
    pub enabled: bool,
    /// Maximum memories per grounding loop.
    pub max_memories_per_loop: usize,
    /// Confidence boost for validated memories.
    pub boost_delta: f64,
    /// Confidence penalty for partially grounded memories.
    pub partial_penalty: f64,
    /// Confidence penalty for weakly grounded memories.
    pub weak_penalty: f64,
    /// Minimum confidence floor (never zero).
    pub invalidated_floor: f64,
    /// Confidence drop for contradictions.
    pub contradiction_drop: f64,
    /// Full grounding every N scans.
    pub full_grounding_interval: u32,
}

impl Default for GroundingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_memories_per_loop: 500,
            boost_delta: 0.05,
            partial_penalty: 0.05,
            weak_penalty: 0.15,
            invalidated_floor: 0.1,
            contradiction_drop: 0.3,
            full_grounding_interval: 10,
        }
    }
}

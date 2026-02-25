//! Composite causal strength scoring with threshold for edge creation.

use cortex_core::memory::BaseMemory;

use super::strategies;

/// Default threshold: minimum composite score to create a causal edge.
pub const DEFAULT_EDGE_THRESHOLD: f64 = 0.3;

/// Breakdown of individual strategy scores.
#[derive(Debug, Clone)]
pub struct ScoreBreakdown {
    /// Per-strategy scores: (name, raw_score, weighted_score).
    pub strategy_scores: Vec<(&'static str, f64, f64)>,
    /// Final composite score (normalized).
    pub composite: f64,
    /// Whether this score exceeds the edge creation threshold.
    pub above_threshold: bool,
}

/// Compute the composite causal strength between two memories.
pub fn compute_composite(source: &BaseMemory, target: &BaseMemory) -> f64 {
    let strategies = strategies::all_strategies();
    let total_weight = strategies::total_weight();

    if total_weight == 0.0 {
        return 0.0;
    }

    let weighted_sum: f64 = strategies
        .iter()
        .map(|s| {
            let raw = (s.score_fn)(source, target);
            raw * s.weight
        })
        .sum();

    (weighted_sum / total_weight).clamp(0.0, 1.0)
}

/// Compute a full breakdown of all strategy scores.
pub fn compute_breakdown(
    source: &BaseMemory,
    target: &BaseMemory,
    threshold: f64,
) -> ScoreBreakdown {
    let strategies = strategies::all_strategies();
    let total_weight = strategies::total_weight();

    let mut strategy_scores = Vec::with_capacity(strategies.len());
    let mut weighted_sum = 0.0;

    for s in &strategies {
        let raw = (s.score_fn)(source, target);
        let weighted = raw * s.weight;
        weighted_sum += weighted;
        strategy_scores.push((s.name, raw, weighted));
    }

    let composite = if total_weight > 0.0 {
        (weighted_sum / total_weight).clamp(0.0, 1.0)
    } else {
        0.0
    };

    ScoreBreakdown {
        strategy_scores,
        composite,
        above_threshold: composite >= threshold,
    }
}

/// Check if two memories should have a causal edge created.
pub fn should_create_edge(source: &BaseMemory, target: &BaseMemory, threshold: f64) -> bool {
    compute_composite(source, target) >= threshold
}

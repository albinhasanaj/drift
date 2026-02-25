//! Strategy registry and weighted scoring for causal inference.

pub mod entity_overlap;
pub mod explicit_reference;
pub mod file_co_occurrence;
pub mod pattern_matching;
pub mod semantic_similarity;
pub mod temporal_proximity;

use cortex_core::memory::BaseMemory;

/// A named strategy with its weight.
pub struct StrategyEntry {
    pub name: &'static str,
    pub weight: f64,
    pub score_fn: fn(&BaseMemory, &BaseMemory) -> f64,
}

/// All registered strategies with their weights.
pub fn all_strategies() -> Vec<StrategyEntry> {
    vec![
        StrategyEntry {
            name: "temporal_proximity",
            weight: temporal_proximity::WEIGHT,
            score_fn: temporal_proximity::score,
        },
        StrategyEntry {
            name: "semantic_similarity",
            weight: semantic_similarity::WEIGHT,
            score_fn: semantic_similarity::score,
        },
        StrategyEntry {
            name: "entity_overlap",
            weight: entity_overlap::WEIGHT,
            score_fn: entity_overlap::score,
        },
        StrategyEntry {
            name: "explicit_reference",
            weight: explicit_reference::WEIGHT,
            score_fn: explicit_reference::score,
        },
        StrategyEntry {
            name: "pattern_matching",
            weight: pattern_matching::WEIGHT,
            score_fn: pattern_matching::score,
        },
        StrategyEntry {
            name: "file_co_occurrence",
            weight: file_co_occurrence::WEIGHT,
            score_fn: file_co_occurrence::score,
        },
    ]
}

/// Total weight across all strategies (for normalization).
pub fn total_weight() -> f64 {
    all_strategies().iter().map(|s| s.weight).sum()
}

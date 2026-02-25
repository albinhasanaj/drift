//! Phase 7: Gold layer refresh (materialized views in drift.db).
//!
//! Produces the final output suitable for persistence. In the full system,
//! this writes to drift.db via the batch writer. Here we prepare the data.

use super::types::AggregatedPattern;

/// Result of the gold layer refresh — ready for persistence.
#[derive(Debug, Clone)]
pub struct GoldLayerResult {
    /// Patterns that are new or modified (need INSERT/UPDATE).
    pub upserts: Vec<AggregatedPattern>,
    /// Pattern IDs that were merged away (need DELETE or mark as alias).
    pub merged_away: Vec<String>,
    /// Total pattern count after refresh.
    pub total_patterns: usize,
    /// Total location count across all patterns.
    pub total_locations: usize,
}

/// Prepare the gold layer output from aggregated patterns.
///
/// Separates dirty (modified) patterns for upsert and identifies
/// patterns that were merged into others.
pub fn prepare_gold_layer(patterns: &[AggregatedPattern]) -> GoldLayerResult {
    let mut upserts = Vec::new();
    let mut merged_away = Vec::new();
    let mut total_locations = 0usize;

    for pattern in patterns {
        // Patterns with a parent_id are merged children — mark for removal
        if let Some(ref hierarchy) = pattern.hierarchy {
            if hierarchy.parent_id.is_some() {
                merged_away.push(pattern.pattern_id.clone());
                continue;
            }
        }

        total_locations += pattern.location_count as usize;

        if pattern.is_dirty {
            upserts.push(pattern.clone());
        }
    }

    let total_patterns = patterns
        .iter()
        .filter(|p| {
            p.hierarchy
                .as_ref()
                .map(|h| h.parent_id.is_none())
                .unwrap_or(true)
        })
        .count();

    GoldLayerResult {
        upserts,
        merged_away,
        total_patterns,
        total_locations,
    }
}

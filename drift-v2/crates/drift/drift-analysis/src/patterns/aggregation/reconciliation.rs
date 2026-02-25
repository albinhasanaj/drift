//! Phase 6: Counter reconciliation.
//!
//! Recomputes cached counters (location_count, outlier_count, file_spread)
//! from the actual location data to ensure consistency after merges.

use drift_core::types::collections::FxHashSet;

use super::grouper::compute_mean_stddev;
use super::types::AggregatedPattern;

/// Reconcile all cached counters on an aggregated pattern.
///
/// After merges and hierarchy building, counters may be stale.
/// This recomputes them from the actual location data.
pub fn reconcile(pattern: &mut AggregatedPattern) {
    // Recompute location_count
    pattern.location_count = pattern.locations.len() as u32;

    // Recompute outlier_count
    pattern.outlier_count = pattern.locations.iter().filter(|l| l.is_outlier).count() as u32;

    // Recompute file_spread
    let mut files = FxHashSet::default();
    for loc in &pattern.locations {
        files.insert(loc.file.clone());
    }
    pattern.file_spread = files.len() as u32;

    // Recompute confidence statistics
    let mut vals: Vec<f64> = pattern.locations.iter().map(|l| l.confidence as f64).collect();
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let (mean, stddev) = compute_mean_stddev(&vals);
    pattern.confidence_mean = mean;
    pattern.confidence_stddev = stddev;
    pattern.confidence_values = vals;

    // Recompute location hash
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for loc in &pattern.locations {
        loc.file.hash(&mut hasher);
        loc.line.hash(&mut hasher);
        loc.column.hash(&mut hasher);
    }
    pattern.location_hash = hasher.finish();

    // Update hierarchy aggregated count if present
    if let Some(ref mut hierarchy) = pattern.hierarchy {
        hierarchy.aggregated_location_count = pattern.location_count;
    }
}

/// Reconcile all patterns in a collection.
pub fn reconcile_all(patterns: &mut [AggregatedPattern]) {
    for pattern in patterns.iter_mut() {
        reconcile(pattern);
    }
}

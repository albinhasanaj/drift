//! Incremental re-aggregation for changed files only.
//!
//! Content-hash aware: only re-aggregates patterns from files that changed
//! since the last aggregation pass.

use drift_core::types::collections::FxHashSet;

use crate::engine::types::PatternMatch;

use super::types::AggregatedPattern;

/// Filter matches to only include those from changed files.
///
/// `changed_files`: set of file paths that changed since last scan.
/// Returns only matches from those files.
pub fn filter_changed_matches<'a>(
    matches: &'a [PatternMatch],
    changed_files: &FxHashSet<String>,
) -> Vec<&'a PatternMatch> {
    matches
        .iter()
        .filter(|m| changed_files.contains(&m.file))
        .collect()
}

/// Determine which patterns need re-aggregation based on changed files.
///
/// A pattern needs re-aggregation if any of its locations are in changed files.
pub fn patterns_needing_reaggregation(
    existing_patterns: &[AggregatedPattern],
    changed_files: &FxHashSet<String>,
) -> FxHashSet<String> {
    let mut affected = FxHashSet::default();
    for pattern in existing_patterns {
        for loc in &pattern.locations {
            if changed_files.contains(&loc.file) {
                affected.insert(pattern.pattern_id.clone());
                break;
            }
        }
    }
    affected
}

/// Remove locations from changed files in existing patterns.
///
/// These will be re-added from the fresh match data.
pub fn remove_stale_locations(
    pattern: &mut AggregatedPattern,
    changed_files: &FxHashSet<String>,
) {
    pattern.locations.retain(|loc| !changed_files.contains(&loc.file));
    pattern.location_count = pattern.locations.len() as u32;
    pattern.is_dirty = true;
}

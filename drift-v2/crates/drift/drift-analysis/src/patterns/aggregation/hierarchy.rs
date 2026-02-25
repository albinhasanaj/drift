//! Phase 5: Parent-child pattern relationship building.
//!
//! After merging, builds a hierarchy where merged patterns become children
//! of the surviving (primary) pattern.

use drift_core::types::collections::FxHashMap;

use super::types::{AggregatedPattern, MergeCandidate, MergeDecision, PatternHierarchy};

/// Build parent-child hierarchies from merge candidates.
///
/// For each AutoMerge pair, the pattern with more locations becomes the parent.
/// The other becomes a child. The parent's hierarchy tracks all children and
/// aggregated location counts.
pub fn build_hierarchies(
    patterns: &mut FxHashMap<String, AggregatedPattern>,
    candidates: &[MergeCandidate],
) {
    for candidate in candidates {
        if candidate.decision != MergeDecision::AutoMerge {
            continue;
        }

        let (parent_id, child_id) = {
            let count_a = patterns.get(&candidate.pattern_a).map(|p| p.location_count).unwrap_or(0);
            let count_b = patterns.get(&candidate.pattern_b).map(|p| p.location_count).unwrap_or(0);
            if count_a >= count_b {
                (candidate.pattern_a.clone(), candidate.pattern_b.clone())
            } else {
                (candidate.pattern_b.clone(), candidate.pattern_a.clone())
            }
        };

        // Merge child into parent
        let child_locations = patterns.get(&child_id).map(|p| p.locations.clone()).unwrap_or_default();
        let child_pattern_id = child_id.clone();

        if let Some(parent) = patterns.get_mut(&parent_id) {
            // Add child locations to parent
            parent.locations.extend(child_locations);
            parent.location_count = parent.locations.len() as u32;
            parent.merged_from.push(child_pattern_id.clone());
            parent.aliases.push(child_pattern_id.clone());
            parent.is_dirty = true;

            // Recompute file spread
            let mut files = drift_core::types::collections::FxHashSet::default();
            for loc in &parent.locations {
                files.insert(loc.file.clone());
            }
            parent.file_spread = files.len() as u32;

            // Build/update hierarchy
            let hierarchy = parent.hierarchy.get_or_insert_with(|| PatternHierarchy {
                parent_id: None,
                child_ids: Vec::new(),
                aggregated_location_count: 0,
            });
            hierarchy.child_ids.push(child_pattern_id);
            hierarchy.aggregated_location_count = parent.location_count;
        }

        // Mark child with parent reference (don't remove — keep for audit trail)
        if let Some(child) = patterns.get_mut(&child_id) {
            child.hierarchy = Some(PatternHierarchy {
                parent_id: Some(parent_id.clone()),
                child_ids: Vec::new(),
                aggregated_location_count: child.location_count,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::types::PatternCategory;
    use crate::patterns::aggregation::types::PatternLocation;

    fn make_pattern(id: &str, n_locations: u32) -> AggregatedPattern {
        let locations: Vec<PatternLocation> = (0..n_locations)
            .map(|i| PatternLocation {
                file: format!("file_{}.ts", i),
                line: i + 1,
                column: 0,
                confidence: 0.9,
                is_outlier: false,
                matched_text: None,
            })
            .collect();
        AggregatedPattern {
            pattern_id: id.to_string(),
            category: PatternCategory::Structural,
            location_count: n_locations,
            outlier_count: 0,
            file_spread: n_locations,
            hierarchy: None,
            locations,
            aliases: Vec::new(),
            merged_from: Vec::new(),
            confidence_mean: 0.9,
            confidence_stddev: 0.0,
            confidence_values: vec![0.9; n_locations as usize],
            is_dirty: false,
            location_hash: 0,
        }
    }

    #[test]
    fn test_build_hierarchies_auto_merge() {
        let mut patterns = FxHashMap::default();
        patterns.insert("a".to_string(), make_pattern("a", 10));
        patterns.insert("b".to_string(), make_pattern("b", 5));

        let candidates = vec![MergeCandidate {
            pattern_a: "a".to_string(),
            pattern_b: "b".to_string(),
            similarity: 0.96,
            decision: MergeDecision::AutoMerge,
        }];

        build_hierarchies(&mut patterns, &candidates);

        let parent = patterns.get("a").unwrap();
        assert_eq!(parent.location_count, 15);
        assert!(parent.merged_from.contains(&"b".to_string()));
        assert!(parent.hierarchy.is_some());
        assert!(parent.hierarchy.as_ref().unwrap().child_ids.contains(&"b".to_string()));
    }
}

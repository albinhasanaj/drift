//! Phase 1-2: Group by pattern ID + cross-file merging.
//!
//! Buckets per-file PatternMatch results by pattern_id using FxHashMap,
//! collects all locations per pattern across files, and deduplicates
//! by exact location (file:line:column).

use drift_core::types::collections::FxHashMap;

use crate::engine::types::PatternMatch;

use super::types::{AggregatedPattern, PatternLocation};

/// Groups per-file pattern matches into project-level aggregated patterns.
pub struct PatternGrouper;

impl PatternGrouper {
    /// Phase 1-2: Group matches by pattern_id, merge cross-file, deduplicate locations.
    ///
    /// Input: flat list of PatternMatch from all files.
    /// Output: map of pattern_id → AggregatedPattern with deduplicated locations.
    pub fn group(matches: &[PatternMatch]) -> FxHashMap<String, AggregatedPattern> {
        let mut groups: FxHashMap<String, Vec<&PatternMatch>> = FxHashMap::default();

        // Phase 1: Bucket by pattern_id
        for m in matches {
            groups.entry(m.pattern_id.clone()).or_default().push(m);
        }

        // Phase 2: Build AggregatedPattern per group with deduplication
        let mut result = FxHashMap::default();
        for (pattern_id, group_matches) in groups {
            let pattern = Self::build_aggregated(&pattern_id, &group_matches);
            result.insert(pattern_id, pattern);
        }

        result
    }

    /// Build an AggregatedPattern from a group of matches sharing the same pattern_id.
    fn build_aggregated(pattern_id: &str, matches: &[&PatternMatch]) -> AggregatedPattern {
        // Deduplicate by exact location (file:line:column)
        let mut seen = FxHashMap::default();
        let mut locations = Vec::new();

        for m in matches {
            let key = format!("{}:{}:{}", m.file, m.line, m.column);
            if let Some(existing_idx) = seen.get(&key) {
                // Keep higher confidence on collision
                let existing: &mut PatternLocation = &mut locations[*existing_idx];
                if m.confidence > existing.confidence {
                    existing.confidence = m.confidence;
                }
            } else {
                seen.insert(key, locations.len());
                locations.push(PatternLocation {
                    file: m.file.clone(),
                    line: m.line,
                    column: m.column,
                    confidence: m.confidence,
                    is_outlier: false,
                    matched_text: Some(m.matched_text.clone()),
                });
            }
        }

        // Compute file spread
        let mut files = drift_core::types::collections::FxHashSet::default();
        for loc in &locations {
            files.insert(loc.file.clone());
        }

        // Compute confidence statistics
        let confidence_values: Vec<f64> = {
            let mut vals: Vec<f64> = locations.iter().map(|l| l.confidence as f64).collect();
            vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            vals
        };

        let (mean, stddev) = compute_mean_stddev(&confidence_values);

        // Compute location hash for change detection
        let location_hash = compute_location_hash(&locations);

        let category = matches
            .first()
            .map(|m| m.category)
            .unwrap_or_default();

        AggregatedPattern {
            pattern_id: pattern_id.to_string(),
            category,
            location_count: locations.len() as u32,
            outlier_count: 0,
            file_spread: files.len() as u32,
            hierarchy: None,
            locations,
            aliases: Vec::new(),
            merged_from: Vec::new(),
            confidence_mean: mean,
            confidence_stddev: stddev,
            confidence_values,
            is_dirty: true,
            location_hash,
        }
    }
}

/// Compute mean and standard deviation of a slice of f64 values.
pub fn compute_mean_stddev(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    if values.len() == 1 {
        return (mean, 0.0);
    }
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
    let stddev = if variance.is_finite() && variance >= 0.0 {
        variance.sqrt()
    } else {
        0.0
    };
    (mean, stddev)
}

/// Compute a hash of the location set for change detection.
fn compute_location_hash(locations: &[PatternLocation]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for loc in locations {
        loc.file.hash(&mut hasher);
        loc.line.hash(&mut hasher);
        loc.column.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mean_stddev_empty() {
        let (m, s) = compute_mean_stddev(&[]);
        assert_eq!(m, 0.0);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn test_mean_stddev_single() {
        let (m, s) = compute_mean_stddev(&[0.5]);
        assert!((m - 0.5).abs() < 1e-10);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn test_mean_stddev_multiple() {
        let (m, _s) = compute_mean_stddev(&[0.2, 0.4, 0.6, 0.8]);
        assert!((m - 0.5).abs() < 1e-10);
    }
}

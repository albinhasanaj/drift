//! Three-tier Jaccard duplicate detection.

use std::collections::HashSet;

use super::types::*;

/// Duplicate detector using Jaccard similarity on pattern location sets.
pub struct DuplicateDetector {
    /// Threshold for auto-merge (>0.95).
    pub auto_merge_threshold: f64,
    /// Threshold for recommended merge (>0.90).
    pub merge_threshold: f64,
    /// Threshold for human review (>0.85).
    pub review_threshold: f64,
}

impl DuplicateDetector {
    pub fn new() -> Self {
        Self {
            auto_merge_threshold: 0.95,
            merge_threshold: 0.90,
            review_threshold: 0.85,
        }
    }

    /// Detect duplicate patterns using Jaccard similarity on location sets.
    /// Only compares patterns within the same category.
    pub fn detect(&self, patterns: &[PatternAuditData]) -> Vec<DuplicateGroup> {
        let mut groups = Vec::new();

        // Group by category first
        let mut by_category: std::collections::HashMap<&str, Vec<&PatternAuditData>> =
            std::collections::HashMap::new();
        for p in patterns {
            by_category.entry(&p.category).or_default().push(p);
        }

        for cat_patterns in by_category.values() {
            let n = cat_patterns.len();
            for i in 0..n {
                for j in (i + 1)..n {
                    let sim = self.jaccard_similarity(cat_patterns[i], cat_patterns[j]);
                    if sim >= self.review_threshold {
                        let action = if sim > self.auto_merge_threshold {
                            DuplicateAction::AutoMerge
                        } else if sim > self.merge_threshold {
                            DuplicateAction::Merge
                        } else {
                            DuplicateAction::Review
                        };

                        groups.push(DuplicateGroup {
                            pattern_ids: vec![
                                cat_patterns[i].id.clone(),
                                cat_patterns[j].id.clone(),
                            ],
                            similarity: sim,
                            action,
                        });
                    }
                }
            }
        }

        groups
    }

    /// Compute Jaccard similarity between two patterns based on their locations.
    /// Uses real set intersection when location data is available, otherwise
    /// falls back to count-ratio proxy.
    fn jaccard_similarity(&self, a: &PatternAuditData, b: &PatternAuditData) -> f64 {
        // Use real Jaccard when both patterns have location data
        if !a.locations.is_empty() && !b.locations.is_empty() {
            let set_a: HashSet<&str> = a.locations.iter().map(|s| s.as_str()).collect();
            let set_b: HashSet<&str> = b.locations.iter().map(|s| s.as_str()).collect();
            let intersection = set_a.intersection(&set_b).count();
            let union = set_a.union(&set_b).count();
            if union == 0 {
                return 0.0;
            }
            return intersection as f64 / union as f64;
        }

        // Fallback: count-ratio proxy when locations are not available
        let a_count = a.location_count;
        let b_count = b.location_count;

        if a_count == 0 && b_count == 0 {
            return 0.0;
        }

        let min_count = a_count.min(b_count) as f64;
        let max_count = a_count.max(b_count) as f64;

        if max_count == 0.0 {
            return 0.0;
        }

        min_count / max_count
    }

    /// Compute exact Jaccard similarity between two sets of location strings.
    pub fn jaccard_from_sets(set_a: &HashSet<String>, set_b: &HashSet<String>) -> f64 {
        if set_a.is_empty() && set_b.is_empty() {
            return 0.0;
        }
        let intersection = set_a.intersection(set_b).count();
        let union = set_a.union(set_b).count();
        if union == 0 {
            return 0.0;
        }
        intersection as f64 / union as f64
    }
}

impl Default for DuplicateDetector {
    fn default() -> Self {
        Self::new()
    }
}

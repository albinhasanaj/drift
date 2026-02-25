//! Top-level 8-phase aggregation pipeline orchestrator.
//!
//! Phase A hardening: outlier detection wired between reconciliation and gold layer,
//! incremental runs detect duplicates and outliers, diagnostics emitted.

use std::collections::HashMap;
use std::fmt;

use drift_core::types::collections::{FxHashMap, FxHashSet};

use crate::engine::types::{PatternCategory, PatternMatch};
use crate::patterns::outliers::conversion::{self, OutlierViolation};
use crate::patterns::outliers::selector::OutlierDetector;

use super::gold_layer::{self, GoldLayerResult};
use super::grouper::PatternGrouper;
use super::hierarchy;
use super::incremental;
use super::reconciliation;
use super::similarity::{self, location_key_set, MinHashIndex};
use super::types::{AggregatedPattern, AggregationConfig, MergeCandidate, MergeDecision};

/// The 8-phase aggregation pipeline.
pub struct AggregationPipeline {
    config: AggregationConfig,
    outlier_detector: OutlierDetector,
}

impl AggregationPipeline {
    /// Create a new pipeline with the given configuration.
    pub fn new(config: AggregationConfig) -> Self {
        Self {
            config,
            outlier_detector: OutlierDetector::new(),
        }
    }

    /// Create a pipeline with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AggregationConfig::default())
    }

    /// Run the full 8-phase aggregation pipeline.
    ///
    /// Input: flat list of PatternMatch from all files.
    /// Output: list of AggregatedPattern ready for downstream consumption.
    pub fn run(&self, matches: &[PatternMatch]) -> AggregationResult {
        let raw_match_count = matches.len();

        // Phase 1-2: Group by pattern ID + cross-file merging + dedup
        let mut grouped = PatternGrouper::group(matches);

        // Phase 3-4: Near-duplicate detection
        let patterns_vec: Vec<&AggregatedPattern> = grouped.values().collect();
        let candidates = self.detect_duplicates(&patterns_vec);

        // Phase 5: Hierarchy building (merge auto-merge candidates)
        hierarchy::build_hierarchies(&mut grouped, &candidates);

        // Phase 6: Counter reconciliation
        for pattern in grouped.values_mut() {
            reconciliation::reconcile(pattern);
        }

        // Phase 6.5: Outlier detection (PI-AGG-01)
        let violations = self.run_outlier_detection(grouped.values_mut());

        // Re-reconcile outlier_count after marking outliers
        for pattern in grouped.values_mut() {
            pattern.outlier_count = pattern.locations.iter().filter(|l| l.is_outlier).count() as u32;
        }

        // Phase 7: Gold layer refresh
        let all_patterns: Vec<AggregatedPattern> = grouped.into_values().collect();
        let gold = gold_layer::prepare_gold_layer(&all_patterns);

        // Phase 8: Diagnostics (PI-AGG-08/09/10)
        let diagnostics = Self::compute_diagnostics(&all_patterns, raw_match_count, &candidates);

        AggregationResult {
            patterns: all_patterns,
            merge_candidates: candidates,
            gold_layer: gold,
            violations,
            diagnostics,
        }
    }

    /// Run incremental aggregation — only re-aggregate changed files.
    pub fn run_incremental(
        &self,
        matches: &[PatternMatch],
        existing_patterns: &mut Vec<AggregatedPattern>,
        changed_files: &FxHashSet<String>,
    ) -> AggregationResult {
        let raw_match_count = matches.len();

        // Filter to only changed file matches
        let changed_matches: Vec<PatternMatch> = matches
            .iter()
            .filter(|m| changed_files.contains(&m.file))
            .cloned()
            .collect();

        // Remove stale locations from existing patterns
        let affected_ids = incremental::patterns_needing_reaggregation(existing_patterns, changed_files);
        for pattern in existing_patterns.iter_mut() {
            if affected_ids.contains(&pattern.pattern_id) {
                incremental::remove_stale_locations(pattern, changed_files);
            }
        }

        // Group the new matches
        let new_grouped = PatternGrouper::group(&changed_matches);

        // Merge new data into existing patterns
        let mut all_patterns: FxHashMap<String, AggregatedPattern> = existing_patterns
            .drain(..)
            .map(|p| (p.pattern_id.clone(), p))
            .collect();

        for (id, new_pattern) in new_grouped {
            if let Some(existing) = all_patterns.get_mut(&id) {
                existing.locations.extend(new_pattern.locations);
                existing.is_dirty = true;
            } else {
                all_patterns.insert(id, new_pattern);
            }
        }

        // Reconcile all affected patterns
        for pattern in all_patterns.values_mut() {
            reconciliation::reconcile(pattern);
        }

        // PI-AGG-04: Run similarity detection on affected + new patterns
        let affected_patterns: Vec<&AggregatedPattern> = all_patterns
            .values()
            .filter(|p| p.is_dirty)
            .collect();
        let candidates = if !affected_patterns.is_empty() {
            self.detect_duplicates(&affected_patterns)
        } else {
            Vec::new()
        };

        // PI-AGG-05: Run outlier detection on affected patterns
        let violations = self.run_outlier_detection(
            all_patterns.values_mut().filter(|p| p.is_dirty)
        );

        // Re-reconcile outlier_count
        for pattern in all_patterns.values_mut() {
            if pattern.is_dirty {
                pattern.outlier_count = pattern.locations.iter().filter(|l| l.is_outlier).count() as u32;
            }
        }

        let patterns: Vec<AggregatedPattern> = all_patterns.into_values().collect();
        let gold = gold_layer::prepare_gold_layer(&patterns);
        let diagnostics = Self::compute_diagnostics(&patterns, raw_match_count, &candidates);

        AggregationResult {
            patterns,
            merge_candidates: candidates,
            gold_layer: gold,
            violations,
            diagnostics,
        }
    }

    /// Phase 3-4: Detect near-duplicate patterns.
    fn detect_duplicates(&self, patterns: &[&AggregatedPattern]) -> Vec<MergeCandidate> {
        let n = patterns.len();
        let use_minhash = self.config.minhash_enabled
            || (n > self.config.minhash_auto_threshold);

        if use_minhash {
            self.detect_duplicates_minhash(patterns)
        } else {
            similarity::find_duplicates(
                patterns,
                self.config.duplicate_flag_threshold,
                self.config.auto_merge_threshold,
            )
        }
    }

    /// Run outlier detection on each pattern's confidence_values.
    /// Marks PatternLocation.is_outlier and returns violations.
    fn run_outlier_detection<'a>(
        &self,
        patterns: impl Iterator<Item = &'a mut AggregatedPattern>,
    ) -> Vec<OutlierViolation> {
        let mut all_violations = Vec::new();

        for pattern in patterns {
            if pattern.confidence_values.len() < 2 {
                continue;
            }

            let results = self.outlier_detector.detect(&pattern.confidence_values);

            // Mark locations as outliers
            for result in &results {
                if result.is_outlier {
                    if let Some(loc) = pattern.locations.get_mut(result.index) {
                        loc.is_outlier = true;
                    }
                }
            }

            // Convert to violations (PI-AGG-03)
            let file_line_map: Vec<(String, u32)> = pattern
                .locations
                .iter()
                .map(|l| (l.file.clone(), l.line))
                .collect();

            let violations = conversion::convert_to_violations(
                &pattern.pattern_id,
                &results,
                &file_line_map,
            );
            all_violations.extend(violations);
        }

        all_violations
    }

    /// Compute aggregation diagnostics (PI-AGG-08/09/10).
    fn compute_diagnostics(
        patterns: &[AggregatedPattern],
        raw_match_count: usize,
        candidates: &[MergeCandidate],
    ) -> AggregationDiagnostics {
        let total_patterns = patterns.len();
        let total_locations: usize = patterns.iter().map(|p| p.location_count as usize).sum();
        let total_outliers: usize = patterns.iter().map(|p| p.outlier_count as usize).sum();

        let mut patterns_per_category: HashMap<PatternCategory, usize> = HashMap::new();
        let mut multi_file_count = 0usize;
        let mut single_file_count = 0usize;

        for p in patterns {
            *patterns_per_category.entry(p.category).or_insert(0) += 1;
            if p.file_spread > 1 {
                multi_file_count += 1;
            } else {
                single_file_count += 1;
            }
        }

        let dedup_ratio = if raw_match_count > 0 {
            1.0 - (total_locations as f64 / raw_match_count as f64)
        } else {
            0.0
        };

        let single_file_warning = total_patterns > 0
            && (single_file_count as f64 / total_patterns as f64) > 0.9;
        let low_dedup_warning = raw_match_count > 10 && dedup_ratio < 0.05;

        AggregationDiagnostics {
            total_patterns,
            total_locations,
            total_outliers,
            merge_candidate_count: candidates.len(),
            patterns_per_category,
            multi_file_patterns: multi_file_count,
            single_file_patterns: single_file_count,
            single_file_warning,
            raw_match_count,
            dedup_ratio,
            low_dedup_warning,
        }
    }

    /// MinHash LSH-based duplicate detection for large pattern sets.
    fn detect_duplicates_minhash(&self, patterns: &[&AggregatedPattern]) -> Vec<MergeCandidate> {
        let mut index = MinHashIndex::new(self.config.minhash_num_perm, self.config.minhash_num_bands);

        // Build index
        for pattern in patterns {
            let key_set = location_key_set(pattern);
            index.insert(&pattern.pattern_id, &key_set);
        }

        // Find candidates and verify with estimated similarity
        let raw_candidates = index.find_candidates();
        let mut candidates = Vec::new();

        for (id_a, id_b) in raw_candidates {
            if let Some(sim) = index.estimate_similarity(&id_a, &id_b) {
                if sim >= self.config.duplicate_flag_threshold {
                    let decision = MergeDecision::from_similarity(sim);
                    candidates.push(MergeCandidate {
                        pattern_a: id_a,
                        pattern_b: id_b,
                        similarity: sim,
                        decision,
                    });
                }
            }
        }

        candidates
    }
}

/// Result of the aggregation pipeline.
#[derive(Debug)]
pub struct AggregationResult {
    /// All aggregated patterns (including merged children for audit trail).
    pub patterns: Vec<AggregatedPattern>,
    /// Merge candidates detected during similarity analysis.
    pub merge_candidates: Vec<MergeCandidate>,
    /// Gold layer output ready for persistence.
    pub gold_layer: GoldLayerResult,
    /// Outlier violations detected during aggregation.
    pub violations: Vec<OutlierViolation>,
    /// Aggregation diagnostics.
    pub diagnostics: AggregationDiagnostics,
}

/// Diagnostics summary for the aggregation pipeline.
#[derive(Debug, Clone)]
pub struct AggregationDiagnostics {
    /// Total aggregated patterns.
    pub total_patterns: usize,
    /// Total deduplicated locations across all patterns.
    pub total_locations: usize,
    /// Total outlier locations.
    pub total_outliers: usize,
    /// Number of merge candidates detected.
    pub merge_candidate_count: usize,
    /// Patterns per category.
    pub patterns_per_category: HashMap<PatternCategory, usize>,
    /// Patterns appearing in multiple files.
    pub multi_file_patterns: usize,
    /// Patterns appearing in only one file.
    pub single_file_patterns: usize,
    /// Warning: >90% of patterns are single-file.
    pub single_file_warning: bool,
    /// Raw match count before deduplication.
    pub raw_match_count: usize,
    /// Dedup ratio: 1 - (deduplicated / raw). Higher = more dedup.
    pub dedup_ratio: f64,
    /// Warning: dedup ratio < 5% (dedup not effective).
    pub low_dedup_warning: bool,
}

impl fmt::Display for AggregationDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AggregationDiagnostics {{ patterns={}, locations={}, outliers={}, merges={}, dedup_ratio={:.1}%, single_file_warn={}, low_dedup_warn={} }}",
            self.total_patterns,
            self.total_locations,
            self.total_outliers,
            self.merge_candidate_count,
            self.dedup_ratio * 100.0,
            self.single_file_warning,
            self.low_dedup_warning,
        )
    }
}

impl AggregationResult {
    /// Get only the top-level patterns (excluding merged children).
    pub fn top_level_patterns(&self) -> Vec<&AggregatedPattern> {
        self.patterns
            .iter()
            .filter(|p| {
                p.hierarchy
                    .as_ref()
                    .map(|h| h.parent_id.is_none())
                    .unwrap_or(true)
            })
            .collect()
    }
}

//! Framework diagnostics — collects load, match, and learning metrics.

use std::collections::HashMap;
use std::time::Duration;

/// Aggregated diagnostics from the framework definition system.
#[derive(Debug, Clone, Default)]
pub struct FrameworkDiagnostics {
    pub builtin_packs_loaded: usize,
    pub builtin_packs_skipped: usize,
    pub custom_packs_loaded: usize,
    pub custom_packs_skipped: usize,
    pub total_patterns_compiled: usize,
    pub patterns_skipped: usize,
    pub files_processed: usize,
    pub files_matched: usize,
    pub total_hits: usize,
    pub hits_per_category: HashMap<String, usize>,
    pub hits_per_pack: HashMap<String, usize>,
    pub frameworks_detected: Vec<String>,
    pub learning_groups: usize,
    pub learning_deviations: usize,
    pub files_truncated: usize,
    pub pack_versions: HashMap<String, String>,
    pub load_duration: Duration,
    pub match_duration: Duration,
    pub learn_duration: Duration,
}

impl FrameworkDiagnostics {
    /// Merge another diagnostics into this one (additive).
    pub fn merge(&mut self, other: &FrameworkDiagnostics) {
        self.builtin_packs_loaded += other.builtin_packs_loaded;
        self.builtin_packs_skipped += other.builtin_packs_skipped;
        self.custom_packs_loaded += other.custom_packs_loaded;
        self.custom_packs_skipped += other.custom_packs_skipped;
        self.total_patterns_compiled += other.total_patterns_compiled;
        self.patterns_skipped += other.patterns_skipped;
        self.files_processed += other.files_processed;
        self.files_matched += other.files_matched;
        self.total_hits += other.total_hits;
        for (k, v) in &other.hits_per_category {
            *self.hits_per_category.entry(k.clone()).or_insert(0) += v;
        }
        for (k, v) in &other.hits_per_pack {
            *self.hits_per_pack.entry(k.clone()).or_insert(0) += v;
        }
        self.frameworks_detected.extend(other.frameworks_detected.iter().cloned());
        self.learning_groups += other.learning_groups;
        self.learning_deviations += other.learning_deviations;
        self.files_truncated += other.files_truncated;
        for (k, v) in &other.pack_versions {
            self.pack_versions.entry(k.clone()).or_insert_with(|| v.clone());
        }
        self.load_duration += other.load_duration;
        self.match_duration += other.match_duration;
        self.learn_duration += other.learn_duration;
    }

    /// Format a summary line matching the V2 logging pattern.
    pub fn summary(&self) -> String {
        format!(
            "[drift-analyze] framework diagnostics: {} packs ({} builtin, {} custom), \
             {} patterns, {} files processed, {} hits, {} deviations",
            self.builtin_packs_loaded + self.custom_packs_loaded,
            self.builtin_packs_loaded,
            self.custom_packs_loaded,
            self.total_patterns_compiled,
            self.files_processed,
            self.total_hits,
            self.learning_deviations,
        )
    }
}

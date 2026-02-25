//! Core types for pattern aggregation.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine::types::PatternCategory;

/// A project-level aggregated pattern — the primary output of the aggregation pipeline.
#[derive(Debug, Clone)]
pub struct AggregatedPattern {
    /// Canonical pattern ID (string-based for cross-system compatibility).
    pub pattern_id: String,
    /// Category of the pattern.
    pub category: PatternCategory,
    /// Total deduplicated location count.
    pub location_count: u32,
    /// Number of locations flagged as outliers.
    pub outlier_count: u32,
    /// Number of unique files containing this pattern.
    pub file_spread: u32,
    /// Parent-child hierarchy (if part of a pattern group).
    pub hierarchy: Option<PatternHierarchy>,
    /// All deduplicated locations.
    pub locations: Vec<PatternLocation>,
    /// Aliases from merged patterns.
    pub aliases: Vec<String>,
    /// Pattern IDs that were merged into this one.
    pub merged_from: Vec<String>,
    /// Confidence statistics across locations.
    pub confidence_mean: f64,
    pub confidence_stddev: f64,
    /// Confidence values for downstream outlier detection (sorted ascending).
    pub confidence_values: Vec<f64>,
    /// Whether this pattern was modified in the current aggregation pass.
    pub is_dirty: bool,
    /// Location set hash for change detection.
    pub location_hash: u64,
}

impl AggregatedPattern {
    /// Outlier rate: outlier_count / location_count.
    pub fn outlier_rate(&self) -> f64 {
        if self.location_count == 0 {
            return 0.0;
        }
        self.outlier_count as f64 / self.location_count as f64
    }
}

/// A single location within an aggregated pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub confidence: f32,
    pub is_outlier: bool,
    pub matched_text: Option<String>,
}

/// Parent-child pattern hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternHierarchy {
    pub parent_id: Option<String>,
    pub child_ids: Vec<String>,
    pub aggregated_location_count: u32,
}

/// A candidate pair for merging based on similarity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeCandidate {
    pub pattern_a: String,
    pub pattern_b: String,
    pub similarity: f64,
    pub decision: MergeDecision,
}

/// Decision for a merge candidate pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MergeDecision {
    /// similarity ≥ 0.95 — automatically merged.
    AutoMerge,
    /// 0.85 ≤ similarity < 0.95 — flagged for review.
    FlagReview,
    /// similarity < 0.85 — kept separate.
    Separate,
}

impl MergeDecision {
    /// Classify a similarity score into a merge decision.
    pub fn from_similarity(similarity: f64) -> Self {
        if similarity >= 0.95 {
            Self::AutoMerge
        } else if similarity >= 0.85 {
            Self::FlagReview
        } else {
            Self::Separate
        }
    }
}

impl fmt::Display for MergeDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AutoMerge => write!(f, "auto_merge"),
            Self::FlagReview => write!(f, "flag_review"),
            Self::Separate => write!(f, "separate"),
        }
    }
}

/// Configuration for the aggregation pipeline.
#[derive(Debug, Clone)]
pub struct AggregationConfig {
    /// Jaccard similarity threshold for flagging potential duplicates (default: 0.85).
    pub duplicate_flag_threshold: f64,
    /// Jaccard similarity threshold for automatic merging (default: 0.95).
    pub auto_merge_threshold: f64,
    /// Whether to enable MinHash LSH for scalable dedup (default: false, auto at >50K).
    pub minhash_enabled: bool,
    /// Number of MinHash permutations (default: 128).
    pub minhash_num_perm: usize,
    /// Number of LSH bands (default: 32).
    pub minhash_num_bands: usize,
    /// Threshold for auto-enabling MinHash (default: 50_000).
    pub minhash_auto_threshold: usize,
    /// Whether to run incrementally (default: true).
    pub incremental: bool,
    /// Maximum locations per pattern (default: 10_000).
    pub max_locations_per_pattern: usize,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            duplicate_flag_threshold: 0.85,
            auto_merge_threshold: 0.95,
            minhash_enabled: false,
            minhash_num_perm: 128,
            minhash_num_bands: 32,
            minhash_auto_threshold: 50_000,
            incremental: true,
            max_locations_per_pattern: 10_000,
        }
    }
}

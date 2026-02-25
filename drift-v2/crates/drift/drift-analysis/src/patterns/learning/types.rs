//! Core types for the learning system.
//!
//! Phase D hardening: ConventionStore trait, observation tracking,
//! convergence metrics, learning diagnostics.

use std::collections::HashMap;
use std::fmt;

use drift_core::types::collections::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::patterns::confidence::types::ConfidenceScore;

/// A discovered convention.
#[derive(Debug, Clone)]
pub struct Convention {
    /// Unique convention ID.
    pub id: String,
    /// Pattern ID this convention is based on.
    pub pattern_id: String,
    /// Convention category.
    pub category: ConventionCategory,
    /// Scope of the convention.
    pub scope: ConventionScope,
    /// Confidence score from Bayesian scoring.
    pub confidence_score: ConfidenceScore,
    /// Dominance ratio: this pattern's frequency / total alternatives.
    pub dominance_ratio: f64,
    /// Unix timestamp of discovery.
    pub discovery_date: u64,
    /// Unix timestamp of last observation.
    pub last_seen: u64,
    /// Current promotion status.
    pub promotion_status: PromotionStatus,
    /// Number of times this pattern has been observed across all scans.
    pub observation_count: u64,
    /// Number of scans that have seen this pattern.
    pub scan_count: u64,
}

/// Convergence score for a convention: 1.0 - (ci_width / 2.0).
/// Higher = more converged (narrower CI).
impl Convention {
    /// Compute convergence score from credible interval width.
    pub fn convergence_score(&self) -> f64 {
        let ci_width = self.confidence_score.credible_interval.1
            - self.confidence_score.credible_interval.0;
        (1.0 - ci_width / 2.0).clamp(0.0, 1.0)
    }
}

/// Trait for persisting conventions across runs.
pub trait ConventionStore: Send + Sync {
    /// Load all conventions.
    fn load_all(&self) -> Vec<Convention>;
    /// Save a convention (insert or update).
    fn save(&mut self, convention: &Convention);
    /// Load a convention by pattern_id.
    fn load_by_pattern_id(&self, pattern_id: &str) -> Option<Convention>;
}

/// In-memory implementation of ConventionStore for tests.
#[derive(Debug, Default)]
pub struct InMemoryConventionStore {
    conventions: FxHashMap<String, Convention>,
}

impl InMemoryConventionStore {
    pub fn new() -> Self {
        Self {
            conventions: FxHashMap::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.conventions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.conventions.is_empty()
    }
}

impl ConventionStore for InMemoryConventionStore {
    fn load_all(&self) -> Vec<Convention> {
        self.conventions.values().cloned().collect()
    }

    fn save(&mut self, convention: &Convention) {
        self.conventions
            .insert(convention.pattern_id.clone(), convention.clone());
    }

    fn load_by_pattern_id(&self, pattern_id: &str) -> Option<Convention> {
        self.conventions.get(pattern_id).cloned()
    }
}

/// Diagnostics for the learning system.
#[derive(Debug, Clone)]
pub struct LearningDiagnostics {
    /// Total conventions discovered.
    pub total_conventions: usize,
    /// Conventions per category.
    pub per_category: HashMap<ConventionCategory, usize>,
    /// Conventions per promotion status.
    pub per_status: HashMap<PromotionStatus, usize>,
    /// Average convergence score.
    pub avg_convergence: f64,
    /// Number of converged conventions (convergence > 0.8).
    pub converged_count: usize,
    /// Number of contested conventions.
    pub contested_count: usize,
}

/// Convention categories based on spread and consistency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConventionCategory {
    /// High spread (≥80% of files), high confidence (Established tier).
    Universal,
    /// Moderate spread, project-scoped.
    ProjectSpecific,
    /// Rising momentum, growing adoption.
    Emerging,
    /// Falling momentum, declining usage.
    Legacy,
    /// Two patterns within 15% frequency of each other.
    Contested,
}

impl ConventionCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Universal => "universal",
            Self::ProjectSpecific => "project_specific",
            Self::Emerging => "emerging",
            Self::Legacy => "legacy",
            Self::Contested => "contested",
        }
    }
}

impl fmt::Display for ConventionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Scope of a convention.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConventionScope {
    /// Applies to the entire project.
    Project,
    /// Applies to a specific directory.
    Directory(String),
    /// Applies to a specific package/module.
    Package(String),
}

impl ConventionScope {
    pub fn name(&self) -> &str {
        match self {
            Self::Project => "project",
            Self::Directory(d) => d,
            Self::Package(p) => p,
        }
    }
}

impl fmt::Display for ConventionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Project => write!(f, "project"),
            Self::Directory(d) => write!(f, "directory:{}", d),
            Self::Package(p) => write!(f, "package:{}", p),
        }
    }
}

/// Promotion status lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PromotionStatus {
    /// Newly discovered, not yet promoted.
    Discovered,
    /// Promoted to enforced convention.
    Approved,
    /// Explicitly rejected by user.
    Rejected,
    /// Expired due to inactivity.
    Expired,
}

impl PromotionStatus {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

impl fmt::Display for PromotionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Configuration for the learning system.
#[derive(Debug, Clone)]
pub struct LearningConfig {
    /// Minimum occurrences for a pattern to be considered a convention.
    pub min_occurrences: u64,
    /// Minimum dominance ratio (pattern frequency / total alternatives).
    pub dominance_threshold: f64,
    /// Minimum files for a pattern to be considered.
    pub min_files: u64,
    /// Spread threshold for Universal classification (≥80%).
    pub universal_spread_threshold: f64,
    /// Contested threshold: two patterns within this % of each other.
    pub contested_threshold: f64,
    /// Days before a convention expires if not seen.
    pub expiry_days: u64,
    /// File change threshold for triggering re-learning (>10%).
    pub relearn_threshold: f64,
}

impl Default for LearningConfig {
    fn default() -> Self {
        Self {
            min_occurrences: 3,
            dominance_threshold: 0.60,
            min_files: 2,
            universal_spread_threshold: 0.80,
            contested_threshold: 0.15,
            expiry_days: 90,
            relearn_threshold: 0.10,
        }
    }
}

impl LearningDiagnostics {
    /// Compute diagnostics from a set of conventions.
    pub fn from_conventions(conventions: &[Convention]) -> Self {
        let mut per_category: HashMap<ConventionCategory, usize> = HashMap::new();
        let mut per_status: HashMap<PromotionStatus, usize> = HashMap::new();
        let mut total_convergence = 0.0;
        let mut converged_count = 0;
        let mut contested_count = 0;

        for c in conventions {
            *per_category.entry(c.category).or_insert(0) += 1;
            *per_status.entry(c.promotion_status).or_insert(0) += 1;
            let conv = c.convergence_score();
            total_convergence += conv;
            if conv > 0.8 {
                converged_count += 1;
            }
            if c.category == ConventionCategory::Contested {
                contested_count += 1;
            }
        }

        let avg_convergence = if conventions.is_empty() {
            0.0
        } else {
            total_convergence / conventions.len() as f64
        };

        Self {
            total_conventions: conventions.len(),
            per_category,
            per_status,
            avg_convergence,
            converged_count,
            contested_count,
        }
    }
}

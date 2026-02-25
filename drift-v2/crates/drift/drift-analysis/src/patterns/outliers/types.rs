//! Core types for outlier detection.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Result of outlier analysis for a single data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierResult {
    /// Index into the original values array.
    pub index: usize,
    /// The actual value that was flagged.
    pub value: f64,
    /// Test statistic (z-score, Grubbs' statistic, etc.).
    pub test_statistic: f64,
    /// Normalized deviation score [0.0, 1.0].
    pub deviation_score: DeviationScore,
    /// Significance tier.
    pub significance: SignificanceTier,
    /// Method that detected this outlier.
    pub method: OutlierMethod,
    /// Whether this is confirmed as an outlier.
    pub is_outlier: bool,
}

/// Normalized deviation score in [0.0, 1.0].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DeviationScore(f64);

impl DeviationScore {
    /// Create a new deviation score, clamped to [0.0, 1.0].
    pub fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    /// Get the raw value.
    pub fn value(&self) -> f64 {
        self.0
    }

    /// Zero deviation (not an outlier).
    pub fn zero() -> Self {
        Self(0.0)
    }
}

impl fmt::Display for DeviationScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.4}", self.0)
    }
}

/// Significance tiers for outlier results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignificanceTier {
    /// Extreme deviation — requires immediate attention.
    Critical,
    /// Strong deviation — should be reviewed.
    High,
    /// Moderate deviation — informational.
    Moderate,
    /// Mild deviation — low priority.
    Low,
}

impl SignificanceTier {
    /// Classify from a deviation score.
    pub fn from_deviation(score: f64) -> Self {
        if score >= 0.9 {
            Self::Critical
        } else if score >= 0.7 {
            Self::High
        } else if score >= 0.4 {
            Self::Moderate
        } else {
            Self::Low
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Moderate => "moderate",
            Self::Low => "low",
        }
    }
}

impl fmt::Display for SignificanceTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Statistical method used for outlier detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutlierMethod {
    ZScore,
    Grubbs,
    GeneralizedEsd,
    Iqr,
    Mad,
    RuleBased,
}

impl OutlierMethod {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ZScore => "z_score",
            Self::Grubbs => "grubbs",
            Self::GeneralizedEsd => "generalized_esd",
            Self::Iqr => "iqr",
            Self::Mad => "mad",
            Self::RuleBased => "rule_based",
        }
    }
}

impl fmt::Display for OutlierMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Configuration for outlier detection.
#[derive(Debug, Clone)]
pub struct OutlierConfig {
    /// Minimum sample size for statistical methods (default: 10).
    pub min_sample_size: usize,
    /// Z-Score threshold (default: 2.5).
    pub z_threshold: f64,
    /// Maximum Z-Score iterations (default: 3).
    pub max_iterations: usize,
    /// IQR multiplier for Tukey fences (default: 1.5).
    pub iqr_multiplier: f64,
    /// MAD threshold (default: 3.5).
    pub mad_threshold: f64,
    /// Significance level for Grubbs' and ESD tests (default: 0.05).
    pub alpha: f64,
}

impl Default for OutlierConfig {
    fn default() -> Self {
        Self {
            min_sample_size: 10,
            z_threshold: 2.5,
            max_iterations: 3,
            iqr_multiplier: 1.5,
            mad_threshold: 3.5,
            alpha: 0.05,
        }
    }
}

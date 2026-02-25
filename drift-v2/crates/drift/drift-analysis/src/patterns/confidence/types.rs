//! Core types for Bayesian confidence scoring.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A Bayesian confidence score with Beta distribution parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceScore {
    /// Alpha parameter of the Beta distribution (successes + prior).
    pub alpha: f64,
    /// Beta parameter of the Beta distribution (failures + prior).
    pub beta: f64,
    /// Posterior mean: alpha / (alpha + beta).
    pub posterior_mean: f64,
    /// 95% credible interval (low, high).
    pub credible_interval: (f64, f64),
    /// Graduated confidence tier.
    pub tier: ConfidenceTier,
    /// Momentum direction.
    pub momentum: MomentumDirection,
}

impl ConfidenceScore {
    /// Create a score from raw alpha/beta values.
    pub fn from_params(alpha: f64, beta: f64, momentum: MomentumDirection) -> Self {
        let posterior_mean = if (alpha + beta) > 0.0 {
            alpha / (alpha + beta)
        } else {
            0.5
        };
        let ci = crate::patterns::confidence::beta::credible_interval(alpha, beta, 0.95);
        let tier = ConfidenceTier::from_posterior_mean(posterior_mean);
        Self {
            alpha,
            beta,
            posterior_mean,
            credible_interval: ci,
            tier,
            momentum,
        }
    }

    /// Create a uniform prior score (no evidence).
    pub fn uniform_prior() -> Self {
        Self::from_params(1.0, 1.0, MomentumDirection::Stable)
    }
}

/// Graduated confidence tiers based on posterior mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfidenceTier {
    /// posterior_mean ≥ 0.85 — well-established pattern.
    Established,
    /// posterior_mean ≥ 0.70 — likely pattern.
    Emerging,
    /// posterior_mean ≥ 0.50 — emerging pattern.
    Tentative,
    /// posterior_mean < 0.50 — insufficient evidence.
    Uncertain,
}

impl ConfidenceTier {
    /// Classify a posterior mean into a tier.
    pub fn from_posterior_mean(mean: f64) -> Self {
        if mean >= 0.85 {
            Self::Established
        } else if mean >= 0.70 {
            Self::Emerging
        } else if mean >= 0.50 {
            Self::Tentative
        } else {
            Self::Uncertain
        }
    }

    /// Tier name as string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::Emerging => "emerging",
            Self::Tentative => "tentative",
            Self::Uncertain => "uncertain",
        }
    }
}

impl fmt::Display for ConfidenceTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Momentum direction — trend of pattern adoption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MomentumDirection {
    /// Pattern adoption is increasing.
    Rising,
    /// Pattern adoption is decreasing.
    Falling,
    /// Pattern adoption is stable.
    Stable,
}

impl MomentumDirection {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Rising => "rising",
            Self::Falling => "falling",
            Self::Stable => "stable",
        }
    }
}

impl fmt::Display for MomentumDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

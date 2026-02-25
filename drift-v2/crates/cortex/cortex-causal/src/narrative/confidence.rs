//! Chain confidence calculation: 60% min edge strength + 40% average, with depth penalty.

/// Calculate chain confidence for a causal path.
///
/// Formula: confidence = (0.6 * min_strength + 0.4 * avg_strength) * depth_penalty
/// Depth penalty: 0.95^depth (5% reduction per hop).
pub fn chain_confidence(edge_strengths: &[f64], depth: usize) -> f64 {
    if edge_strengths.is_empty() {
        return 0.0;
    }

    let min_strength = edge_strengths.iter().copied().fold(f64::INFINITY, f64::min);

    let avg_strength = edge_strengths.iter().sum::<f64>() / edge_strengths.len() as f64;

    let base = 0.6 * min_strength + 0.4 * avg_strength;
    let depth_penalty = 0.95_f64.powi(depth as i32);

    (base * depth_penalty).clamp(0.0, 1.0)
}

/// Confidence level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
    VeryLow,
}

impl ConfidenceLevel {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.8 {
            Self::High
        } else if score >= 0.5 {
            Self::Medium
        } else if score >= 0.3 {
            Self::Low
        } else {
            Self::VeryLow
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::VeryLow => "very low",
        }
    }
}

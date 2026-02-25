//! Outlier-to-violation conversion pipeline.
//!
//! Converts OutlierResult into violation-ready data for the Rules Engine.

use super::types::{OutlierResult, SignificanceTier};

/// A violation generated from an outlier detection.
#[derive(Debug, Clone)]
pub struct OutlierViolation {
    /// Pattern ID this outlier belongs to.
    pub pattern_id: String,
    /// File where the outlier was found.
    pub file: String,
    /// Line number.
    pub line: u32,
    /// Severity derived from significance tier.
    pub severity: ViolationSeverity,
    /// Human-readable message.
    pub message: String,
    /// The outlier method that detected it.
    pub method: String,
    /// Deviation score [0.0, 1.0].
    pub deviation_score: f64,
}

/// Violation severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViolationSeverity {
    Error,
    Warning,
    Info,
}

impl ViolationSeverity {
    /// Convert from significance tier.
    pub fn from_significance(tier: SignificanceTier) -> Self {
        match tier {
            SignificanceTier::Critical => Self::Error,
            SignificanceTier::High => Self::Error,
            SignificanceTier::Moderate => Self::Warning,
            SignificanceTier::Low => Self::Info,
        }
    }
}

/// Convert outlier results into violations.
pub fn convert_to_violations(
    pattern_id: &str,
    outliers: &[OutlierResult],
    file_line_map: &[(String, u32)], // Maps index → (file, line)
) -> Vec<OutlierViolation> {
    outliers
        .iter()
        .filter(|o| o.is_outlier)
        .filter_map(|o| {
            let (file, line) = file_line_map.get(o.index)?;
            Some(OutlierViolation {
                pattern_id: pattern_id.to_string(),
                file: file.clone(),
                line: *line,
                severity: ViolationSeverity::from_significance(o.significance),
                message: format!(
                    "Outlier detected: value {:.4} deviates from pattern (method: {}, score: {})",
                    o.value,
                    o.method,
                    o.deviation_score
                ),
                method: o.method.name().to_string(),
                deviation_score: o.deviation_score.value(),
            })
        })
        .collect()
}

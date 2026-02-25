//! Rule-based outlier detection (always active, for structural rules).
//!
//! Domain-specific checks that statistics can't capture.

use super::types::{DeviationScore, OutlierMethod, OutlierResult, SignificanceTier};

/// Type alias for rule check functions.
pub type RuleCheckFn = Box<dyn Fn(f64, &RuleContext) -> bool + Send + Sync>;

/// A rule for detecting outliers based on domain knowledge.
pub struct OutlierRule {
    /// Rule identifier.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// The check function: returns true if the value is an outlier.
    pub check: RuleCheckFn,
    /// Significance tier for violations of this rule.
    pub significance: SignificanceTier,
}

/// Context provided to rule checks.
#[derive(Debug, Clone)]
pub struct RuleContext {
    /// Mean of all values.
    pub mean: f64,
    /// Standard deviation.
    pub stddev: f64,
    /// Minimum value.
    pub min: f64,
    /// Maximum value.
    pub max: f64,
    /// Number of values.
    pub count: usize,
}

impl RuleContext {
    /// Compute context from a slice of values.
    pub fn from_values(values: &[f64]) -> Self {
        if values.is_empty() {
            return Self {
                mean: 0.0,
                stddev: 0.0,
                min: 0.0,
                max: 0.0,
                count: 0,
            };
        }

        let n = values.len() as f64;
        let mean = values.iter().sum::<f64>() / n;
        let variance = if values.len() > 1 {
            values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0)
        } else {
            0.0
        };
        let stddev = if variance.is_finite() && variance >= 0.0 {
            variance.sqrt()
        } else {
            0.0
        };

        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        Self {
            mean,
            stddev,
            min,
            max,
            count: values.len(),
        }
    }
}

/// Detect outliers using registered rules.
pub fn detect(values: &[f64], rules: &[OutlierRule]) -> Vec<OutlierResult> {
    if values.is_empty() || rules.is_empty() {
        return Vec::new();
    }

    let ctx = RuleContext::from_values(values);
    let mut results = Vec::new();

    for (idx, &val) in values.iter().enumerate() {
        for rule in rules {
            if (rule.check)(val, &ctx) {
                results.push(OutlierResult {
                    index: idx,
                    value: val,
                    test_statistic: 0.0,
                    deviation_score: DeviationScore::new(0.5),
                    significance: rule.significance,
                    method: OutlierMethod::RuleBased,
                    is_outlier: true,
                });
                break; // One rule match per value is sufficient
            }
        }
    }

    results
}

/// Create a default rule: zero-confidence values are always outliers.
pub fn zero_confidence_rule() -> OutlierRule {
    OutlierRule {
        id: "zero_confidence".to_string(),
        description: "Zero-confidence values are always outliers".to_string(),
        check: Box::new(|val, _ctx| val <= 0.0),
        significance: SignificanceTier::High,
    }
}

/// Create a rule: values more than N standard deviations from mean.
pub fn extreme_deviation_rule(n_stddev: f64) -> OutlierRule {
    OutlierRule {
        id: format!("extreme_deviation_{}", n_stddev),
        description: format!("Values more than {} stddev from mean", n_stddev),
        check: Box::new(move |val, ctx| {
            if ctx.stddev <= 0.0 {
                return false;
            }
            (val - ctx.mean).abs() / ctx.stddev > n_stddev
        }),
        significance: SignificanceTier::Critical,
    }
}

/// PI-OUT-05: Confidence cliff rule — flag locations where confidence drops >50% vs pattern mean.
///
/// Example: pattern mean is 0.9, a location with 0.3 is flagged (drop of 67%).
pub fn confidence_cliff_rule() -> OutlierRule {
    OutlierRule {
        id: "confidence_cliff".to_string(),
        description: "Confidence drops >50% below pattern mean".to_string(),
        check: Box::new(|val, ctx| {
            if ctx.mean <= 0.0 {
                return false;
            }
            let drop_ratio = (ctx.mean - val) / ctx.mean;
            drop_ratio > 0.5
        }),
        significance: SignificanceTier::High,
    }
}

/// PI-OUT-06: File isolation rule — flag singleton values in patterns with many data points.
///
/// When a pattern has 10+ observations and a value is far below the minimum
/// of the non-outlier cluster, it's likely an isolated anomaly.
/// This uses a simple heuristic: value < mean - 3*stddev in large samples.
pub fn file_isolation_rule() -> OutlierRule {
    OutlierRule {
        id: "file_isolation".to_string(),
        description: "Isolated low-confidence value in large pattern".to_string(),
        check: Box::new(|val, ctx| {
            if ctx.count < 10 || ctx.stddev <= 0.0 {
                return false;
            }
            // Flag values more than 3 stddev below the mean in large patterns
            val < ctx.mean - 3.0 * ctx.stddev
        }),
        significance: SignificanceTier::Moderate,
    }
}

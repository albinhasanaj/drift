//! IQR with Tukey fences (supplementary, non-normal data).
//!
//! Resistant to extreme outliers that inflate stddev.
//! Uses Q1 - k*IQR and Q3 + k*IQR as fences (k = 1.5 default).

use super::types::{DeviationScore, OutlierMethod, OutlierResult, SignificanceTier};

/// Detect outliers using IQR with Tukey fences.
///
/// `values`: the data points.
/// `multiplier`: IQR multiplier for fences (default 1.5).
pub fn detect(values: &[f64], multiplier: f64) -> Vec<OutlierResult> {
    if values.len() < 4 {
        return Vec::new(); // Need at least 4 values for meaningful quartiles
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let q1 = percentile(&sorted, 25.0);
    let q3 = percentile(&sorted, 75.0);
    let iqr = q3 - q1;

    if iqr <= 0.0 || !iqr.is_finite() {
        // IQR is zero — most values are identical. Flag values outside the
        // constant range using a simple distance-from-median approach.
        let median = percentile(&sorted, 50.0);
        let mut results = Vec::new();
        for (idx, &val) in values.iter().enumerate() {
            if (val - median).abs() > f64::EPSILON {
                let range = sorted.last().unwrap_or(&0.0) - sorted.first().unwrap_or(&0.0);
                let dev = if range > 0.0 {
                    (val - median).abs() / range
                } else {
                    0.0
                };
                let deviation = DeviationScore::new(dev);
                let significance = SignificanceTier::from_deviation(deviation.value());
                results.push(OutlierResult {
                    index: idx,
                    value: val,
                    test_statistic: (val - median).abs(),
                    deviation_score: deviation,
                    significance,
                    method: OutlierMethod::Iqr,
                    is_outlier: true,
                });
            }
        }
        return results;
    }

    let lower_fence = q1 - multiplier * iqr;
    let upper_fence = q3 + multiplier * iqr;

    let mut results = Vec::new();
    for (idx, &val) in values.iter().enumerate() {
        if val < lower_fence || val > upper_fence {
            let distance = if val < lower_fence {
                (lower_fence - val) / iqr
            } else {
                (val - upper_fence) / iqr
            };

            let deviation = DeviationScore::new(distance / (distance + multiplier));
            let significance = SignificanceTier::from_deviation(deviation.value());

            results.push(OutlierResult {
                index: idx,
                value: val,
                test_statistic: distance,
                deviation_score: deviation,
                significance,
                method: OutlierMethod::Iqr,
                is_outlier: true,
            });
        }
    }

    results
}

/// Compute percentile using linear interpolation.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }

    let rank = (p / 100.0) * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let frac = rank - lower as f64;

    if upper >= sorted.len() {
        sorted[sorted.len() - 1]
    } else {
        sorted[lower] * (1.0 - frac) + sorted[upper] * frac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iqr_no_outliers() {
        let values: Vec<f64> = (1..=20).map(|i| i as f64).collect();
        let results = detect(&values, 1.5);
        assert!(results.is_empty());
    }

    #[test]
    fn test_iqr_with_outlier() {
        let mut values: Vec<f64> = vec![10.0; 20];
        values[0] = 100.0;
        let results = detect(&values, 1.5);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.index == 0));
    }

    #[test]
    fn test_iqr_identical_values() {
        let values = vec![5.0; 20];
        let results = detect(&values, 1.5);
        assert!(results.is_empty());
    }

    #[test]
    fn test_percentile_basic() {
        let sorted = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((percentile(&sorted, 50.0) - 3.0).abs() < 1e-10);
    }
}

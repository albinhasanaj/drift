//! Modified Z-Score / MAD (robust to extreme outliers).
//!
//! Uses median instead of mean, MAD instead of stddev.
//! Robust when normality assumption fails or when >25% of data are outliers.

use super::types::{DeviationScore, OutlierMethod, OutlierResult, SignificanceTier};

/// Detect outliers using Modified Z-Score (MAD-based).
///
/// `values`: the data points.
/// `threshold`: modified Z-Score threshold (default 3.5).
pub fn detect(values: &[f64], threshold: f64) -> Vec<OutlierResult> {
    if values.len() < 3 {
        return Vec::new();
    }

    let median = compute_median(values);
    let mad = compute_mad(values, median);

    if mad <= 0.0 || !mad.is_finite() {
        // MAD is zero — most values are identical. Use fallback: flag values
        // that differ from the median by more than a small epsilon.
        let mut results = Vec::new();
        for (idx, &val) in values.iter().enumerate() {
            if (val - median).abs() > f64::EPSILON {
                // Use distance from median normalized by range as deviation
                let range = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
                    - values.iter().cloned().fold(f64::INFINITY, f64::min);
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
                    test_statistic: f64::INFINITY,
                    deviation_score: deviation,
                    significance,
                    method: OutlierMethod::Mad,
                    is_outlier: true,
                });
            }
        }
        return results;
    }

    // Modified Z-Score: M_i = 0.6745 * (x_i - median) / MAD
    // The constant 0.6745 makes it consistent with the standard normal distribution
    const CONSISTENCY_CONSTANT: f64 = 0.6745;

    let mut results = Vec::new();
    for (idx, &val) in values.iter().enumerate() {
        let modified_z = CONSISTENCY_CONSTANT * (val - median) / mad;

        if modified_z.abs() > threshold {
            let deviation = DeviationScore::new((modified_z.abs() - threshold) / threshold);
            let significance = SignificanceTier::from_deviation(deviation.value());

            results.push(OutlierResult {
                index: idx,
                value: val,
                test_statistic: modified_z,
                deviation_score: deviation,
                significance,
                method: OutlierMethod::Mad,
                is_outlier: true,
            });
        }
    }

    results
}

/// Compute the median of a slice.
fn compute_median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted.len();
    if n % 2 == 0 {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    }
}

/// Compute the Median Absolute Deviation (MAD).
fn compute_mad(values: &[f64], median: f64) -> f64 {
    let deviations: Vec<f64> = values.iter().map(|v| (v - median).abs()).collect();
    compute_median(&deviations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mad_no_outliers() {
        let values: Vec<f64> = (1..=20).map(|i| i as f64).collect();
        let results = detect(&values, 3.5);
        assert!(results.is_empty());
    }

    #[test]
    fn test_mad_with_extreme_outlier() {
        let mut values: Vec<f64> = vec![10.0; 20];
        values[0] = 1000.0;
        let results = detect(&values, 3.5);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_mad_robust_to_many_outliers() {
        // 60% normal, 40% outliers — MAD should still work
        let mut values: Vec<f64> = vec![10.0; 30];
        for v in values.iter_mut().take(12) {
            *v = 100.0;
        }
        let results = detect(&values, 3.5);
        // MAD uses median, so the 60% majority defines "normal"
        assert!(!results.is_empty());
    }

    #[test]
    fn test_mad_identical_values() {
        let values = vec![5.0; 20];
        let results = detect(&values, 3.5);
        assert!(results.is_empty());
    }
}

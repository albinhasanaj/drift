//! Grubbs' test (10 ≤ n < 30, single outlier in small samples).
//!
//! Uses T-distribution critical values via `statrs`.

use statrs::distribution::{ContinuousCDF, StudentsT};

use super::types::{DeviationScore, OutlierMethod, OutlierResult, SignificanceTier};

/// Detect the single most extreme outlier using Grubbs' test.
///
/// `values`: the data points (10 ≤ n < 30 recommended).
/// `alpha`: significance level (default 0.05).
///
/// Returns at most one outlier result.
pub fn detect(values: &[f64], alpha: f64) -> Vec<OutlierResult> {
    let n = values.len();
    if n < 3 {
        return Vec::new(); // Grubbs' requires at least 3 observations
    }

    let n_f = n as f64;
    let mean = values.iter().sum::<f64>() / n_f;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n_f - 1.0);

    if !variance.is_finite() || variance <= 0.0 {
        return Vec::new(); // All identical — no outlier
    }

    let stddev = variance.sqrt();
    if stddev <= 0.0 || !stddev.is_finite() {
        return Vec::new();
    }

    // Find the value with maximum |deviation| from mean
    let (max_idx, max_val, max_g) = values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let g = (v - mean).abs() / stddev;
            (i, v, g)
        })
        .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap();

    // Compute Grubbs' critical value
    let critical = grubbs_critical_value(n, alpha);

    if max_g > critical {
        let deviation = DeviationScore::new((max_g - critical) / critical.max(1.0));
        let significance = SignificanceTier::from_deviation(deviation.value());

        vec![OutlierResult {
            index: max_idx,
            value: max_val,
            test_statistic: max_g,
            deviation_score: deviation,
            significance,
            method: OutlierMethod::Grubbs,
            is_outlier: true,
        }]
    } else {
        Vec::new()
    }
}

/// Compute Grubbs' critical value using T-distribution.
///
/// G_critical = ((n-1) / sqrt(n)) * sqrt(t² / (n - 2 + t²))
/// where t = t_{α/(2n), n-2}
fn grubbs_critical_value(n: usize, alpha: f64) -> f64 {
    let n_f = n as f64;
    let df = n_f - 2.0;

    if df <= 0.0 {
        return f64::MAX; // Can't compute — never reject
    }

    let adjusted_alpha = alpha / (2.0 * n_f);

    match StudentsT::new(0.0, 1.0, df) {
        Ok(t_dist) => {
            let t = t_dist.inverse_cdf(1.0 - adjusted_alpha);
            if !t.is_finite() {
                return f64::MAX;
            }
            let t2 = t * t;
            let g = ((n_f - 1.0) / n_f.sqrt()) * (t2 / (n_f - 2.0 + t2)).sqrt();
            if g.is_finite() { g } else { f64::MAX }
        }
        Err(_) => f64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grubbs_no_outlier() {
        let values: Vec<f64> = (1..=20).map(|i| i as f64).collect();
        let results = detect(&values, 0.05);
        assert!(results.is_empty());
    }

    #[test]
    fn test_grubbs_clear_outlier() {
        let mut values: Vec<f64> = vec![10.0; 20];
        values[0] = 100.0; // Extreme outlier
        let results = detect(&values, 0.05);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].index, 0);
    }

    #[test]
    fn test_grubbs_too_few_values() {
        let results = detect(&[1.0, 2.0], 0.05);
        assert!(results.is_empty());
    }

    #[test]
    fn test_grubbs_identical_values() {
        let values = vec![5.0; 15];
        let results = detect(&values, 0.05);
        assert!(results.is_empty());
    }
}

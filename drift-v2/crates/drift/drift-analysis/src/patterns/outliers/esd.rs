//! Generalized ESD / Rosner test (n ≥ 25, multiple outliers).
//!
//! Detects up to `max_outliers` outliers without specifying the exact count.
//! Based on Rosner (1983).

use statrs::distribution::{ContinuousCDF, StudentsT};

use super::types::{DeviationScore, OutlierMethod, OutlierResult, SignificanceTier};

/// Detect multiple outliers using the Generalized ESD test.
///
/// `values`: the data points (n ≥ 25 recommended).
/// `max_outliers`: maximum number of outliers to test for.
/// `alpha`: significance level (default 0.05).
pub fn detect(values: &[f64], max_outliers: usize, alpha: f64) -> Vec<OutlierResult> {
    let n = values.len();
    if n < 3 || max_outliers == 0 {
        return Vec::new();
    }

    let max_k = max_outliers.min(n / 2); // Never test more than half the data
    let mut working: Vec<(usize, f64)> = values.iter().enumerate().map(|(i, &v)| (i, v)).collect();
    let mut test_stats = Vec::new();
    let mut removed_indices = Vec::new();

    // Step 1: Compute test statistics R_1, R_2, ..., R_k
    for _ in 0..max_k {
        if working.len() < 3 {
            break;
        }

        let n_w = working.len() as f64;
        let mean = working.iter().map(|(_, v)| v).sum::<f64>() / n_w;
        let variance = working.iter().map(|(_, v)| (v - mean).powi(2)).sum::<f64>() / (n_w - 1.0);

        if !variance.is_finite() || variance <= 0.0 {
            break;
        }

        let stddev = variance.sqrt();
        if stddev <= 0.0 || !stddev.is_finite() {
            break;
        }

        // Find the value with maximum |deviation|
        let (max_pos, &(orig_idx, max_val)) = working
            .iter()
            .enumerate()
            .max_by(|a, b| {
                let da = (a.1 .1 - mean).abs();
                let db = (b.1 .1 - mean).abs();
                da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();

        let r = (max_val - mean).abs() / stddev;
        test_stats.push(r);
        removed_indices.push((orig_idx, max_val));
        working.remove(max_pos);
    }

    // Step 2: Compute critical values λ_1, λ_2, ..., λ_k
    let mut results = Vec::new();
    let mut num_outliers = 0;

    for (i, &stat) in test_stats.iter().enumerate() {
        let p = n - i; // Remaining sample size
        let critical = esd_critical_value(p, alpha);

        if stat > critical {
            num_outliers = i + 1;
        }
    }

    // Step 3: The first `num_outliers` removed values are outliers
    for i in 0..num_outliers {
        let (orig_idx, val) = removed_indices[i];
        let r = test_stats[i];
        let deviation = DeviationScore::new(r / (r + 1.0)); // Normalize
        let significance = SignificanceTier::from_deviation(deviation.value());

        results.push(OutlierResult {
            index: orig_idx,
            value: val,
            test_statistic: r,
            deviation_score: deviation,
            significance,
            method: OutlierMethod::GeneralizedEsd,
            is_outlier: true,
        });
    }

    results
}

/// Compute ESD critical value for a given sample size and significance level.
///
/// λ_i = (p-1) * t_{α/(2p), p-2} / sqrt((p - 2 + t²) * p)
fn esd_critical_value(p: usize, alpha: f64) -> f64 {
    let p_f = p as f64;
    let df = p_f - 2.0;

    if df <= 0.0 {
        return f64::MAX;
    }

    let adjusted_alpha = alpha / (2.0 * p_f);

    match StudentsT::new(0.0, 1.0, df) {
        Ok(t_dist) => {
            let t = t_dist.inverse_cdf(1.0 - adjusted_alpha);
            if !t.is_finite() {
                return f64::MAX;
            }
            let t2 = t * t;
            let lambda = (p_f - 1.0) * t / ((p_f - 2.0 + t2) * p_f).sqrt();
            if lambda.is_finite() { lambda } else { f64::MAX }
        }
        Err(_) => f64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esd_no_outliers() {
        let values: Vec<f64> = (1..=30).map(|i| i as f64).collect();
        let results = detect(&values, 3, 0.05);
        assert!(results.is_empty());
    }

    #[test]
    fn test_esd_multiple_outliers() {
        let mut values: Vec<f64> = vec![10.0; 30];
        values[0] = 100.0;
        values[1] = 95.0;
        values[2] = 90.0;
        let results = detect(&values, 5, 0.05);
        assert!(results.len() >= 2, "Should find multiple outliers: found {}", results.len());
    }

    #[test]
    fn test_esd_empty_input() {
        let results = detect(&[], 3, 0.05);
        assert!(results.is_empty());
    }
}

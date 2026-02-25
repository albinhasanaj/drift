//! Z-Score with iterative masking (n ≥ 30, 3-iteration cap).
//!
//! Standard Z-Score detection with iterative masking to prevent
//! one extreme outlier from hiding others by inflating stddev.

use super::types::{DeviationScore, OutlierMethod, OutlierResult, SignificanceTier};

/// Detect outliers using Z-Score with iterative masking.
///
/// `values`: the data points to analyze.
/// `threshold`: Z-Score threshold (default 2.5).
/// `max_iterations`: maximum masking iterations (default 3).
///
/// Returns outlier results indexed into the original `values` array.
pub fn detect(values: &[f64], threshold: f64, max_iterations: usize) -> Vec<OutlierResult> {
    if values.len() < 2 {
        return Vec::new();
    }

    let mut masked = vec![false; values.len()];
    let mut all_outliers = Vec::new();

    for _iteration in 0..max_iterations {
        // Compute mean and stddev excluding masked values
        let active: Vec<(usize, f64)> = values
            .iter()
            .enumerate()
            .filter(|(i, _)| !masked[*i])
            .map(|(i, &v)| (i, v))
            .collect();

        if active.len() < 2 {
            break;
        }

        let n = active.len() as f64;
        let mean = active.iter().map(|(_, v)| v).sum::<f64>() / n;
        let variance = active.iter().map(|(_, v)| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);

        if !variance.is_finite() || variance <= 0.0 {
            break; // All identical values — no outliers possible
        }

        let stddev = variance.sqrt();
        if stddev <= 0.0 || !stddev.is_finite() {
            break;
        }

        let mut found_new = false;
        for &(idx, val) in &active {
            let z = (val - mean) / stddev;
            if z.abs() > threshold {
                masked[idx] = true;
                found_new = true;

                let deviation = normalize_zscore(z.abs(), threshold);
                let significance = SignificanceTier::from_deviation(deviation.value());

                all_outliers.push(OutlierResult {
                    index: idx,
                    value: val,
                    test_statistic: z,
                    deviation_score: deviation,
                    significance,
                    method: OutlierMethod::ZScore,
                    is_outlier: true,
                });
            }
        }

        if !found_new {
            break; // No new outliers found — converged
        }
    }

    all_outliers
}

/// Normalize a Z-Score to a [0.0, 1.0] deviation score.
///
/// Maps |z| from [threshold, threshold*3] to [0.0, 1.0].
fn normalize_zscore(abs_z: f64, threshold: f64) -> DeviationScore {
    if abs_z <= threshold {
        return DeviationScore::zero();
    }
    let max_z = threshold * 3.0;
    let normalized = (abs_z - threshold) / (max_z - threshold);
    DeviationScore::new(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_outliers_uniform() {
        let values: Vec<f64> = (0..50).map(|i| 50.0 + (i as f64) * 0.1).collect();
        let results = detect(&values, 2.5, 3);
        assert!(results.is_empty());
    }

    #[test]
    fn test_single_outlier() {
        let mut values: Vec<f64> = vec![50.0; 50];
        values[25] = 200.0; // Clear outlier
        let results = detect(&values, 2.5, 3);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.index == 25));
    }

    #[test]
    fn test_iterative_masking_finds_multiple() {
        let mut values: Vec<f64> = vec![10.0; 50];
        values[0] = 100.0;
        values[1] = 95.0;
        values[2] = 90.0;
        let results = detect(&values, 2.5, 3);
        assert!(results.len() >= 2, "Should find multiple outliers: found {}", results.len());
    }

    #[test]
    fn test_all_identical_no_outliers() {
        let values = vec![5.0; 50];
        let results = detect(&values, 2.5, 3);
        assert!(results.is_empty());
    }
}

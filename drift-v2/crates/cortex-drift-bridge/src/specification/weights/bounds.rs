//! Weight invariant enforcement: NaN protection, range clamping, sum bounds.
//!
//! Invariants:
//! - Individual weight: 0.0 ≤ w ≤ 5.0
//! - Weight sum: 5.0 ≤ sum ≤ 30.0
//! - NaN → static default
//! - Infinity → max bound

/// Minimum allowed individual weight.
pub const MIN_WEIGHT: f64 = 0.0;
/// Maximum allowed individual weight.
pub const MAX_WEIGHT: f64 = 5.0;
/// Minimum allowed sum of all weights.
pub const MIN_WEIGHT_SUM: f64 = 5.0;
/// Maximum allowed sum of all weights.
pub const MAX_WEIGHT_SUM: f64 = 30.0;

/// Clamp a single weight to valid bounds. NaN → default.
pub fn clamp_weight(weight: f64, default: f64) -> f64 {
    if !weight.is_finite() {
        return default;
    }
    weight.clamp(MIN_WEIGHT, MAX_WEIGHT)
}

/// Validate and normalize a weight vector.
/// - Replaces NaN/Infinity with corresponding defaults.
/// - Clamps individual weights to [0.0, 5.0].
/// - If sum is outside [5.0, 30.0], scales proportionally.
///
/// Returns the sanitized weight vector.
pub fn normalize_weights(weights: &[f64], defaults: &[f64]) -> Vec<f64> {
    assert_eq!(
        weights.len(),
        defaults.len(),
        "weights and defaults must have same length"
    );

    // Step 1: Clamp individual weights
    let mut result: Vec<f64> = weights
        .iter()
        .zip(defaults.iter())
        .map(|(w, d)| clamp_weight(*w, *d))
        .collect();

    // Step 2: Check sum bounds
    let sum: f64 = result.iter().sum();
    if sum < MIN_WEIGHT_SUM && sum > 0.0 {
        // Scale up proportionally
        let factor = MIN_WEIGHT_SUM / sum;
        for w in &mut result {
            *w = (*w * factor).min(MAX_WEIGHT);
        }
    } else if sum > MAX_WEIGHT_SUM {
        // Scale down proportionally
        let factor = MAX_WEIGHT_SUM / sum;
        for w in &mut result {
            *w *= factor;
        }
    } else if sum <= 0.0 {
        // All weights are zero — reset to defaults
        result = defaults.to_vec();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp_normal() {
        assert_eq!(clamp_weight(1.5, 1.0), 1.5);
    }

    #[test]
    fn test_clamp_nan() {
        assert_eq!(clamp_weight(f64::NAN, 1.0), 1.0);
    }

    #[test]
    fn test_clamp_infinity() {
        assert_eq!(clamp_weight(f64::INFINITY, 1.0), 1.0);
    }

    #[test]
    fn test_clamp_negative() {
        assert_eq!(clamp_weight(-1.0, 1.0), 0.0);
    }

    #[test]
    fn test_clamp_above_max() {
        assert_eq!(clamp_weight(10.0, 1.0), 5.0);
    }

    #[test]
    fn test_normalize_valid_weights() {
        let weights = vec![1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
        let defaults = vec![1.0; 6];
        let result = normalize_weights(&weights, &defaults);
        let sum: f64 = result.iter().sum();
        assert!((sum - 6.0).abs() < 0.01);
    }

    #[test]
    fn test_normalize_scales_up() {
        let weights = vec![0.1, 0.1, 0.1, 0.1, 0.1, 0.1]; // sum=0.6
        let defaults = vec![1.0; 6];
        let result = normalize_weights(&weights, &defaults);
        let sum: f64 = result.iter().sum();
        assert!(sum >= MIN_WEIGHT_SUM - 0.01);
    }

    #[test]
    fn test_normalize_scales_down() {
        let weights = vec![5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0]; // sum=35
        let defaults = vec![1.0; 7];
        let result = normalize_weights(&weights, &defaults);
        let sum: f64 = result.iter().sum();
        assert!(sum <= MAX_WEIGHT_SUM + 0.01);
    }

    #[test]
    fn test_normalize_all_nan_uses_defaults() {
        let weights = vec![f64::NAN, f64::NAN, f64::NAN];
        let defaults = vec![2.0, 3.0, 4.0];
        let result = normalize_weights(&weights, &defaults);
        assert_eq!(result, vec![2.0, 3.0, 4.0]);
    }

    #[test]
    fn test_normalize_all_zero_uses_defaults() {
        let weights = vec![0.0, 0.0, 0.0];
        let defaults = vec![2.0, 3.0, 4.0];
        let result = normalize_weights(&weights, &defaults);
        assert_eq!(result, defaults);
    }
}

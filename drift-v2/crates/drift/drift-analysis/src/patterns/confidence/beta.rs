//! Beta distribution posterior computation via `statrs` crate.
//!
//! Prior: Beta(1, 1) — uniform, no prior bias.
//! Posterior: Beta(1+k, 1+n-k) where k = successes, n = total observations.
//! Credible interval: 95% HDI via inverse CDF.

use statrs::distribution::{Beta, ContinuousCDF};

/// Beta distribution posterior computation.
pub struct BetaPosterior;

impl BetaPosterior {
    /// Compute posterior parameters from observations.
    ///
    /// `successes`: number of pattern matches (k).
    /// `total`: total observations (n).
    /// Returns (alpha, beta) for the posterior Beta distribution.
    ///
    /// Prior: Beta(1, 1) — uniform.
    /// Posterior: Beta(1 + k, 1 + n - k).
    pub fn posterior_params(successes: u64, total: u64) -> (f64, f64) {
        let k = successes as f64;
        let n = total as f64;
        let alpha = 1.0 + k;
        let beta = 1.0 + (n - k).max(0.0);
        (alpha, beta)
    }

    /// Compute posterior mean: alpha / (alpha + beta).
    ///
    /// Guards against division by zero.
    pub fn posterior_mean(alpha: f64, beta: f64) -> f64 {
        let sum = alpha + beta;
        if sum <= 0.0 || !sum.is_finite() {
            return 0.5; // Fallback to uniform
        }
        let mean = alpha / sum;
        if !mean.is_finite() {
            0.5
        } else {
            mean.clamp(0.0, 1.0)
        }
    }

    /// Compute posterior variance: alpha*beta / ((alpha+beta)^2 * (alpha+beta+1)).
    pub fn posterior_variance(alpha: f64, beta: f64) -> f64 {
        let sum = alpha + beta;
        if sum <= 0.0 || !sum.is_finite() {
            return 0.25; // Maximum variance for uniform
        }
        let denom = sum * sum * (sum + 1.0);
        if denom <= 0.0 || !denom.is_finite() {
            return 0.25;
        }
        let var = (alpha * beta) / denom;
        if !var.is_finite() {
            0.25
        } else {
            var.max(0.0)
        }
    }
}

/// Compute the credible interval for a Beta distribution.
///
/// Uses the inverse CDF (quantile function) to find the interval
/// that contains `level` probability mass (e.g., 0.95 for 95% CI).
///
/// Returns (low, high). Guards against invalid parameters.
pub fn credible_interval(alpha: f64, beta_param: f64, level: f64) -> (f64, f64) {
    // Guard against invalid parameters
    if alpha <= 0.0 || beta_param <= 0.0 || !alpha.is_finite() || !beta_param.is_finite() {
        return (0.0, 1.0);
    }

    // Guard against extreme values that would cause numerical issues
    if alpha > 1e6 || beta_param > 1e6 {
        let mean = alpha / (alpha + beta_param);
        let epsilon = 1e-6;
        return ((mean - epsilon).max(0.0), (mean + epsilon).min(1.0));
    }

    let tail = (1.0 - level) / 2.0;

    match Beta::new(alpha, beta_param) {
        Ok(dist) => {
            let low = dist.inverse_cdf(tail);
            let high = dist.inverse_cdf(1.0 - tail);

            // Guard against NaN/Inf from numerical issues
            let low = if low.is_finite() { low.clamp(0.0, 1.0) } else { 0.0 };
            let high = if high.is_finite() { high.clamp(0.0, 1.0) } else { 1.0 };

            (low, high)
        }
        Err(_) => (0.0, 1.0), // Fallback for invalid distribution
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniform_prior() {
        let (a, b) = BetaPosterior::posterior_params(0, 0);
        assert_eq!(a, 1.0);
        assert_eq!(b, 1.0);
        let mean = BetaPosterior::posterior_mean(a, b);
        assert!((mean - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_posterior_with_evidence() {
        let (a, b) = BetaPosterior::posterior_params(8, 10);
        assert_eq!(a, 9.0); // 1 + 8
        assert_eq!(b, 3.0); // 1 + (10 - 8)
        let mean = BetaPosterior::posterior_mean(a, b);
        assert!((mean - 0.75).abs() < 1e-10);
    }

    #[test]
    fn test_posterior_all_successes() {
        let (a, b) = BetaPosterior::posterior_params(100, 100);
        assert_eq!(a, 101.0);
        assert_eq!(b, 1.0);
        let mean = BetaPosterior::posterior_mean(a, b);
        assert!(mean > 0.98);
    }

    #[test]
    fn test_credible_interval_uniform() {
        let (low, high) = credible_interval(1.0, 1.0, 0.95);
        assert!(low < 0.1);
        assert!(high > 0.9);
    }

    #[test]
    fn test_credible_interval_narrows_with_evidence() {
        let (low1, high1) = credible_interval(2.0, 2.0, 0.95);
        let (low2, high2) = credible_interval(20.0, 20.0, 0.95);
        let width1 = high1 - low1;
        let width2 = high2 - low2;
        assert!(width2 < width1, "More evidence should narrow the interval");
    }

    #[test]
    fn test_numerical_stability_extreme_alpha() {
        let mean = BetaPosterior::posterior_mean(100000.0, 1.0);
        assert!(mean > 0.99);
        assert!(mean.is_finite());
    }

    #[test]
    fn test_numerical_stability_near_zero() {
        let mean = BetaPosterior::posterior_mean(0.001, 1000.0);
        assert!(mean < 0.01);
        assert!(mean.is_finite());
    }

    #[test]
    fn test_credible_interval_invalid_params() {
        let (low, high) = credible_interval(0.0, 0.0, 0.95);
        assert_eq!(low, 0.0);
        assert_eq!(high, 1.0);
    }

    #[test]
    fn test_credible_interval_extreme_values() {
        let (low, high) = credible_interval(1e7, 1.0, 0.95);
        assert!(low.is_finite());
        assert!(high.is_finite());
        assert!(low <= high);
    }
}

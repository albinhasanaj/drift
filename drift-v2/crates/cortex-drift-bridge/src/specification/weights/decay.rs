//! 365-day half-life decay for adaptive weights.
//!
//! Formula: effective = static_default + (stored - static_default) * 0.5^(days / 365)
//! As time passes, adaptive weights decay back toward their static defaults.

/// Compute the decayed weight value.
///
/// - `stored`: the adaptive weight value when it was last computed
/// - `static_default`: the baseline weight for this evidence type
/// - `elapsed_days`: days since the weight was last updated
///
/// Returns the effective weight after decay.
pub fn decay_weight(stored: f64, static_default: f64, elapsed_days: f64) -> f64 {
    if elapsed_days <= 0.0 || !elapsed_days.is_finite() {
        return stored;
    }
    if !stored.is_finite() {
        return static_default;
    }

    let half_life = 365.0;
    let decay_factor = 0.5_f64.powf(elapsed_days / half_life);
    static_default + (stored - static_default) * decay_factor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_decay_at_zero_days() {
        let result = decay_weight(2.0, 1.0, 0.0);
        assert!((result - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_half_decay_at_365_days() {
        // stored=2.0, default=1.0, after 365 days: 1.0 + (2.0-1.0)*0.5 = 1.5
        let result = decay_weight(2.0, 1.0, 365.0);
        assert!((result - 1.5).abs() < 0.001);
    }

    #[test]
    fn test_full_decay_at_many_years() {
        // After many half-lives, should converge to static_default
        let result = decay_weight(5.0, 1.0, 365.0 * 20.0);
        assert!((result - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_decay_below_default() {
        // stored=0.5, default=1.0: decays UP toward default
        let result = decay_weight(0.5, 1.0, 365.0);
        assert!((result - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_nan_stored_returns_default() {
        assert_eq!(decay_weight(f64::NAN, 1.0, 100.0), 1.0);
    }

    #[test]
    fn test_negative_days_returns_stored() {
        assert_eq!(decay_weight(2.0, 1.0, -5.0), 2.0);
    }

    #[test]
    fn test_nan_days_returns_stored() {
        assert_eq!(decay_weight(2.0, 1.0, f64::NAN), 2.0);
    }
}

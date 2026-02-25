//! Bayesian 7-signal confidence model for contract matching.

/// Compute Bayesian confidence from 7 signals.
///
/// Signals:
/// 1. Path similarity (0-1)
/// 2. Field overlap (0-1)
/// 3. Type compatibility (0-1)
/// 4. Response shape match (0-1)
/// 5. Temporal stability (0-1)
/// 6. Cross-validation (0-1)
/// 7. Consumer agreement (0-1)
pub fn bayesian_confidence(signals: &[f64; 7]) -> f64 {
    let weights = [0.25, 0.20, 0.15, 0.15, 0.10, 0.08, 0.07];

    let weighted_sum: f64 = signals
        .iter()
        .zip(weights.iter())
        .map(|(s, w)| s.clamp(0.0, 1.0) * w)
        .sum();

    weighted_sum.clamp(0.0, 1.0)
}

/// Verify that each signal independently affects the confidence score.
pub fn signal_independence_check() -> bool {
    let baseline = [0.5; 7];
    let base_score = bayesian_confidence(&baseline);

    for i in 0..7 {
        let mut boosted = baseline;
        boosted[i] = 1.0;
        let boosted_score = bayesian_confidence(&boosted);
        if (boosted_score - base_score).abs() < 0.001 {
            return false; // Signal i has no effect
        }
    }
    true
}

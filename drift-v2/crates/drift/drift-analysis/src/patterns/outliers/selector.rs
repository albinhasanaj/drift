//! Auto-select method based on sample size and data characteristics.
//!
//! Phase C hardening: normality check for method selection, ensemble consensus
//! scoring, improved ESD heuristic, per-method diagnostics.

use std::collections::HashMap;

use super::types::{DeviationScore, OutlierConfig, OutlierMethod, OutlierResult, SignificanceTier};
use super::{esd, grubbs, iqr, mad, rule_based, zscore};

/// The top-level outlier detector with automatic method selection.
pub struct OutlierDetector {
    config: OutlierConfig,
    rules: Vec<rule_based::OutlierRule>,
}

impl OutlierDetector {
    /// Create a new detector with default configuration and domain-specific rules.
    pub fn new() -> Self {
        Self {
            config: OutlierConfig::default(),
            rules: vec![
                rule_based::zero_confidence_rule(),
                rule_based::confidence_cliff_rule(),
                rule_based::file_isolation_rule(),
            ],
        }
    }

    /// Create a detector with custom configuration and default rules.
    pub fn with_config(config: OutlierConfig) -> Self {
        Self {
            config,
            rules: vec![
                rule_based::zero_confidence_rule(),
                rule_based::confidence_cliff_rule(),
                rule_based::file_isolation_rule(),
            ],
        }
    }

    /// Add a custom rule.
    pub fn add_rule(&mut self, rule: rule_based::OutlierRule) {
        self.rules.push(rule);
    }

    /// Detect outliers with automatic method selection and ensemble consensus.
    ///
    /// Returns all detected outliers, merged, deduplicated, and consensus-scored.
    pub fn detect(&self, values: &[f64]) -> Vec<OutlierResult> {
        let n = values.len();

        if n < self.config.min_sample_size {
            return rule_based::detect(values, &self.rules);
        }

        // Track which methods flag each index
        let mut index_methods: HashMap<usize, Vec<OutlierResult>> = HashMap::new();

        // Primary statistical method based on sample size + normality (PI-OUT-01/02)
        let primary = self.select_primary_method(values);
        let statistical = match primary {
            OutlierMethod::ZScore => {
                zscore::detect(values, self.config.z_threshold, self.config.max_iterations)
            }
            OutlierMethod::Grubbs => grubbs::detect(values, self.config.alpha),
            OutlierMethod::GeneralizedEsd => {
                // PI-OUT-08: sqrt heuristic for max_outliers
                let max_outliers = ((n as f64).sqrt().ceil() as usize).clamp(1, 10);
                esd::detect(values, max_outliers, self.config.alpha)
            }
            OutlierMethod::Iqr => iqr::detect(values, self.config.iqr_multiplier),
            OutlierMethod::Mad => mad::detect(values, self.config.mad_threshold),
            _ => Vec::new(),
        };
        for r in statistical {
            index_methods.entry(r.index).or_default().push(r);
        }

        // Supplementary IQR for n >= 30 (cross-validation)
        if n >= 30 && primary != OutlierMethod::Iqr {
            let iqr_results = iqr::detect(values, self.config.iqr_multiplier);
            for r in iqr_results {
                index_methods.entry(r.index).or_default().push(r);
            }
        }

        // MAD for robustness check
        if primary != OutlierMethod::Mad {
            let mad_results = mad::detect(values, self.config.mad_threshold);
            for r in mad_results {
                index_methods.entry(r.index).or_default().push(r);
            }
        }

        // Rule-based (always active)
        let rule_results = rule_based::detect(values, &self.rules);
        for r in rule_results {
            index_methods.entry(r.index).or_default().push(r);
        }

        // PI-OUT-03/04: Ensemble consensus scoring
        let mut final_results = Vec::new();
        for (_index, methods) in index_methods {
            let method_count = methods.len();
            let non_rule_count = methods.iter()
                .filter(|r| r.method != OutlierMethod::RuleBased)
                .count();

            // Pick the result with highest deviation score as base
            let mut best = methods.into_iter()
                .max_by(|a, b| a.deviation_score.value().partial_cmp(&b.deviation_score.value()).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap();

            if method_count > 1 {
                // PI-OUT-03: Boost multi-method agreement
                let boost = (method_count as f64 / 2.0).min(1.5);
                let boosted = best.deviation_score.value() * boost;
                best.deviation_score = DeviationScore::new(boosted);
                best.significance = SignificanceTier::from_deviation(boosted);
            } else if non_rule_count == 1 {
                // PI-OUT-04: Downgrade single non-rule-based method outliers
                best.significance = downgrade_tier(best.significance);
            }

            final_results.push(best);
        }

        final_results
    }

    /// Detect with diagnostics — returns both results and per-method stats.
    pub fn detect_with_diagnostics(&self, values: &[f64]) -> (Vec<OutlierResult>, OutlierDiagnostics) {
        let results = self.detect(values);

        let mut per_method: HashMap<OutlierMethod, usize> = HashMap::new();
        for r in &results {
            *per_method.entry(r.method).or_insert(0) += 1;
        }

        let outlier_rate = if values.is_empty() {
            0.0
        } else {
            results.len() as f64 / values.len() as f64
        };

        let diag = OutlierDiagnostics {
            total_values: values.len(),
            total_outliers: results.len(),
            outlier_rate,
            per_method,
            is_normal: values.len() >= 10 && is_approximately_normal(values),
        };

        (results, diag)
    }

    /// Select the primary statistical method based on sample size and normality.
    ///
    /// PI-OUT-01/02: When data is non-normal (|skewness| > 2 or |kurtosis| > 7),
    /// prefer IQR/MAD over Z-Score/Grubbs.
    pub fn select_primary_method(&self, values: &[f64]) -> OutlierMethod {
        let n = values.len();
        let normal = is_approximately_normal(values);

        if n >= 30 {
            if normal {
                OutlierMethod::ZScore
            } else {
                OutlierMethod::Iqr
            }
        } else if n >= 25 {
            if normal {
                OutlierMethod::GeneralizedEsd
            } else {
                OutlierMethod::Mad
            }
        } else if n >= 10 {
            if normal {
                OutlierMethod::Grubbs
            } else {
                OutlierMethod::Mad
            }
        } else {
            OutlierMethod::RuleBased
        }
    }
}

/// Check if data is approximately normal using skewness and kurtosis.
///
/// Returns false if |skewness| > 2 or |excess_kurtosis| > 7.
pub fn is_approximately_normal(values: &[f64]) -> bool {
    if values.len() < 4 {
        return true; // Not enough data to assess
    }

    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;

    let m2: f64 = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    let m3: f64 = values.iter().map(|v| (v - mean).powi(3)).sum::<f64>() / n;
    let m4: f64 = values.iter().map(|v| (v - mean).powi(4)).sum::<f64>() / n;

    if m2 <= 0.0 {
        return true; // All identical values
    }

    let skewness = m3 / m2.powf(1.5);
    let kurtosis = m4 / m2.powi(2) - 3.0; // Excess kurtosis

    skewness.abs() <= 2.0 && kurtosis.abs() <= 7.0
}

/// Downgrade a significance tier by one level.
fn downgrade_tier(tier: SignificanceTier) -> SignificanceTier {
    match tier {
        SignificanceTier::Critical => SignificanceTier::High,
        SignificanceTier::High => SignificanceTier::Moderate,
        SignificanceTier::Moderate => SignificanceTier::Low,
        SignificanceTier::Low => SignificanceTier::Low,
    }
}

/// Per-method outlier detection diagnostics.
#[derive(Debug, Clone)]
pub struct OutlierDiagnostics {
    /// Total values analyzed.
    pub total_values: usize,
    /// Total outliers detected.
    pub total_outliers: usize,
    /// Outlier rate (outliers / total).
    pub outlier_rate: f64,
    /// Detections per method.
    pub per_method: HashMap<OutlierMethod, usize>,
    /// Whether the data was assessed as approximately normal.
    pub is_normal: bool,
}

impl Default for OutlierDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate n normal-ish values centered at 0.8 with small spread.
    fn normal_values(n: usize) -> Vec<f64> {
        (0..n).map(|i| 0.8 + (i as f64 % 5.0) * 0.01).collect()
    }

    /// Helper: generate n highly skewed values (right-skewed spike distribution).
    /// 90% of values near 1.0, 10% are extreme spikes — guarantees |skewness| > 2.
    fn skewed_values(n: usize) -> Vec<f64> {
        let n_normal = (n as f64 * 0.9).ceil() as usize;
        let n_spikes = n - n_normal;
        let mut vals: Vec<f64> = vec![1.0; n_normal];
        for i in 0..n_spikes {
            vals.push(1000.0 * (i as f64 + 1.0));
        }
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap());
        vals
    }

    // --- PIT-OUT-02: Normal data selects Z-Score for n>=30 ---
    #[test]
    fn test_auto_select_zscore_normal() {
        let detector = OutlierDetector::new();
        let vals = normal_values(30);
        assert_eq!(detector.select_primary_method(&vals), OutlierMethod::ZScore);
        let vals = normal_values(100);
        assert_eq!(detector.select_primary_method(&vals), OutlierMethod::ZScore);
    }

    // --- PIT-OUT-01: Skewed data selects IQR or MAD, not Z-Score ---
    #[test]
    fn test_auto_select_iqr_skewed() {
        let detector = OutlierDetector::new();
        let vals = skewed_values(50);
        let method = detector.select_primary_method(&vals);
        assert!(
            method == OutlierMethod::Iqr || method == OutlierMethod::Mad,
            "Skewed data should select IQR or MAD, got {:?}",
            method
        );
    }

    #[test]
    fn test_auto_select_grubbs_normal() {
        let detector = OutlierDetector::new();
        let vals = normal_values(10);
        assert_eq!(detector.select_primary_method(&vals), OutlierMethod::Grubbs);
        let vals = normal_values(24);
        assert_eq!(detector.select_primary_method(&vals), OutlierMethod::Grubbs);
    }

    #[test]
    fn test_auto_select_esd_normal() {
        let detector = OutlierDetector::new();
        let vals = normal_values(25);
        assert_eq!(detector.select_primary_method(&vals), OutlierMethod::GeneralizedEsd);
        let vals = normal_values(29);
        assert_eq!(detector.select_primary_method(&vals), OutlierMethod::GeneralizedEsd);
    }

    #[test]
    fn test_auto_select_rule_based_small() {
        let detector = OutlierDetector::new();
        let vals = normal_values(5);
        assert_eq!(detector.select_primary_method(&vals), OutlierMethod::RuleBased);
    }

    #[test]
    fn test_detect_with_clear_outlier() {
        let detector = OutlierDetector::new();
        let mut values: Vec<f64> = vec![0.9; 50];
        values[0] = 0.01; // Clear outlier
        let results = detector.detect(&values);
        assert!(!results.is_empty());
    }

    // --- PIT-OUT-07: ESD max_outliers uses sqrt heuristic ---
    #[test]
    fn test_esd_sqrt_heuristic() {
        // n=25 -> sqrt(25)=5, clamped to 5
        assert_eq!(((25f64).sqrt().ceil() as usize).clamp(1, 10), 5);
        // n=100 -> sqrt(100)=10, clamped to 10
        assert_eq!(((100f64).sqrt().ceil() as usize).clamp(1, 10), 10);
        // n=4 -> sqrt(4)=2, clamped to 2
        assert_eq!(((4f64).sqrt().ceil() as usize).clamp(1, 10), 2);
    }

    // --- PIT-OUT-08: Per-method diagnostics ---
    #[test]
    fn test_detect_with_diagnostics() {
        let detector = OutlierDetector::new();
        let mut values: Vec<f64> = vec![0.9; 50];
        values[0] = 0.01;
        let (results, diag) = detector.detect_with_diagnostics(&values);
        assert!(!results.is_empty());
        assert_eq!(diag.total_values, 50);
        assert!(diag.total_outliers > 0);
        assert!(diag.outlier_rate > 0.0);
    }

    // --- PIT-OUT-09: Z-Score on uniform data: 0 outliers ---
    #[test]
    fn test_uniform_data_no_outliers() {
        let detector = OutlierDetector::new();
        let values: Vec<f64> = vec![0.85; 50];
        let results = detector.detect(&values);
        // Uniform data should have no statistical outliers
        // (rule-based zero_confidence won't fire on 0.85)
        assert!(
            results.is_empty(),
            "Uniform data should have 0 outliers, got {}",
            results.len()
        );
    }

    // --- PIT-OUT-16: Empty input ---
    #[test]
    fn test_empty_input_no_crash() {
        let detector = OutlierDetector::new();
        let results = detector.detect(&[]);
        assert!(results.is_empty());
    }

    // --- Normality check tests ---
    #[test]
    fn test_is_normal_uniform() {
        let vals: Vec<f64> = vec![0.9; 50];
        assert!(is_approximately_normal(&vals));
    }

    #[test]
    fn test_is_normal_skewed() {
        let vals = skewed_values(50);
        assert!(!is_approximately_normal(&vals), "Highly skewed data should not be normal");
    }

    #[test]
    fn test_is_normal_small_sample() {
        // < 4 values: always returns true
        assert!(is_approximately_normal(&[1.0, 2.0, 3.0]));
    }

    // --- PIT-OUT-01: Skewed data for n=10-24 selects MAD ---
    #[test]
    fn test_auto_select_mad_skewed_small() {
        let detector = OutlierDetector::new();
        let vals = skewed_values(15);
        let method = detector.select_primary_method(&vals);
        assert_eq!(method, OutlierMethod::Mad, "Skewed small sample should use MAD");
    }
}

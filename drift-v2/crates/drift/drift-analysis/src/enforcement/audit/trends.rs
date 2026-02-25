//! Trend prediction via linear regression on health_trends table.

use super::types::*;

/// Trend analyzer: 7-day rolling averages and linear regression prediction.
pub struct TrendAnalyzer;

impl TrendAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Classify trend direction from a series of health scores.
    /// Uses ±2 threshold for improving/declining (preserved from v1).
    pub fn classify_trend(&self, scores: &[f64]) -> TrendDirection {
        if scores.len() < 2 {
            return TrendDirection::Stable;
        }

        let n = scores.len();
        let recent_avg = if n >= 7 {
            scores[n - 7..].iter().sum::<f64>() / 7.0
        } else {
            scores.iter().sum::<f64>() / n as f64
        };

        let older_avg = if n >= 14 {
            scores[n - 14..n - 7].iter().sum::<f64>() / 7.0
        } else if n >= 2 {
            scores[..n / 2].iter().sum::<f64>() / (n / 2) as f64
        } else {
            recent_avg
        };

        let delta = recent_avg - older_avg;
        if delta > 2.0 {
            TrendDirection::Improving
        } else if delta < -2.0 {
            TrendDirection::Declining
        } else {
            TrendDirection::Stable
        }
    }

    /// Classify pattern growth rate.
    pub fn classify_growth(&self, daily_counts: &[f64]) -> PatternGrowth {
        if daily_counts.is_empty() {
            return PatternGrowth::Stagnant;
        }
        let avg_daily = daily_counts.iter().sum::<f64>() / daily_counts.len() as f64;
        if avg_daily > 5.0 {
            PatternGrowth::Rapid
        } else if avg_daily < 0.5 {
            PatternGrowth::Stagnant
        } else {
            PatternGrowth::Healthy
        }
    }

    /// Predict future health score via simple linear regression.
    pub fn predict(&self, scores: &[f64]) -> Option<TrendPrediction> {
        if scores.len() < 5 {
            return None;
        }

        let n = scores.len() as f64;
        let x_values: Vec<f64> = (0..scores.len()).map(|i| i as f64).collect();

        // Linear regression: y = mx + b
        let x_mean = x_values.iter().sum::<f64>() / n;
        let y_mean = scores.iter().sum::<f64>() / n;

        let mut numerator = 0.0;
        let mut denominator = 0.0;
        for i in 0..scores.len() {
            let x_diff = x_values[i] - x_mean;
            let y_diff = scores[i] - y_mean;
            numerator += x_diff * y_diff;
            denominator += x_diff * x_diff;
        }

        if denominator.abs() < f64::EPSILON {
            return None;
        }

        let slope = numerator / denominator;
        let intercept = y_mean - slope * x_mean;

        // Predict 7 and 30 days ahead
        let last_x = scores.len() as f64 - 1.0;
        let predicted_7d = (slope * (last_x + 7.0) + intercept).clamp(0.0, 100.0);
        let predicted_30d = (slope * (last_x + 30.0) + intercept).clamp(0.0, 100.0);

        // Compute R² for confidence interval
        let ss_res: f64 = scores
            .iter()
            .enumerate()
            .map(|(i, y)| {
                let predicted = slope * i as f64 + intercept;
                (y - predicted).powi(2)
            })
            .sum();
        let ss_tot: f64 = scores.iter().map(|y| (y - y_mean).powi(2)).sum();
        let r_squared = if ss_tot > 0.0 {
            1.0 - (ss_res / ss_tot)
        } else {
            0.0
        };

        let direction = if slope > 0.1 {
            TrendDirection::Improving
        } else if slope < -0.1 {
            TrendDirection::Declining
        } else {
            TrendDirection::Stable
        };

        Some(TrendPrediction {
            predicted_score_7d: predicted_7d,
            predicted_score_30d: predicted_30d,
            slope,
            confidence_interval: r_squared,
            direction,
        })
    }

    /// Detect anomalies via Z-score.
    pub fn detect_anomalies(
        &self,
        metric_name: &str,
        values: &[f64],
        threshold: f64,
    ) -> Vec<AuditAnomaly> {
        if values.len() < 3 {
            return Vec::new();
        }

        let n = values.len() as f64;
        let mean = values.iter().sum::<f64>() / n;
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
        let std_dev = variance.sqrt();

        if std_dev < f64::EPSILON {
            return Vec::new();
        }

        let mut anomalies = Vec::new();
        let last_value = values[values.len() - 1];
        let z_score = (last_value - mean) / std_dev;

        if z_score.abs() > threshold {
            anomalies.push(AuditAnomaly {
                metric: metric_name.to_string(),
                z_score,
                value: last_value,
                mean,
                std_dev,
                message: format!(
                    "Anomaly in {metric_name}: value {last_value:.2} (z-score: {z_score:.2}, mean: {mean:.2})"
                ),
            });
        }

        anomalies
    }
}

impl Default for TrendAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

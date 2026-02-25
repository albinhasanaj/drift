//! Degradation detection — health score declining over time.

use super::types::*;

/// Degradation detector: compares current snapshot against previous.
pub struct DegradationDetector {
    /// Warning threshold: health drop of this many points triggers warning.
    pub warning_threshold: f64,
    /// Critical threshold: health drop of this many points triggers critical.
    pub critical_threshold: f64,
    /// Confidence drop warning threshold.
    pub confidence_warning: f64,
    /// Confidence drop critical threshold.
    pub confidence_critical: f64,
}

impl DegradationDetector {
    pub fn new() -> Self {
        Self {
            warning_threshold: 5.0,
            critical_threshold: 15.0,
            confidence_warning: 0.05,
            confidence_critical: 0.15,
        }
    }

    /// Detect degradation between current and previous snapshots.
    /// Returns empty if the snapshots have incompatible scopes (different root_path).
    pub fn detect(
        &self,
        current: &AuditSnapshot,
        previous: &AuditSnapshot,
    ) -> Vec<DegradationAlert> {
        // Guard: skip comparison if scans have different scopes.
        // Comparing a scan of "packages/drift-cli" (46 files) against a scan of "." (970 files)
        // would produce false "100% decrease" alerts for every pattern.
        if let (Some(curr_root), Some(prev_root)) = (&current.root_path, &previous.root_path) {
            if curr_root != prev_root {
                return Vec::new();
            }
        }
        // Also skip if file counts differ by more than 50% — likely a scope change
        // even if root_path wasn't set (backward compatibility with old snapshots).
        if let (Some(curr_files), Some(prev_files)) = (current.total_files, previous.total_files) {
            if curr_files > 0 && prev_files > 0 {
                let ratio = curr_files as f64 / prev_files as f64;
                if ratio < 0.5 || ratio > 2.0 {
                    return Vec::new();
                }
            }
        }

        let mut alerts = Vec::new();

        // Health score drop
        let health_delta = current.health_score - previous.health_score;
        if health_delta <= -self.critical_threshold {
            alerts.push(DegradationAlert {
                alert_type: AlertType::HealthDrop,
                severity: AlertSeverity::Critical,
                message: format!(
                    "Critical health regression: {:.1} → {:.1} ({:+.1} points)",
                    previous.health_score, current.health_score, health_delta
                ),
                current_value: current.health_score,
                previous_value: previous.health_score,
                delta: health_delta,
            });
        } else if health_delta <= -self.warning_threshold {
            alerts.push(DegradationAlert {
                alert_type: AlertType::HealthDrop,
                severity: AlertSeverity::Warning,
                message: format!(
                    "Health score declining: {:.1} → {:.1} ({:+.1} points)",
                    previous.health_score, current.health_score, health_delta
                ),
                current_value: current.health_score,
                previous_value: previous.health_score,
                delta: health_delta,
            });
        }

        // Confidence drop
        let conf_delta = current.avg_confidence - previous.avg_confidence;
        if conf_delta <= -self.confidence_critical {
            alerts.push(DegradationAlert {
                alert_type: AlertType::ConfidenceDrop,
                severity: AlertSeverity::Critical,
                message: format!(
                    "Critical confidence drop: {:.2} → {:.2}",
                    previous.avg_confidence, current.avg_confidence
                ),
                current_value: current.avg_confidence,
                previous_value: previous.avg_confidence,
                delta: conf_delta,
            });
        } else if conf_delta <= -self.confidence_warning {
            alerts.push(DegradationAlert {
                alert_type: AlertType::ConfidenceDrop,
                severity: AlertSeverity::Warning,
                message: format!(
                    "Confidence declining: {:.2} → {:.2}",
                    previous.avg_confidence, current.avg_confidence
                ),
                current_value: current.avg_confidence,
                previous_value: previous.avg_confidence,
                delta: conf_delta,
            });
        }

        alerts
    }
}

impl Default for DegradationDetector {
    fn default() -> Self {
        Self::new()
    }
}

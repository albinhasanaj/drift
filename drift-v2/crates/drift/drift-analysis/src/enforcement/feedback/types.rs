//! Feedback loop types.

use serde::{Deserialize, Serialize};

/// Actions a developer can take on a violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackAction {
    Fix,
    Dismiss,
    Suppress,
    Escalate,
}

/// Dismissal reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DismissalReason {
    FalsePositive,
    WontFix,
    NotApplicable,
    Duplicate,
}

impl DismissalReason {
    pub fn counts_as_false_positive(&self) -> bool {
        matches!(self, Self::FalsePositive | Self::NotApplicable)
    }
}

/// Metrics for a single detector's feedback.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedbackMetrics {
    pub detector_id: String,
    pub total_findings: u64,
    pub fixed: u64,
    pub dismissed: u64,
    pub suppressed: u64,
    pub escalated: u64,
    pub false_positives: u64,
    pub fp_rate: f64,
    pub action_rate: f64,
    pub days_above_threshold: u32,
}

impl FeedbackMetrics {
    /// Compute the false positive rate.
    /// FP rate = (dismissed + ignored) / (fixed + dismissed + ignored + auto_fixed)
    pub fn compute_fp_rate(&mut self) {
        let acted_on = self.fixed + self.dismissed;
        if acted_on == 0 {
            self.fp_rate = 0.0;
        } else {
            self.fp_rate = self.false_positives as f64 / acted_on as f64;
        }
    }

    /// Compute the action rate (how many findings were acted upon).
    pub fn compute_action_rate(&mut self) {
        if self.total_findings == 0 {
            self.action_rate = 0.0;
        } else {
            let acted = self.fixed + self.dismissed + self.suppressed + self.escalated;
            self.action_rate = acted as f64 / self.total_findings as f64;
        }
    }
}

/// A feedback record for a single violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRecord {
    pub violation_id: String,
    pub pattern_id: String,
    pub detector_id: String,
    pub action: FeedbackAction,
    pub dismissal_reason: Option<DismissalReason>,
    pub reason: Option<String>,
    pub author: Option<String>,
    pub timestamp: u64,
}

/// Detector health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectorHealthStatus {
    Healthy,
    Warning,
    Disabled,
}

//! Tricorder-style false-positive tracking per detector, auto-disable.

use std::collections::HashMap;

use super::types::*;

/// Feedback tracker: tracks FP rates per detector and auto-disables noisy ones.
pub struct FeedbackTracker {
    /// FP rate threshold for alert (10%).
    pub alert_threshold: f64,
    /// FP rate threshold for auto-disable (20%).
    pub disable_threshold: f64,
    /// Sustained period in days before auto-disable.
    pub sustained_days: u32,
    /// Minimum findings before FP rate is meaningful.
    pub min_findings: u64,
    /// Per-detector metrics.
    metrics: HashMap<String, FeedbackMetrics>,
    /// Abuse detection: per-author dismiss counts.
    dismiss_counts: HashMap<String, Vec<u64>>,
}

impl FeedbackTracker {
    pub fn new() -> Self {
        Self {
            alert_threshold: 0.10,
            disable_threshold: 0.20,
            sustained_days: 30,
            min_findings: 10,
            metrics: HashMap::new(),
            dismiss_counts: HashMap::new(),
        }
    }

    /// Record a feedback action.
    pub fn record(&mut self, record: &FeedbackRecord) {
        let metrics = self
            .metrics
            .entry(record.detector_id.clone())
            .or_insert_with(|| FeedbackMetrics {
                detector_id: record.detector_id.clone(),
                ..Default::default()
            });

        metrics.total_findings += 1;

        match record.action {
            FeedbackAction::Fix => metrics.fixed += 1,
            FeedbackAction::Dismiss => {
                metrics.dismissed += 1;
                if let Some(reason) = &record.dismissal_reason {
                    if reason.counts_as_false_positive() {
                        metrics.false_positives += 1;
                    }
                }
            }
            FeedbackAction::Suppress => metrics.suppressed += 1,
            FeedbackAction::Escalate => metrics.escalated += 1,
        }

        metrics.compute_fp_rate();
        metrics.compute_action_rate();

        // Track dismiss counts for abuse detection
        if record.action == FeedbackAction::Dismiss {
            if let Some(ref author) = record.author {
                self.dismiss_counts
                    .entry(author.clone())
                    .or_default()
                    .push(record.timestamp);
            }
        }
    }

    /// Get metrics for a specific detector.
    pub fn get_metrics(&self, detector_id: &str) -> Option<&FeedbackMetrics> {
        self.metrics.get(detector_id)
    }

    /// Get all detector metrics.
    pub fn all_metrics(&self) -> &HashMap<String, FeedbackMetrics> {
        &self.metrics
    }

    /// Check which detectors should be disabled.
    /// Auto-disable rule: >20% FP rate sustained for 30+ days.
    pub fn check_auto_disable(&self) -> Vec<String> {
        self.metrics
            .iter()
            .filter(|(_, m)| {
                let acted_on = m.fixed + m.dismissed;
                acted_on >= self.min_findings
                    && m.fp_rate > self.disable_threshold
                    && m.days_above_threshold >= self.sustained_days
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Check which detectors should receive alerts.
    pub fn check_alerts(&self) -> Vec<String> {
        self.metrics
            .iter()
            .filter(|(_, m)| {
                let acted_on = m.fixed + m.dismissed;
                acted_on >= self.min_findings && m.fp_rate > self.alert_threshold
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Detect feedback abuse: >100 dismissals in 1 minute from same user.
    pub fn detect_abuse(&self, window_seconds: u64, threshold: usize) -> Vec<String> {
        let mut abusers = Vec::new();

        for (author, timestamps) in &self.dismiss_counts {
            if timestamps.len() < threshold {
                continue;
            }

            // Check if threshold dismissals occurred within the window
            let len = timestamps.len();
            if len >= threshold {
                let recent = &timestamps[len - threshold..];
                if let (Some(&first), Some(&last)) = (recent.first(), recent.last()) {
                    if last - first <= window_seconds {
                        abusers.push(author.clone());
                    }
                }
            }
        }

        abusers
    }

    /// Update days_above_threshold for a detector.
    pub fn update_sustained_days(&mut self, detector_id: &str, days: u32) {
        if let Some(metrics) = self.metrics.get_mut(detector_id) {
            metrics.days_above_threshold = days;
        }
    }

    /// Get the FP rate for a specific detector.
    pub fn fp_rate(&self, detector_id: &str) -> f64 {
        self.metrics
            .get(detector_id)
            .map_or(0.0, |m| m.fp_rate)
    }
}

impl super::stats_provider::FeedbackStatsProvider for FeedbackTracker {
    fn fp_rate_for_detector(&self, detector_id: &str) -> f64 {
        self.metrics
            .get(detector_id)
            .map_or(0.0, |m| m.fp_rate)
    }

    fn fp_rate_for_pattern(&self, pattern_id: &str) -> f64 {
        // Pattern IDs may map to detector IDs; check both
        self.metrics
            .get(pattern_id)
            .map_or(0.0, |m| m.fp_rate)
    }

    fn is_detector_disabled(&self, detector_id: &str) -> bool {
        self.check_auto_disable().contains(&detector_id.to_string())
    }

    fn total_actions_for_detector(&self, detector_id: &str) -> u64 {
        self.metrics
            .get(detector_id)
            .map_or(0, |m| m.total_findings)
    }
}

impl Default for FeedbackTracker {
    fn default() -> Self {
        Self::new()
    }
}

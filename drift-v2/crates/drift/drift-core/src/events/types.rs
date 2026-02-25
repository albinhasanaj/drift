//! Event payload types for all 24 Drift events.

use std::path::PathBuf;

/// Payload for `on_scan_started`.
#[derive(Debug, Clone)]
pub struct ScanStartedEvent {
    pub root: PathBuf,
    pub file_count: Option<usize>,
}

/// Payload for `on_scan_progress`.
#[derive(Debug, Clone)]
pub struct ScanProgressEvent {
    pub processed: usize,
    pub total: usize,
}

/// Payload for `on_scan_complete`.
#[derive(Debug, Clone)]
pub struct ScanCompleteEvent {
    pub added: usize,
    pub modified: usize,
    pub removed: usize,
    pub unchanged: usize,
    pub duration_ms: u64,
}

/// Payload for `on_scan_error`.
#[derive(Debug, Clone)]
pub struct ScanErrorEvent {
    pub message: String,
}

/// Payload for `on_pattern_discovered`.
#[derive(Debug, Clone)]
pub struct PatternDiscoveredEvent {
    pub pattern_id: String,
    pub category: String,
    pub confidence: f64,
}

/// Payload for `on_pattern_approved`.
#[derive(Debug, Clone)]
pub struct PatternApprovedEvent {
    pub pattern_id: String,
}

/// Payload for `on_pattern_ignored`.
#[derive(Debug, Clone)]
pub struct PatternIgnoredEvent {
    pub pattern_id: String,
    pub reason: String,
}

/// Payload for `on_pattern_merged`.
#[derive(Debug, Clone)]
pub struct PatternMergedEvent {
    pub kept_id: String,
    pub merged_id: String,
}

/// Payload for `on_violation_detected`.
#[derive(Debug, Clone)]
pub struct ViolationDetectedEvent {
    pub violation_id: String,
    pub pattern_id: String,
    pub file: PathBuf,
    pub line: usize,
    pub message: String,
}

/// Payload for `on_violation_dismissed`.
#[derive(Debug, Clone)]
pub struct ViolationDismissedEvent {
    pub violation_id: String,
    pub reason: String,
}

/// Payload for `on_violation_fixed`.
#[derive(Debug, Clone)]
pub struct ViolationFixedEvent {
    pub violation_id: String,
}

/// Payload for `on_gate_evaluated`.
#[derive(Debug, Clone)]
pub struct GateEvaluatedEvent {
    pub gate_name: String,
    pub passed: bool,
    pub score: Option<f64>,
    pub message: String,
}

/// Payload for `on_regression_detected`.
#[derive(Debug, Clone)]
pub struct RegressionDetectedEvent {
    pub pattern_id: String,
    pub previous_score: f64,
    pub current_score: f64,
}

/// Payload for `on_enforcement_changed`.
#[derive(Debug, Clone)]
pub struct EnforcementChangedEvent {
    pub gate_name: String,
    pub old_level: String,
    pub new_level: String,
}

/// Payload for `on_constraint_approved`.
#[derive(Debug, Clone)]
pub struct ConstraintApprovedEvent {
    pub constraint_id: String,
}

/// Payload for `on_constraint_violated`.
#[derive(Debug, Clone)]
pub struct ConstraintViolatedEvent {
    pub constraint_id: String,
    pub message: String,
}

/// Payload for `on_decision_mined`.
#[derive(Debug, Clone)]
pub struct DecisionMinedEvent {
    pub decision_id: String,
    pub category: String,
}

/// Payload for `on_decision_reversed`.
#[derive(Debug, Clone)]
pub struct DecisionReversedEvent {
    pub decision_id: String,
    pub reason: String,
}

/// Payload for `on_adr_detected`.
#[derive(Debug, Clone)]
pub struct AdrDetectedEvent {
    pub adr_id: String,
    pub title: String,
}

/// Payload for `on_boundary_discovered`.
#[derive(Debug, Clone)]
pub struct BoundaryDiscoveredEvent {
    pub boundary_id: String,
    pub orm: String,
    pub model: String,
}

/// Payload for `on_detector_alert`.
#[derive(Debug, Clone)]
pub struct DetectorAlertEvent {
    pub detector_id: String,
    pub false_positive_rate: f64,
}

/// Payload for `on_detector_disabled`.
#[derive(Debug, Clone)]
pub struct DetectorDisabledEvent {
    pub detector_id: String,
    pub reason: String,
}

/// Payload for `on_feedback_abuse_detected`.
#[derive(Debug, Clone)]
pub struct FeedbackAbuseDetectedEvent {
    pub user_id: String,
    pub pattern: String,
}

/// Payload for `on_error`.
#[derive(Debug, Clone)]
pub struct ErrorEvent {
    pub message: String,
    pub error_code: String,
}

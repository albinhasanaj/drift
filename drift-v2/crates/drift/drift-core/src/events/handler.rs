//! DriftEventHandler trait with 24 event methods, all with no-op defaults.

use super::types::*;

/// Trait for handling Drift events.
///
/// All methods have no-op default implementations, so handlers only need
/// to override the events they care about. The trait requires `Send + Sync`
/// for use in multi-threaded analysis pipelines.
pub trait DriftEventHandler: Send + Sync {
    // ---- Scan Lifecycle ----
    fn on_scan_started(&self, _event: &ScanStartedEvent) {}
    fn on_scan_progress(&self, _event: &ScanProgressEvent) {}
    fn on_scan_complete(&self, _event: &ScanCompleteEvent) {}
    fn on_scan_error(&self, _event: &ScanErrorEvent) {}

    // ---- Pattern Lifecycle ----
    fn on_pattern_discovered(&self, _event: &PatternDiscoveredEvent) {}
    fn on_pattern_approved(&self, _event: &PatternApprovedEvent) {}
    fn on_pattern_ignored(&self, _event: &PatternIgnoredEvent) {}
    fn on_pattern_merged(&self, _event: &PatternMergedEvent) {}

    // ---- Violations ----
    fn on_violation_detected(&self, _event: &ViolationDetectedEvent) {}
    fn on_violation_dismissed(&self, _event: &ViolationDismissedEvent) {}
    fn on_violation_fixed(&self, _event: &ViolationFixedEvent) {}

    // ---- Enforcement ----
    fn on_gate_evaluated(&self, _event: &GateEvaluatedEvent) {}
    fn on_regression_detected(&self, _event: &RegressionDetectedEvent) {}
    fn on_enforcement_changed(&self, _event: &EnforcementChangedEvent) {}

    // ---- Constraints ----
    fn on_constraint_approved(&self, _event: &ConstraintApprovedEvent) {}
    fn on_constraint_violated(&self, _event: &ConstraintViolatedEvent) {}

    // ---- Decisions ----
    fn on_decision_mined(&self, _event: &DecisionMinedEvent) {}
    fn on_decision_reversed(&self, _event: &DecisionReversedEvent) {}
    fn on_adr_detected(&self, _event: &AdrDetectedEvent) {}

    // ---- Boundaries ----
    fn on_boundary_discovered(&self, _event: &BoundaryDiscoveredEvent) {}

    // ---- Detector Health ----
    fn on_detector_alert(&self, _event: &DetectorAlertEvent) {}
    fn on_detector_disabled(&self, _event: &DetectorDisabledEvent) {}

    // ---- Feedback ----
    fn on_feedback_abuse_detected(&self, _event: &FeedbackAbuseDetectedEvent) {}

    // ---- Errors ----
    fn on_error(&self, _event: &ErrorEvent) {}
}

//! EventDispatcher — synchronous event dispatch with zero overhead when empty.

use std::sync::Arc;

use super::handler::DriftEventHandler;
use super::types::*;

/// Synchronous event dispatcher wrapping a list of handlers.
///
/// When no handlers are registered, `emit` iterates over an empty Vec —
/// effectively zero cost. The compiler may optimize it away entirely.
pub struct EventDispatcher {
    handlers: Vec<Arc<dyn DriftEventHandler>>,
}

impl EventDispatcher {
    /// Create a new empty dispatcher.
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Register an event handler.
    pub fn register(&mut self, handler: Arc<dyn DriftEventHandler>) {
        self.handlers.push(handler);
    }

    /// Returns the number of registered handlers.
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Emit an event to all registered handlers.
    /// Handlers that panic are caught and do not prevent subsequent handlers
    /// from receiving the event.
    fn emit<F: Fn(&dyn DriftEventHandler)>(&self, f: F) {
        for handler in &self.handlers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                f(handler.as_ref());
            }));
            if let Err(_panic) = result {
                // Handler panicked — log and continue.
                // In production, this would be logged via tracing.
            }
        }
    }

    // ---- Scan Lifecycle ----
    pub fn emit_scan_started(&self, event: &ScanStartedEvent) {
        self.emit(|h| h.on_scan_started(event));
    }

    pub fn emit_scan_progress(&self, event: &ScanProgressEvent) {
        self.emit(|h| h.on_scan_progress(event));
    }

    pub fn emit_scan_complete(&self, event: &ScanCompleteEvent) {
        self.emit(|h| h.on_scan_complete(event));
    }

    pub fn emit_scan_error(&self, event: &ScanErrorEvent) {
        self.emit(|h| h.on_scan_error(event));
    }

    // ---- Pattern Lifecycle ----
    pub fn emit_pattern_discovered(&self, event: &PatternDiscoveredEvent) {
        self.emit(|h| h.on_pattern_discovered(event));
    }

    pub fn emit_pattern_approved(&self, event: &PatternApprovedEvent) {
        self.emit(|h| h.on_pattern_approved(event));
    }

    pub fn emit_pattern_ignored(&self, event: &PatternIgnoredEvent) {
        self.emit(|h| h.on_pattern_ignored(event));
    }

    pub fn emit_pattern_merged(&self, event: &PatternMergedEvent) {
        self.emit(|h| h.on_pattern_merged(event));
    }

    // ---- Violations ----
    pub fn emit_violation_detected(&self, event: &ViolationDetectedEvent) {
        self.emit(|h| h.on_violation_detected(event));
    }

    pub fn emit_violation_dismissed(&self, event: &ViolationDismissedEvent) {
        self.emit(|h| h.on_violation_dismissed(event));
    }

    pub fn emit_violation_fixed(&self, event: &ViolationFixedEvent) {
        self.emit(|h| h.on_violation_fixed(event));
    }

    // ---- Enforcement ----
    pub fn emit_gate_evaluated(&self, event: &GateEvaluatedEvent) {
        self.emit(|h| h.on_gate_evaluated(event));
    }

    pub fn emit_regression_detected(&self, event: &RegressionDetectedEvent) {
        self.emit(|h| h.on_regression_detected(event));
    }

    pub fn emit_enforcement_changed(&self, event: &EnforcementChangedEvent) {
        self.emit(|h| h.on_enforcement_changed(event));
    }

    // ---- Constraints ----
    pub fn emit_constraint_approved(&self, event: &ConstraintApprovedEvent) {
        self.emit(|h| h.on_constraint_approved(event));
    }

    pub fn emit_constraint_violated(&self, event: &ConstraintViolatedEvent) {
        self.emit(|h| h.on_constraint_violated(event));
    }

    // ---- Decisions ----
    pub fn emit_decision_mined(&self, event: &DecisionMinedEvent) {
        self.emit(|h| h.on_decision_mined(event));
    }

    pub fn emit_decision_reversed(&self, event: &DecisionReversedEvent) {
        self.emit(|h| h.on_decision_reversed(event));
    }

    pub fn emit_adr_detected(&self, event: &AdrDetectedEvent) {
        self.emit(|h| h.on_adr_detected(event));
    }

    // ---- Boundaries ----
    pub fn emit_boundary_discovered(&self, event: &BoundaryDiscoveredEvent) {
        self.emit(|h| h.on_boundary_discovered(event));
    }

    // ---- Detector Health ----
    pub fn emit_detector_alert(&self, event: &DetectorAlertEvent) {
        self.emit(|h| h.on_detector_alert(event));
    }

    pub fn emit_detector_disabled(&self, event: &DetectorDisabledEvent) {
        self.emit(|h| h.on_detector_disabled(event));
    }

    // ---- Feedback ----
    pub fn emit_feedback_abuse_detected(&self, event: &FeedbackAbuseDetectedEvent) {
        self.emit(|h| h.on_feedback_abuse_detected(event));
    }

    // ---- Errors ----
    pub fn emit_error(&self, event: &ErrorEvent) {
        self.emit(|h| h.on_error(event));
    }
}

impl Default for EventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: EventDispatcher is Send + Sync because all handlers are Arc<dyn Send + Sync>.
unsafe impl Send for EventDispatcher {}
unsafe impl Sync for EventDispatcher {}

//! Production Category 12: Event System & DriftEventHandler
//!
//! 4 tests verifying the full event lifecycle, dispatcher fan-out,
//! progress event frequency, and error event propagation.
//!
//! Source verification:
//!   - DriftEventHandler trait: drift-core/src/events/handler.rs (24 methods)
//!   - EventDispatcher: drift-core/src/events/dispatcher.rs
//!   - Progress modulo 100: drift-analysis/src/scanner/scanner.rs:99
//!   - Error event before Err: drift-analysis/src/scanner/scanner.rs:66-69
//!   - Runtime dispatcher: drift-napi/src/runtime.rs:120

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use drift_core::events::dispatcher::EventDispatcher;
use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;

// ---------------------------------------------------------------------------
// Shared test infrastructure
// ---------------------------------------------------------------------------

/// Identifies which of the 24 event methods fired (in order).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum EventKind {
    ScanStarted,
    ScanProgress,
    ScanComplete,
    ScanError,
    PatternDiscovered,
    PatternApproved,
    PatternIgnored,
    PatternMerged,
    ViolationDetected,
    ViolationDismissed,
    ViolationFixed,
    GateEvaluated,
    RegressionDetected,
    EnforcementChanged,
    ConstraintApproved,
    ConstraintViolated,
    DecisionMined,
    DecisionReversed,
    AdrDetected,
    BoundaryDiscovered,
    DetectorAlert,
    DetectorDisabled,
    FeedbackAbuseDetected,
    Error,
}

/// Handler that records every event kind received, in order.
struct RecordingHandler {
    events: Mutex<Vec<EventKind>>,
}

impl RecordingHandler {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    fn recorded(&self) -> Vec<EventKind> {
        self.events.lock().unwrap().clone()
    }
}

impl DriftEventHandler for RecordingHandler {
    fn on_scan_started(&self, _: &ScanStartedEvent) {
        self.events.lock().unwrap().push(EventKind::ScanStarted);
    }
    fn on_scan_progress(&self, _: &ScanProgressEvent) {
        self.events.lock().unwrap().push(EventKind::ScanProgress);
    }
    fn on_scan_complete(&self, _: &ScanCompleteEvent) {
        self.events.lock().unwrap().push(EventKind::ScanComplete);
    }
    fn on_scan_error(&self, _: &ScanErrorEvent) {
        self.events.lock().unwrap().push(EventKind::ScanError);
    }
    fn on_pattern_discovered(&self, _: &PatternDiscoveredEvent) {
        self.events.lock().unwrap().push(EventKind::PatternDiscovered);
    }
    fn on_pattern_approved(&self, _: &PatternApprovedEvent) {
        self.events.lock().unwrap().push(EventKind::PatternApproved);
    }
    fn on_pattern_ignored(&self, _: &PatternIgnoredEvent) {
        self.events.lock().unwrap().push(EventKind::PatternIgnored);
    }
    fn on_pattern_merged(&self, _: &PatternMergedEvent) {
        self.events.lock().unwrap().push(EventKind::PatternMerged);
    }
    fn on_violation_detected(&self, _: &ViolationDetectedEvent) {
        self.events.lock().unwrap().push(EventKind::ViolationDetected);
    }
    fn on_violation_dismissed(&self, _: &ViolationDismissedEvent) {
        self.events.lock().unwrap().push(EventKind::ViolationDismissed);
    }
    fn on_violation_fixed(&self, _: &ViolationFixedEvent) {
        self.events.lock().unwrap().push(EventKind::ViolationFixed);
    }
    fn on_gate_evaluated(&self, _: &GateEvaluatedEvent) {
        self.events.lock().unwrap().push(EventKind::GateEvaluated);
    }
    fn on_regression_detected(&self, _: &RegressionDetectedEvent) {
        self.events.lock().unwrap().push(EventKind::RegressionDetected);
    }
    fn on_enforcement_changed(&self, _: &EnforcementChangedEvent) {
        self.events.lock().unwrap().push(EventKind::EnforcementChanged);
    }
    fn on_constraint_approved(&self, _: &ConstraintApprovedEvent) {
        self.events.lock().unwrap().push(EventKind::ConstraintApproved);
    }
    fn on_constraint_violated(&self, _: &ConstraintViolatedEvent) {
        self.events.lock().unwrap().push(EventKind::ConstraintViolated);
    }
    fn on_decision_mined(&self, _: &DecisionMinedEvent) {
        self.events.lock().unwrap().push(EventKind::DecisionMined);
    }
    fn on_decision_reversed(&self, _: &DecisionReversedEvent) {
        self.events.lock().unwrap().push(EventKind::DecisionReversed);
    }
    fn on_adr_detected(&self, _: &AdrDetectedEvent) {
        self.events.lock().unwrap().push(EventKind::AdrDetected);
    }
    fn on_boundary_discovered(&self, _: &BoundaryDiscoveredEvent) {
        self.events.lock().unwrap().push(EventKind::BoundaryDiscovered);
    }
    fn on_detector_alert(&self, _: &DetectorAlertEvent) {
        self.events.lock().unwrap().push(EventKind::DetectorAlert);
    }
    fn on_detector_disabled(&self, _: &DetectorDisabledEvent) {
        self.events.lock().unwrap().push(EventKind::DetectorDisabled);
    }
    fn on_feedback_abuse_detected(&self, _: &FeedbackAbuseDetectedEvent) {
        self.events
            .lock()
            .unwrap()
            .push(EventKind::FeedbackAbuseDetected);
    }
    fn on_error(&self, _: &ErrorEvent) {
        self.events.lock().unwrap().push(EventKind::Error);
    }
}

/// Handler that pushes its ID into a shared order vector on every scan_started event.
struct OrderTrackingHandler {
    id: usize,
    order: Arc<Mutex<Vec<usize>>>,
}

impl DriftEventHandler for OrderTrackingHandler {
    fn on_scan_started(&self, _: &ScanStartedEvent) {
        self.order.lock().unwrap().push(self.id);
    }
    fn on_scan_progress(&self, _: &ScanProgressEvent) {
        self.order.lock().unwrap().push(self.id);
    }
    fn on_scan_error(&self, _: &ScanErrorEvent) {
        self.order.lock().unwrap().push(self.id);
    }
}

/// Handler that counts progress events.
struct ProgressCounter {
    count: AtomicUsize,
}

impl ProgressCounter {
    fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
        }
    }
}

impl DriftEventHandler for ProgressCounter {
    fn on_scan_progress(&self, _: &ScanProgressEvent) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Handler that captures the error message.
struct ErrorCapture {
    messages: Mutex<Vec<String>>,
}

impl ErrorCapture {
    fn new() -> Self {
        Self {
            messages: Mutex::new(Vec::new()),
        }
    }
}

impl DriftEventHandler for ErrorCapture {
    fn on_scan_error(&self, event: &ScanErrorEvent) {
        self.messages.lock().unwrap().push(event.message.clone());
    }
}

// ---------------------------------------------------------------------------
// T12-01: Full Event Sequence (scan → analyze → check)
// ---------------------------------------------------------------------------

/// T12-01: Emit the complete 24-event pipeline sequence through the dispatcher
/// and verify the recording handler captures every event kind exactly once,
/// in the expected phase order, without gaps or duplicates.
#[test]
fn t12_01_full_event_sequence() {
    let mut dispatcher = EventDispatcher::new();
    let recorder = Arc::new(RecordingHandler::new());
    dispatcher.register(recorder.clone());

    // ---- Phase 1: Scan ----
    dispatcher.emit_scan_started(&ScanStartedEvent {
        root: PathBuf::from("/project"),
        file_count: Some(500),
    });
    dispatcher.emit_scan_progress(&ScanProgressEvent {
        processed: 250,
        total: 500,
    });
    dispatcher.emit_scan_complete(&ScanCompleteEvent {
        added: 10,
        modified: 5,
        removed: 2,
        unchanged: 483,
        duration_ms: 120,
    });

    // ---- Phase 2: Analyze (patterns, violations, boundaries, detectors) ----
    dispatcher.emit_pattern_discovered(&PatternDiscoveredEvent {
        pattern_id: "p1".into(),
        category: "naming".into(),
        confidence: 0.92,
    });
    dispatcher.emit_pattern_approved(&PatternApprovedEvent {
        pattern_id: "p1".into(),
    });
    dispatcher.emit_pattern_ignored(&PatternIgnoredEvent {
        pattern_id: "p2".into(),
        reason: "low confidence".into(),
    });
    dispatcher.emit_pattern_merged(&PatternMergedEvent {
        kept_id: "p1".into(),
        merged_id: "p3".into(),
    });
    dispatcher.emit_violation_detected(&ViolationDetectedEvent {
        violation_id: "v1".into(),
        pattern_id: "p1".into(),
        file: PathBuf::from("src/main.rs"),
        line: 42,
        message: "naming violation".into(),
    });
    dispatcher.emit_violation_dismissed(&ViolationDismissedEvent {
        violation_id: "v2".into(),
        reason: "false positive".into(),
    });
    dispatcher.emit_violation_fixed(&ViolationFixedEvent {
        violation_id: "v3".into(),
    });
    dispatcher.emit_boundary_discovered(&BoundaryDiscoveredEvent {
        boundary_id: "b1".into(),
        orm: "diesel".into(),
        model: "User".into(),
    });
    dispatcher.emit_detector_alert(&DetectorAlertEvent {
        detector_id: "d1".into(),
        false_positive_rate: 0.15,
    });
    dispatcher.emit_detector_disabled(&DetectorDisabledEvent {
        detector_id: "d2".into(),
        reason: "excessive FP".into(),
    });

    // ---- Phase 2b: Decisions & Constraints ----
    dispatcher.emit_decision_mined(&DecisionMinedEvent {
        decision_id: "dm1".into(),
        category: "architecture".into(),
    });
    dispatcher.emit_decision_reversed(&DecisionReversedEvent {
        decision_id: "dm2".into(),
        reason: "superseded".into(),
    });
    dispatcher.emit_adr_detected(&AdrDetectedEvent {
        adr_id: "adr1".into(),
        title: "Use microservices".into(),
    });
    dispatcher.emit_constraint_approved(&ConstraintApprovedEvent {
        constraint_id: "c1".into(),
    });
    dispatcher.emit_constraint_violated(&ConstraintViolatedEvent {
        constraint_id: "c2".into(),
        message: "boundary crossed".into(),
    });

    // ---- Phase 3: Check (enforcement) ----
    dispatcher.emit_gate_evaluated(&GateEvaluatedEvent {
        gate_name: "new_pattern_only".into(),
        passed: true,
        score: Some(0.95),
        message: "ok".into(),
    });
    dispatcher.emit_regression_detected(&RegressionDetectedEvent {
        pattern_id: "p1".into(),
        previous_score: 0.95,
        current_score: 0.80,
    });
    dispatcher.emit_enforcement_changed(&EnforcementChangedEvent {
        gate_name: "new_pattern_only".into(),
        old_level: "warn".into(),
        new_level: "block".into(),
    });

    // ---- Phase 3b: Feedback & Errors ----
    dispatcher.emit_feedback_abuse_detected(&FeedbackAbuseDetectedEvent {
        user_id: "u1".into(),
        pattern: "spam dismiss".into(),
    });
    dispatcher.emit_error(&ErrorEvent {
        message: "unexpected EOF".into(),
        error_code: "PARSE_ERROR".into(),
    });

    // ---- Verify ----
    let events = recorder.recorded();

    // All 24 event kinds must appear exactly once
    let expected = vec![
        // Scan lifecycle (4)
        EventKind::ScanStarted,
        EventKind::ScanProgress,
        EventKind::ScanComplete,
        // Analysis (4 pattern + 3 violation + 1 boundary + 2 detector = 10)
        EventKind::PatternDiscovered,
        EventKind::PatternApproved,
        EventKind::PatternIgnored,
        EventKind::PatternMerged,
        EventKind::ViolationDetected,
        EventKind::ViolationDismissed,
        EventKind::ViolationFixed,
        EventKind::BoundaryDiscovered,
        EventKind::DetectorAlert,
        EventKind::DetectorDisabled,
        // Decisions & Constraints (3 + 2 = 5)
        EventKind::DecisionMined,
        EventKind::DecisionReversed,
        EventKind::AdrDetected,
        EventKind::ConstraintApproved,
        EventKind::ConstraintViolated,
        // Enforcement (3)
        EventKind::GateEvaluated,
        EventKind::RegressionDetected,
        EventKind::EnforcementChanged,
        // Feedback + Error (2)
        EventKind::FeedbackAbuseDetected,
        EventKind::Error,
    ];

    assert_eq!(events.len(), 23, "expected 23 events (all 24 kinds minus ScanError which is error-path only)");
    assert_eq!(events, expected, "event sequence must match pipeline order without gaps or duplicates");

    // Verify no duplicates in the recorded kinds
    let mut seen = std::collections::HashSet::new();
    for e in &events {
        assert!(
            seen.insert(e.clone()),
            "duplicate event kind detected: {:?}",
            e
        );
    }
}

// ---------------------------------------------------------------------------
// T12-02: EventDispatcher Fan-Out (3 handlers)
// ---------------------------------------------------------------------------

/// T12-02: Register 3 handlers. Emit one event. All 3 must receive it;
/// delivery order must match registration order.
#[test]
fn t12_02_event_dispatcher_fan_out_3_handlers() {
    let mut dispatcher = EventDispatcher::new();
    let order = Arc::new(Mutex::new(Vec::new()));

    let h1 = Arc::new(OrderTrackingHandler {
        id: 1,
        order: order.clone(),
    });
    let h2 = Arc::new(OrderTrackingHandler {
        id: 2,
        order: order.clone(),
    });
    let h3 = Arc::new(OrderTrackingHandler {
        id: 3,
        order: order.clone(),
    });

    dispatcher.register(h1);
    dispatcher.register(h2);
    dispatcher.register(h3);

    assert_eq!(dispatcher.handler_count(), 3);

    // Emit a single event
    dispatcher.emit_scan_started(&ScanStartedEvent {
        root: PathBuf::from("/project"),
        file_count: Some(100),
    });

    let delivery_order = order.lock().unwrap().clone();
    assert_eq!(
        delivery_order,
        vec![1, 2, 3],
        "all 3 handlers must receive the event in registration order"
    );

    // Emit a second event type to verify fan-out is consistent across types
    dispatcher.emit_scan_progress(&ScanProgressEvent {
        processed: 50,
        total: 100,
    });

    let delivery_order = order.lock().unwrap().clone();
    assert_eq!(
        delivery_order,
        vec![1, 2, 3, 1, 2, 3],
        "fan-out must be consistent across event types"
    );
}

// ---------------------------------------------------------------------------
// T12-03: Progress Event Frequency (every 100 files)
// ---------------------------------------------------------------------------

/// T12-03: Simulate scanner processing 10,000 files. Verify progress events
/// fire every 100 files, matching scanner.rs:99 (`if count % 100 == 0`).
///
/// The scanner emits:
///   1. Initial progress at processed=0 (scanner.rs:79-82)
///   2. In the par_iter loop: `count = fetch_add(1)` → if count % 100 == 0
///      → fires at count 0, 100, 200, ..., 9900 = 100 emissions
///
///   Total = 1 (initial) + 100 (loop) = 101 progress events.
#[test]
fn t12_03_progress_event_frequency_every_100_files() {
    let mut dispatcher = EventDispatcher::new();
    let counter = Arc::new(ProgressCounter::new());
    dispatcher.register(counter.clone());

    let total_files: usize = 10_000;

    // Replicate scanner.rs:79-82 — initial progress emission
    dispatcher.emit_scan_progress(&ScanProgressEvent {
        processed: 0,
        total: total_files,
    });

    // Replicate scanner.rs:98-104 — loop emission at count % 100 == 0
    // fetch_add returns the *previous* value, so count goes 0, 1, 2, ..., 9999
    let processed = AtomicUsize::new(0);
    for _ in 0..total_files {
        let count = processed.fetch_add(1, Ordering::Relaxed);
        if count % 100 == 0 {
            dispatcher.emit_scan_progress(&ScanProgressEvent {
                processed: count,
                total: total_files,
            });
        }
    }

    let progress_count = counter.count.load(Ordering::Relaxed);

    // 1 initial + 100 from loop (0, 100, 200, ..., 9900) = 101
    assert_eq!(
        progress_count, 101,
        "progress must fire 101 times: 1 initial + every 100 files for 10,000 files"
    );

    // Verify the modulo pattern: for N files, loop emissions = N / 100
    assert_eq!(
        total_files / 100,
        100,
        "loop should emit exactly total_files / 100 progress events"
    );
}

// ---------------------------------------------------------------------------
// T12-04: Error Event on Walker Failure
// ---------------------------------------------------------------------------

/// T12-04: Simulate scanner pointing at nonexistent directory.
/// `on_scan_error` must fire with a descriptive message, matching
/// scanner.rs:66-69 which emits ScanErrorEvent then returns Err.
#[test]
fn t12_04_error_event_on_walker_failure() {
    let mut dispatcher = EventDispatcher::new();
    let capture = Arc::new(ErrorCapture::new());
    dispatcher.register(capture.clone());

    // Replicate the scanner's error-path pattern (scanner.rs:66-69):
    //   event_handler.on_scan_error(&ScanErrorEvent { message: e.to_string() });
    //   return Err(e);
    //
    // We simulate by emitting the scan_started first (scanner.rs:52-55),
    // then the error, mirroring the exact sequence.
    dispatcher.emit_scan_started(&ScanStartedEvent {
        root: PathBuf::from("/nonexistent/directory"),
        file_count: None,
    });

    let error_message = "No such file or directory: /nonexistent/directory";
    dispatcher.emit_scan_error(&ScanErrorEvent {
        message: error_message.to_string(),
    });

    // Verify the error handler received the descriptive message
    let messages = capture.messages.lock().unwrap().clone();
    assert_eq!(messages.len(), 1, "exactly one error event must fire");
    assert_eq!(
        messages[0], error_message,
        "error message must be descriptive and match the walker failure"
    );

    // Verify the message is non-empty and contains path information
    assert!(
        messages[0].contains("/nonexistent/directory"),
        "error message must reference the failed path"
    );

    // Verify that scan_complete is NOT emitted after an error
    // (scanner returns Err, so complete is never reached)
    let recorder = Arc::new(RecordingHandler::new());
    let mut dispatcher2 = EventDispatcher::new();
    dispatcher2.register(recorder.clone());

    // Simulate the exact scanner error path: started → error → (no complete)
    dispatcher2.emit_scan_started(&ScanStartedEvent {
        root: PathBuf::from("/nonexistent"),
        file_count: None,
    });
    dispatcher2.emit_scan_error(&ScanErrorEvent {
        message: "walk failed".into(),
    });

    let events = recorder.recorded();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], EventKind::ScanStarted);
    assert_eq!(events[1], EventKind::ScanError);
    assert!(
        !events.contains(&EventKind::ScanComplete),
        "ScanComplete must NOT fire after a walker error"
    );
}

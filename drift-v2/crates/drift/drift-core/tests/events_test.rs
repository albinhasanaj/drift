//! Tests for the Drift event system.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use drift_core::events::dispatcher::EventDispatcher;
use drift_core::events::handler::DriftEventHandler;
use drift_core::events::types::*;

/// A test handler that counts events.
struct CountingHandler {
    scan_started: AtomicUsize,
    scan_progress: AtomicUsize,
    scan_complete: AtomicUsize,
    violation_detected: AtomicUsize,
    error_count: AtomicUsize,
}

impl CountingHandler {
    fn new() -> Self {
        Self {
            scan_started: AtomicUsize::new(0),
            scan_progress: AtomicUsize::new(0),
            scan_complete: AtomicUsize::new(0),
            violation_detected: AtomicUsize::new(0),
            error_count: AtomicUsize::new(0),
        }
    }
}

impl DriftEventHandler for CountingHandler {
    fn on_scan_started(&self, _event: &ScanStartedEvent) {
        self.scan_started.fetch_add(1, Ordering::Relaxed);
    }

    fn on_scan_progress(&self, _event: &ScanProgressEvent) {
        self.scan_progress.fetch_add(1, Ordering::Relaxed);
    }

    fn on_scan_complete(&self, _event: &ScanCompleteEvent) {
        self.scan_complete.fetch_add(1, Ordering::Relaxed);
    }

    fn on_violation_detected(&self, _event: &ViolationDetectedEvent) {
        self.violation_detected.fetch_add(1, Ordering::Relaxed);
    }

    fn on_error(&self, _event: &ErrorEvent) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// T0-EVT-01: Test DriftEventHandler trait compiles with no-op defaults
#[test]
fn test_handler_noop_defaults() {
    struct NoopHandler;
    impl DriftEventHandler for NoopHandler {}

    let handler = NoopHandler;
    // All methods should be callable without implementing them
    handler.on_scan_started(&ScanStartedEvent {
        root: PathBuf::from("/tmp"),
        file_count: Some(100),
    });
    handler.on_scan_progress(&ScanProgressEvent {
        processed: 50,
        total: 100,
    });
    handler.on_pattern_discovered(&PatternDiscoveredEvent {
        pattern_id: "p1".into(),
        category: "naming".into(),
        confidence: 0.9,
    });
    handler.on_error(&ErrorEvent {
        message: "test".into(),
        error_code: "TEST".into(),
    });
}

/// T0-EVT-02: Test EventDispatcher with zero handlers (zero overhead)
#[test]
fn test_dispatcher_zero_handlers() {
    let dispatcher = EventDispatcher::new();
    assert_eq!(dispatcher.handler_count(), 0);

    // Should not panic with zero handlers
    dispatcher.emit_scan_started(&ScanStartedEvent {
        root: PathBuf::from("/tmp"),
        file_count: Some(100),
    });
    dispatcher.emit_scan_progress(&ScanProgressEvent {
        processed: 50,
        total: 100,
    });
}

/// T0-EVT-03: Test EventDispatcher with multiple handlers
#[test]
fn test_dispatcher_multiple_handlers() {
    let mut dispatcher = EventDispatcher::new();

    let handler1 = Arc::new(CountingHandler::new());
    let handler2 = Arc::new(CountingHandler::new());

    dispatcher.register(handler1.clone());
    dispatcher.register(handler2.clone());

    assert_eq!(dispatcher.handler_count(), 2);

    dispatcher.emit_scan_started(&ScanStartedEvent {
        root: PathBuf::from("/tmp"),
        file_count: Some(100),
    });

    // Both handlers should receive the event
    assert_eq!(handler1.scan_started.load(Ordering::Relaxed), 1);
    assert_eq!(handler2.scan_started.load(Ordering::Relaxed), 1);
}

/// T0-EVT-04: Test handler that panics does not crash the dispatcher
#[test]
fn test_panicking_handler_does_not_crash() {
    struct PanickingHandler;
    impl DriftEventHandler for PanickingHandler {
        fn on_scan_started(&self, _event: &ScanStartedEvent) {
            panic!("intentional panic in handler");
        }
    }

    let mut dispatcher = EventDispatcher::new();
    let panicking = Arc::new(PanickingHandler);
    let counting = Arc::new(CountingHandler::new());

    // Register panicking handler first, then counting handler
    dispatcher.register(panicking);
    dispatcher.register(counting.clone());

    // Should not panic — the panicking handler is caught
    dispatcher.emit_scan_started(&ScanStartedEvent {
        root: PathBuf::from("/tmp"),
        file_count: Some(100),
    });

    // The counting handler should still receive the event
    assert_eq!(counting.scan_started.load(Ordering::Relaxed), 1);
}

/// T0-EVT-05: Test event payload data integrity
#[test]
fn test_event_payload_integrity() {
    struct CapturingHandler {
        captured_processed: AtomicUsize,
        captured_total: AtomicUsize,
    }

    impl DriftEventHandler for CapturingHandler {
        fn on_scan_progress(&self, event: &ScanProgressEvent) {
            self.captured_processed
                .store(event.processed, Ordering::Relaxed);
            self.captured_total
                .store(event.total, Ordering::Relaxed);
        }
    }

    let mut dispatcher = EventDispatcher::new();
    let handler = Arc::new(CapturingHandler {
        captured_processed: AtomicUsize::new(0),
        captured_total: AtomicUsize::new(0),
    });
    dispatcher.register(handler.clone());

    dispatcher.emit_scan_progress(&ScanProgressEvent {
        processed: 42,
        total: 100,
    });

    assert_eq!(handler.captured_processed.load(Ordering::Relaxed), 42);
    assert_eq!(handler.captured_total.load(Ordering::Relaxed), 100);
}

/// T0-EVT-06: Test EventDispatcher is Send + Sync
#[test]
fn test_dispatcher_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<EventDispatcher>();
}

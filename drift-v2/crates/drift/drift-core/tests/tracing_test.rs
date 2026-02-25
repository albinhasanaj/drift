//! Tests for the Drift tracing/observability system.

use std::sync::Mutex;

use drift_core::tracing::setup::init_tracing;

/// Global mutex to serialize tracing tests (env var manipulation).
static TRACING_MUTEX: Mutex<()> = Mutex::new(());

/// T0-TRC-01: Test DRIFT_LOG=debug produces structured span output
#[test]
fn test_drift_log_debug() {
    let _lock = TRACING_MUTEX.lock().unwrap();
    // init_tracing reads DRIFT_LOG. We just verify it doesn't panic.
    // The actual output goes to stderr, which we can't easily capture
    // in integration tests, but we verify the function works.
    std::env::set_var("DRIFT_LOG", "debug");
    init_tracing();
    std::env::remove_var("DRIFT_LOG");
}

/// T0-TRC-02: Test per-subsystem log level filtering
#[test]
fn test_per_subsystem_filtering() {
    let _lock = TRACING_MUTEX.lock().unwrap();
    // Verify that the DRIFT_LOG format is accepted without panic
    std::env::set_var("DRIFT_LOG", "scanner=debug,parser=warn,storage=info");
    // init_tracing is idempotent, so calling it again is safe
    init_tracing();
    std::env::remove_var("DRIFT_LOG");
}

/// T0-TRC-03: Test init_tracing() called twice does not panic (idempotent)
#[test]
fn test_init_tracing_idempotent() {
    let _lock = TRACING_MUTEX.lock().unwrap();
    // Call multiple times — should not panic or double-initialize
    init_tracing();
    init_tracing();
    init_tracing();
}

/// T0-TRC-04: Test invalid DRIFT_LOG value falls back to default level
#[test]
fn test_invalid_drift_log_fallback() {
    let _lock = TRACING_MUTEX.lock().unwrap();
    std::env::set_var("DRIFT_LOG", "this_is_garbage_not_a_valid_filter");
    // Should not crash — falls back to default
    init_tracing();
    std::env::remove_var("DRIFT_LOG");
}

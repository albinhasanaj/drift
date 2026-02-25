//! Enterprise stress tests for Cortex Observability hardening fixes.
//!
//! Covers:
//! - P2-17/P2-18: Metrics persistence — MetricsCollector serialization,
//!   metrics_snapshot() produces valid JSON, QueryLog count accuracy.
//!
//! Every test targets a specific production failure mode.

use cortex_observability::engine::ObservabilityEngine;
use cortex_observability::metrics::MetricsCollector;
use cortex_observability::query_log::{QueryLog, QueryLogEntry};
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════════════════
// P2-17/P2-18: METRICS PERSISTENCE — serialization + snapshot
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: All 5 metrics collectors were in-memory only, lost on restart.
/// Verify MetricsCollector serializes to JSON (Serialize derive was missing).
#[test]
fn hst_p217_01_metrics_collector_serializes() {
    let collector = MetricsCollector::new();
    let json = serde_json::to_value(&collector);
    assert!(json.is_ok(), "MetricsCollector must serialize: {:?}", json.err());
    let val = json.unwrap();
    assert!(val.is_object(), "Serialized metrics must be an object");
}

/// Metrics with data serialize correctly.
#[test]
fn hst_p217_02_metrics_with_data_serializes() {
    let mut collector = MetricsCollector::new();

    // Record some retrieval metrics.
    collector.retrieval.record_query(None, true, 100, 200);
    collector.retrieval.record_query(None, false, 50, 200);
    collector.retrieval.record_useful_memory("mem-001");

    // Record storage metrics.
    collector.storage.db_size_bytes = 1_000_000;

    // Record embedding metrics.
    collector.embedding.l1_hits = 42;

    let json = serde_json::to_value(&collector).unwrap();
    assert!(json["retrieval"]["total_tokens_used"].as_u64().unwrap() > 0);
    assert_eq!(json["storage"]["db_size_bytes"].as_u64().unwrap(), 1_000_000);
    assert_eq!(json["embedding"]["l1_hits"].as_u64().unwrap(), 42);
}

/// metrics_snapshot() returns valid JSON with all required fields.
#[test]
fn hst_p217_03_metrics_snapshot_valid_json() {
    let engine = ObservabilityEngine::new();
    let snapshot = engine.metrics_snapshot().unwrap();

    assert!(snapshot.is_object());
    assert!(snapshot.get("metrics").is_some(), "Missing 'metrics' field");
    assert!(snapshot.get("query_log_count").is_some(), "Missing 'query_log_count' field");
    assert!(snapshot.get("query_avg_latency_ms").is_some(), "Missing 'query_avg_latency_ms' field");
}

/// metrics_snapshot() on fresh engine has zero counts.
#[test]
fn hst_p217_04_fresh_engine_zero_counts() {
    let engine = ObservabilityEngine::new();
    let snapshot = engine.metrics_snapshot().unwrap();

    assert_eq!(snapshot["query_log_count"].as_u64().unwrap(), 0);
    assert_eq!(snapshot["query_avg_latency_ms"].as_u64().unwrap(), 0);
}

/// reset_metrics() clears everything.
#[test]
fn hst_p217_05_reset_clears_metrics() {
    let mut engine = ObservabilityEngine::new();

    // Record some data.
    engine.metrics.retrieval.record_query(None, true, 100, 200);
    engine.metrics.storage.db_size_bytes = 999;

    // Reset.
    engine.reset_metrics();

    let snapshot = engine.metrics_snapshot().unwrap();
    assert_eq!(snapshot["metrics"]["storage"]["db_size_bytes"].as_u64().unwrap(), 0);
}

/// QueryLog count is accurate.
#[test]
fn hst_p217_06_query_log_count_accurate() {
    let mut log = QueryLog::new();

    for i in 0..25 {
        log.record(QueryLogEntry::new(
            format!("query {i}"),
            None,
            Duration::from_millis(10 + i),
            i as usize,
            100,
            50,
            i as usize % 5,
        ));
    }

    assert_eq!(log.count(), 25);
}

/// QueryLog ring buffer — doesn't exceed max_entries.
#[test]
fn hst_p217_07_query_log_ring_buffer() {
    let mut log = QueryLog::with_capacity(10);

    for i in 0..25 {
        log.record(QueryLogEntry::new(
            format!("query {i}"),
            None,
            Duration::from_millis(5),
            1,
            100,
            50,
            0,
        ));
    }

    assert!(log.count() <= 10, "Ring buffer should cap at 10, got {}", log.count());
}

/// avg_latency on empty log returns zero, no division by zero.
#[test]
fn hst_p217_08_avg_latency_empty_log() {
    let log = QueryLog::new();
    assert_eq!(log.avg_latency(), Duration::ZERO);
}

/// Stress: 10000 query log entries — no OOM, count correct.
#[test]
fn hst_p217_09_stress_10000_query_log_entries() {
    let mut log = QueryLog::new(); // Default capacity 50_000.

    for i in 0..10_000 {
        log.record(QueryLogEntry::new(
            format!("stress query {i}"),
            None,
            Duration::from_millis(i % 100),
            1,
            100,
            50,
            0,
        ));
    }

    assert_eq!(log.count(), 10_000);
    assert!(log.avg_latency() > Duration::ZERO);
}

/// metrics_snapshot serialization roundtrip — serialize then parse back.
#[test]
fn hst_p217_10_snapshot_serialization_roundtrip() {
    let mut engine = ObservabilityEngine::new();
    engine.metrics.retrieval.record_query(None, true, 100, 200);
    engine.metrics.embedding.l1_hits = 7;

    let snapshot = engine.metrics_snapshot().unwrap();
    let json_str = serde_json::to_string(&snapshot).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(parsed["metrics"]["embedding"]["l1_hits"].as_u64().unwrap(), 7);
}

/// Degradation alerts on fresh engine — empty, no crash.
#[test]
fn hst_p217_11_degradation_alerts_empty() {
    let engine = ObservabilityEngine::new();
    let alerts = engine.degradation_alerts();
    assert!(alerts.is_empty());
}

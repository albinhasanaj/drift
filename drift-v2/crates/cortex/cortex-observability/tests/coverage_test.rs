//! Targeted coverage tests for cortex-observability uncovered paths.
//!
//! Focuses on: health reporter, subsystem checks, recommendations,
//! degradation tracker/alerting, metrics collector, query log, engine.

use chrono::Utc;
use cortex_core::models::{DegradationEvent, HealthStatus};
use cortex_observability::health::{HealthReporter, HealthSnapshot};
use cortex_observability::ObservabilityEngine;

// ─── Health Reporter ─────────────────────────────────────────────────────────

#[test]
fn health_report_healthy_system() {
    let snapshot = HealthSnapshot {
        total_memories: 100,
        active_memories: 90,
        archived_memories: 10,
        average_confidence: 0.85,
        db_size_bytes: 10_000_000,
        embedding_cache_hit_rate: 0.9,
        stale_count: 2,
        contradiction_count: 1,
        unresolved_contradictions: 0,
        consolidation_count: 5,
        memories_needing_validation: 3,
        drift_summary: None,
    };
    let report = HealthReporter::build(&snapshot).unwrap();
    assert_eq!(report.overall_status, HealthStatus::Healthy);
    assert_eq!(report.metrics.total_memories, 100);
    assert_eq!(report.metrics.active_memories, 90);
}

#[test]
fn health_report_degraded_system() {
    let snapshot = HealthSnapshot {
        total_memories: 100,
        active_memories: 90,
        archived_memories: 10,
        average_confidence: 0.3, // Low confidence → degraded
        db_size_bytes: 10_000_000,
        embedding_cache_hit_rate: 0.1, // Low cache hit rate
        stale_count: 50,
        contradiction_count: 20,
        unresolved_contradictions: 15,
        consolidation_count: 0,
        memories_needing_validation: 40,
        drift_summary: None,
    };
    let report = HealthReporter::build(&snapshot).unwrap();
    assert!(
        report.overall_status == HealthStatus::Degraded
            || report.overall_status == HealthStatus::Unhealthy
    );
}

#[test]
fn health_recommendations_for_stale_memories() {
    let snapshot = HealthSnapshot {
        total_memories: 100,
        active_memories: 50,
        archived_memories: 50,
        average_confidence: 0.5,
        db_size_bytes: 10_000_000,
        embedding_cache_hit_rate: 0.5,
        stale_count: 30,
        contradiction_count: 10,
        unresolved_contradictions: 5,
        consolidation_count: 0,
        memories_needing_validation: 20,
        drift_summary: None,
    };
    let recs = HealthReporter::recommendations(&snapshot);
    // Should have at least one recommendation for stale memories or contradictions.
    assert!(!recs.is_empty());
}

#[test]
fn health_recommendations_empty_for_healthy() {
    let snapshot = HealthSnapshot {
        total_memories: 100,
        active_memories: 95,
        archived_memories: 5,
        average_confidence: 0.9,
        db_size_bytes: 1_000_000,
        embedding_cache_hit_rate: 0.95,
        stale_count: 0,
        contradiction_count: 0,
        unresolved_contradictions: 0,
        consolidation_count: 10,
        memories_needing_validation: 0,
        drift_summary: None,
    };
    let recs = HealthReporter::recommendations(&snapshot);
    // Healthy system may still have minor recommendations, but should be few.
    assert!(recs.len() <= 2);
}

// ─── Degradation Tracker ─────────────────────────────────────────────────────

#[test]
fn degradation_tracker_record_and_alert() {
    let mut engine = ObservabilityEngine::new();
    // Record >3 events to trigger a warning alert.
    for i in 0..5 {
        engine.record_degradation(DegradationEvent {
            component: "embeddings".to_string(),
            failure: format!("failure {i}"),
            fallback_used: "tfidf-fallback".to_string(),
            timestamp: Utc::now(),
        });
    }

    let alerts = engine.degradation_alerts();
    assert!(!alerts.is_empty());
}

#[test]
fn degradation_tracker_mark_recovered() {
    let mut engine = ObservabilityEngine::new();
    engine.record_degradation(DegradationEvent {
        component: "embeddings".to_string(),
        failure: "provider down".to_string(),
        fallback_used: "tfidf".to_string(),
        timestamp: Utc::now(),
    });
    engine.mark_recovered("embeddings");
    // After recovery, alerts should be reduced or empty.
    let alerts = engine.degradation_alerts();
    // The recovered component should not generate critical alerts.
    for alert in &alerts {
        if alert.component == "embeddings" {
            assert_ne!(
                format!("{:?}", alert.level),
                "Critical",
                "recovered component should not be critical"
            );
        }
    }
}

// ─── Engine ──────────────────────────────────────────────────────────────────

#[test]
fn engine_health_report() {
    let mut engine = ObservabilityEngine::new();
    let snapshot = HealthSnapshot {
        total_memories: 50,
        active_memories: 45,
        archived_memories: 5,
        average_confidence: 0.8,
        db_size_bytes: 5_000_000,
        embedding_cache_hit_rate: 0.85,
        stale_count: 1,
        contradiction_count: 0,
        unresolved_contradictions: 0,
        consolidation_count: 3,
        memories_needing_validation: 2,
        drift_summary: None,
    };
    let report = engine.health_report(snapshot).unwrap();
    assert_eq!(report.metrics.total_memories, 50);
}

#[test]
fn engine_recommendations() {
    let engine = ObservabilityEngine::new();
    let recs = engine.recommendations();
    // Default engine with no snapshot should return empty or minimal recommendations.
    let _ = recs; // Just ensure it doesn't panic.
}

#[test]
fn engine_reset_metrics() {
    let mut engine = ObservabilityEngine::new();
    engine.reset_metrics();
    // Should not panic.
}

// ─── Metrics Collector ───────────────────────────────────────────────────────

#[test]
fn metrics_collector_retrieval_record_and_reset() {
    let mut collector = cortex_observability::MetricsCollector::new();
    collector.retrieval.record_query(None, true, 100, 200);
    collector.retrieval.record_query(None, false, 50, 200);
    assert!(collector.retrieval.token_efficiency() > 0.0);

    collector.reset();
    assert_eq!(collector.retrieval.token_efficiency(), 0.0);
}

#[test]
fn metrics_collector_consolidation_metrics() {
    let mut collector = cortex_observability::MetricsCollector::new();
    collector.consolidation.record(
        cortex_core::models::ConsolidationMetrics {
            precision: 0.9,
            compression_ratio: 0.5,
            lift: 0.8,
            stability: 0.95,
        },
        2,
    );
    assert!(collector.consolidation.avg_precision() > 0.0);
}

// ─── Query Log ───────────────────────────────────────────────────────────────

#[test]
fn query_log_record_and_count() {
    use cortex_observability::query_log::{QueryLog, QueryLogEntry};
    use std::time::Duration;

    let mut log = QueryLog::new();
    log.record(QueryLogEntry::new(
        "test query",
        None,
        Duration::from_millis(5),
        10,
        2000,
        500,
        3,
    ));
    assert_eq!(log.count(), 1);
}

#[test]
fn query_log_avg_latency() {
    use cortex_observability::query_log::{QueryLog, QueryLogEntry};
    use std::time::Duration;

    let mut log = QueryLog::new();
    log.record(QueryLogEntry::new(
        "q1",
        None,
        Duration::from_millis(10),
        5,
        1000,
        200,
        1,
    ));
    log.record(QueryLogEntry::new(
        "q2",
        None,
        Duration::from_millis(20),
        5,
        1000,
        200,
        1,
    ));
    let avg = log.avg_latency();
    assert_eq!(avg, Duration::from_millis(15));
}

#[test]
fn query_log_latency_percentile() {
    use cortex_observability::query_log::{QueryLog, QueryLogEntry};
    use std::time::Duration;

    let mut log = QueryLog::new();
    for i in 1..=100 {
        log.record(QueryLogEntry::new(
            format!("q{i}"),
            None,
            Duration::from_millis(i),
            1,
            1000,
            100,
            0,
        ));
    }
    let p95 = log.latency_percentile(0.95);
    assert!(p95 >= Duration::from_millis(90));
}

// ─── Embedding Metrics ───────────────────────────────────────────────────────

#[test]
fn embedding_metrics_cache_lookups() {
    let mut m = cortex_observability::metrics::EmbeddingMetrics::new();
    m.record_lookup(Some(1)); // L1 hit
    m.record_lookup(Some(2)); // L2 hit
    m.record_lookup(Some(3)); // L3 hit
    m.record_lookup(None); // Miss
    assert_eq!(m.total_lookups, 4);
    assert_eq!(m.l1_hits, 1);
    assert!((m.l1_hit_rate() - 0.25).abs() < 0.01);
    assert!((m.l2_hit_rate() - 0.25).abs() < 0.01);
    assert!((m.l3_hit_rate() - 0.25).abs() < 0.01);
    assert!((m.combined_hit_rate() - 0.75).abs() < 0.01);
}

#[test]
fn embedding_metrics_latency() {
    use std::time::Duration;
    let mut m = cortex_observability::metrics::EmbeddingMetrics::new();
    m.record_latency(Duration::from_millis(10));
    m.record_latency(Duration::from_millis(20));
    m.record_latency(Duration::from_millis(30));
    let p50 = m.latency_percentile(0.5);
    assert!(p50 >= Duration::from_millis(10));
}

#[test]
fn embedding_metrics_provider_usage() {
    let mut m = cortex_observability::metrics::EmbeddingMetrics::new();
    m.record_provider("onnx");
    m.record_provider("onnx");
    m.record_provider("tfidf");
    assert_eq!(m.provider_usage["onnx"], 2);
    assert_eq!(m.provider_usage["tfidf"], 1);
}

#[test]
fn embedding_metrics_migration_progress() {
    let mut m = cortex_observability::metrics::EmbeddingMetrics::new();
    assert_eq!(m.migration_progress(), 1.0); // No migration = complete.
    m.set_migration_progress(50, 100);
    assert!((m.migration_progress() - 0.5).abs() < 0.01);
}

// ─── Retrieval Metrics ───────────────────────────────────────────────────────

#[test]
fn retrieval_metrics_record_and_hit_rate() {
    use cortex_core::intent::Intent;
    let mut m = cortex_observability::metrics::RetrievalMetrics::new();
    m.record_query(Some(Intent::FixBug), true, 500, 2000);
    m.record_query(Some(Intent::FixBug), false, 0, 2000);
    assert!((m.hit_rate(Intent::FixBug) - 0.5).abs() < 0.01);
    assert!(m.token_efficiency() > 0.0);
}

#[test]
fn retrieval_metrics_useful_memory() {
    let mut m = cortex_observability::metrics::RetrievalMetrics::new();
    m.record_useful_memory("m1");
    m.record_useful_memory("m1");
    m.record_useful_memory("m2");
    assert_eq!(m.most_useful[0].0, "m1");
    assert_eq!(m.most_useful[0].1, 2);
}

#[test]
fn retrieval_metrics_expansion() {
    let mut m = cortex_observability::metrics::RetrievalMetrics::new();
    m.record_expansion(true);
    m.record_expansion(false);
    assert_eq!(m.expansion_improvements, 1);
    assert_eq!(m.expansion_attempts, 2);
}

// ─── Session Metrics ─────────────────────────────────────────────────────────

#[test]
fn session_metrics_lifecycle() {
    use std::time::Duration;
    let mut m = cortex_observability::metrics::SessionMetrics::new();
    m.session_started();
    assert_eq!(m.active_sessions, 1);
    m.session_ended(Duration::from_secs(300));
    assert_eq!(m.active_sessions, 0);
    assert_eq!(m.avg_duration(), Duration::from_secs(300));
}

#[test]
fn session_metrics_dedup() {
    let mut m = cortex_observability::metrics::SessionMetrics::new();
    m.record_dedup(1000, 600);
    assert_eq!(m.tokens_saved_by_dedup, 400);
    assert!((m.dedup_savings_rate() - 0.4).abs() < 0.01);
}

#[test]
fn session_metrics_intent_distribution() {
    let mut m = cortex_observability::metrics::SessionMetrics::new();
    m.record_intent("FixBug");
    m.record_intent("FixBug");
    m.record_intent("AddFeature");
    assert_eq!(m.intent_distribution["FixBug"], 2);
}

// ─── Storage Metrics ─────────────────────────────────────────────────────────

#[test]
fn storage_metrics_record_and_growth() {
    let mut m = cortex_observability::metrics::StorageMetrics::new();
    m.record_size(1000, 1_000_000);
    m.record_size(87400, 2_000_000); // ~1 day later
    let rate = m.growth_rate_bytes_per_day();
    assert!(rate > 0.0);
}

#[test]
fn storage_metrics_fragmentation() {
    let mut m = cortex_observability::metrics::StorageMetrics::new();
    m.set_fragmentation(0.15);
    assert!((m.fragmentation - 0.15).abs() < 0.01);
    m.set_fragmentation(1.5); // Should clamp.
    assert!((m.fragmentation - 1.0).abs() < 0.01);
}

#[test]
fn storage_metrics_days_to_threshold() {
    let mut m = cortex_observability::metrics::StorageMetrics::new();
    m.record_size(0, 500_000);
    m.record_size(86400, 600_000); // 100KB/day growth.
    let days = m.days_to_threshold(1_000_000);
    assert!(days.is_some());
    assert!(days.unwrap() > 0.0);
}

#[test]
fn storage_metrics_no_growth() {
    let m = cortex_observability::metrics::StorageMetrics::new();
    assert_eq!(m.growth_rate_bytes_per_day(), 0.0);
    assert!(m.days_to_threshold(1_000_000).is_none());
}

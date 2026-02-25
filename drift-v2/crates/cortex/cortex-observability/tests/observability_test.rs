//! Tests for cortex-observability (T10-OBS-01 through T10-OBS-06).

use std::time::Duration;

use chrono::Utc;
use cortex_core::intent::Intent;
use cortex_core::models::{ConsolidationMetrics, DegradationEvent, HealthStatus};
use cortex_core::traits::IHealthReporter;

use cortex_observability::degradation::{evaluate_alerts, AlertLevel, DegradationTracker};
use cortex_observability::health::recommendations::{generate, Severity};
use cortex_observability::health::{HealthChecker, HealthSnapshot};
use cortex_observability::metrics::MetricsCollector;
use cortex_observability::query_log::{QueryLog, QueryLogEntry};
use cortex_observability::ObservabilityEngine;

// ---------------------------------------------------------------------------
// T10-OBS-01: Health report includes all subsystem statuses
// ---------------------------------------------------------------------------

#[test]
fn health_report_includes_all_subsystem_statuses() {
    let snapshot = HealthSnapshot {
        total_memories: 100,
        active_memories: 80,
        archived_memories: 20,
        average_confidence: 0.85,
        db_size_bytes: 1_000_000,
        embedding_cache_hit_rate: 0.75,
        stale_count: 0,
        contradiction_count: 0,
        unresolved_contradictions: 0,
        consolidation_count: 5,
        memories_needing_validation: 0,
        drift_summary: None,
    };

    let mut checker = HealthChecker::new();
    checker.set_snapshot(snapshot);
    let report = checker.report().unwrap();

    // Must have all 4 subsystems.
    assert_eq!(report.subsystems.len(), 4);
    let names: Vec<&str> = report.subsystems.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"storage"));
    assert!(names.contains(&"embeddings"));
    assert!(names.contains(&"causal_graph"));
    assert!(names.contains(&"privacy"));

    // All healthy in this scenario.
    assert_eq!(report.overall_status, HealthStatus::Healthy);
    for sub in &report.subsystems {
        assert_eq!(sub.status, HealthStatus::Healthy);
    }
}

#[test]
fn health_report_degraded_when_subsystem_degraded() {
    let snapshot = HealthSnapshot {
        total_memories: 100,
        active_memories: 10,
        archived_memories: 85, // >80% archived → storage degraded
        average_confidence: 0.85,
        db_size_bytes: 500_000,
        embedding_cache_hit_rate: 0.75,
        ..Default::default()
    };

    let mut checker = HealthChecker::new();
    checker.set_snapshot(snapshot);
    let report = checker.report().unwrap();

    assert_eq!(report.overall_status, HealthStatus::Degraded);
    let storage = report
        .subsystems
        .iter()
        .find(|s| s.name == "storage")
        .unwrap();
    assert_eq!(storage.status, HealthStatus::Degraded);
}

#[test]
fn health_report_unhealthy_when_db_too_large() {
    let snapshot = HealthSnapshot {
        db_size_bytes: 2_000_000_000, // 2 GB > 1 GB threshold
        embedding_cache_hit_rate: 0.75,
        ..Default::default()
    };

    let mut checker = HealthChecker::new();
    checker.set_snapshot(snapshot);
    let report = checker.report().unwrap();

    assert_eq!(report.overall_status, HealthStatus::Unhealthy);
}

#[test]
fn health_report_unhealthy_when_embedding_cache_very_low() {
    let snapshot = HealthSnapshot {
        embedding_cache_hit_rate: 0.05, // <10% → unhealthy
        ..Default::default()
    };

    let mut checker = HealthChecker::new();
    checker.set_snapshot(snapshot);
    let report = checker.report().unwrap();

    assert_eq!(report.overall_status, HealthStatus::Unhealthy);
    let emb = report
        .subsystems
        .iter()
        .find(|s| s.name == "embeddings")
        .unwrap();
    assert_eq!(emb.status, HealthStatus::Unhealthy);
}

// ---------------------------------------------------------------------------
// T10-OBS-02: Degradation alerting triggers on threshold (>3/hour → warning)
// ---------------------------------------------------------------------------

#[test]
fn degradation_alerting_warning_on_threshold() {
    let mut tracker = DegradationTracker::new();

    // Record 4 degradation events for the same component within the last hour.
    for i in 0..4 {
        tracker.record(DegradationEvent {
            component: "embeddings".into(),
            failure: format!("timeout_{}", i),
            fallback_used: "local_cache".into(),
            timestamp: Utc::now(),
        });
    }

    let alerts = evaluate_alerts(&tracker);
    assert!(!alerts.is_empty());
    let emb_alert = alerts.iter().find(|a| a.component == "embeddings").unwrap();
    assert_eq!(emb_alert.level, AlertLevel::Warning);
    assert!(emb_alert.message.contains("4 degradation events"));
}

#[test]
fn degradation_no_alert_below_threshold() {
    let mut tracker = DegradationTracker::new();

    // Only 2 events — below the >3 threshold.
    for _ in 0..2 {
        tracker.record(DegradationEvent {
            component: "storage".into(),
            failure: "disk_slow".into(),
            fallback_used: "memory_cache".into(),
            timestamp: Utc::now(),
        });
    }

    let alerts = evaluate_alerts(&tracker);
    let storage_alerts: Vec<_> = alerts.iter().filter(|a| a.component == "storage").collect();
    assert!(storage_alerts.is_empty());
}

#[test]
fn degradation_recovery_tracking() {
    let mut tracker = DegradationTracker::new();

    tracker.record(DegradationEvent {
        component: "embeddings".into(),
        failure: "provider_down".into(),
        fallback_used: "local_onnx".into(),
        timestamp: Utc::now(),
    });

    assert_eq!(tracker.active_degradations().len(), 1);

    tracker.mark_recovered("embeddings");
    assert_eq!(tracker.active_degradations().len(), 0);
}

// ---------------------------------------------------------------------------
// T10-OBS-03: Metrics aggregate correctly across time windows
// ---------------------------------------------------------------------------

#[test]
fn retrieval_metrics_aggregate_correctly() {
    let mut collector = MetricsCollector::new();

    collector
        .retrieval
        .record_query(Some(Intent::Recall), true, 500, 1000);
    collector
        .retrieval
        .record_query(Some(Intent::Recall), true, 300, 1000);
    collector
        .retrieval
        .record_query(Some(Intent::Recall), false, 0, 1000);
    collector
        .retrieval
        .record_query(Some(Intent::FixBug), true, 800, 1000);

    // Recall: 2 hits / 3 queries.
    let recall_rate = collector.retrieval.hit_rate(Intent::Recall);
    assert!((recall_rate - 2.0 / 3.0).abs() < 0.001);

    // FixBug: 1 hit / 1 query.
    assert!((collector.retrieval.hit_rate(Intent::FixBug) - 1.0).abs() < 0.001);

    // Token efficiency: 1600 / 4000.
    assert!((collector.retrieval.token_efficiency() - 0.4).abs() < 0.001);
}

#[test]
fn consolidation_metrics_aggregate_correctly() {
    let mut collector = MetricsCollector::new();

    collector.consolidation.record(
        ConsolidationMetrics {
            precision: 0.9,
            compression_ratio: 2.0,
            lift: 1.5,
            stability: 0.8,
        },
        1,
    );
    collector.consolidation.record(
        ConsolidationMetrics {
            precision: 0.7,
            compression_ratio: 3.0,
            lift: 1.0,
            stability: 0.6,
        },
        2,
    );

    assert!((collector.consolidation.avg_precision() - 0.8).abs() < 0.001);
    assert!((collector.consolidation.avg_compression_ratio() - 2.5).abs() < 0.001);
    assert!((collector.consolidation.avg_lift() - 1.25).abs() < 0.001);
    assert!((collector.consolidation.avg_stability() - 0.7).abs() < 0.001);
    assert!((collector.consolidation.contradiction_rate() - 1.5).abs() < 0.001);
}

#[test]
fn storage_metrics_growth_rate() {
    let mut collector = MetricsCollector::new();

    let now = Utc::now().timestamp();
    collector.storage.record_size(now - 86_400, 1_000_000); // 1 day ago: 1 MB
    collector.storage.record_size(now, 2_000_000); // now: 2 MB

    let rate = collector.storage.growth_rate_bytes_per_day();
    assert!((rate - 1_000_000.0).abs() < 100.0); // ~1 MB/day

    let days = collector.storage.days_to_threshold(10_000_000).unwrap();
    assert!((days - 8.0).abs() < 0.1); // ~8 days to 10 MB
}

#[test]
fn embedding_metrics_cache_rates() {
    let mut collector = MetricsCollector::new();

    for _ in 0..3 {
        collector.embedding.record_lookup(Some(1));
    }
    for _ in 0..2 {
        collector.embedding.record_lookup(Some(2));
    }
    collector.embedding.record_lookup(Some(3));
    for _ in 0..4 {
        collector.embedding.record_lookup(None);
    } // misses

    assert_eq!(collector.embedding.total_lookups, 10);
    assert!((collector.embedding.l1_hit_rate() - 0.3).abs() < 0.001);
    assert!((collector.embedding.l2_hit_rate() - 0.2).abs() < 0.001);
    assert!((collector.embedding.l3_hit_rate() - 0.1).abs() < 0.001);
    assert!((collector.embedding.combined_hit_rate() - 0.6).abs() < 0.001);
}

#[test]
fn session_metrics_dedup_savings() {
    let mut collector = MetricsCollector::new();

    collector.session.session_started();
    collector.session.record_dedup(1000, 600); // saved 400
    collector.session.record_dedup(500, 300); // saved 200
    collector.session.session_ended(Duration::from_secs(120));

    assert_eq!(collector.session.active_sessions, 0);
    assert!((collector.session.dedup_savings_rate() - 0.4).abs() < 0.001); // 600/1500
    assert_eq!(collector.session.avg_duration(), Duration::from_secs(120));
}

// ---------------------------------------------------------------------------
// T10-OBS-04: Recommendations generated for actionable conditions
// ---------------------------------------------------------------------------

#[test]
fn recommendations_for_validation_needed() {
    let snapshot = HealthSnapshot {
        memories_needing_validation: 15,
        ..Default::default()
    };

    let recs = generate(&snapshot);
    assert!(recs
        .iter()
        .any(|r| r.message.contains("15 memories need validation")));
    let val_rec = recs
        .iter()
        .find(|r| r.message.contains("validation"))
        .unwrap();
    assert_eq!(val_rec.severity, Severity::Warning); // >10 → warning
}

#[test]
fn recommendations_for_contradictions() {
    let snapshot = HealthSnapshot {
        unresolved_contradictions: 3,
        ..Default::default()
    };

    let recs = generate(&snapshot);
    assert!(recs.iter().any(|r| r.message.contains("3 contradictions")));
}

#[test]
fn recommendations_for_low_confidence() {
    let snapshot = HealthSnapshot {
        total_memories: 50,
        average_confidence: 0.35,
        ..Default::default()
    };

    let recs = generate(&snapshot);
    let conf_rec = recs
        .iter()
        .find(|r| r.message.contains("confidence"))
        .unwrap();
    assert_eq!(conf_rec.severity, Severity::Critical);
}

#[test]
fn recommendations_for_stale_memories() {
    let snapshot = HealthSnapshot {
        stale_count: 25,
        ..Default::default()
    };

    let recs = generate(&snapshot);
    assert!(recs.iter().any(|r| r.message.contains("25 stale memories")));
}

#[test]
fn no_recommendations_when_healthy() {
    let snapshot = HealthSnapshot {
        total_memories: 100,
        active_memories: 90,
        average_confidence: 0.85,
        embedding_cache_hit_rate: 0.80,
        ..Default::default()
    };

    let recs = generate(&snapshot);
    assert!(recs.is_empty());
}

// ---------------------------------------------------------------------------
// T10-OBS-05: Query log records all retrieval queries with correct fields
// ---------------------------------------------------------------------------

#[test]
fn query_log_records_all_fields() {
    let mut log = QueryLog::new();

    log.record(QueryLogEntry::new(
        "how to deploy",
        Some(Intent::DeployMigrate),
        Duration::from_millis(42),
        5,
        2000,
        1500,
        3,
    ));

    assert_eq!(log.count(), 1);
    let entry = &log.entries()[0];
    assert_eq!(entry.query, "how to deploy");
    assert_eq!(entry.intent, Some(Intent::DeployMigrate));
    assert_eq!(entry.latency, Duration::from_millis(42));
    assert_eq!(entry.result_count, 5);
    assert_eq!(entry.token_budget, 2000);
    assert_eq!(entry.tokens_used, 1500);
    assert_eq!(entry.cache_hits, 3);
    assert!(entry.timestamp_epoch_ms > 0);
}

#[test]
fn query_log_latency_percentiles() {
    let mut log = QueryLog::new();

    for ms in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
        log.record(QueryLogEntry::new(
            "test",
            None,
            Duration::from_millis(ms),
            1,
            100,
            50,
            0,
        ));
    }

    let p50 = log.latency_percentile(0.5);
    assert!(p50 >= Duration::from_millis(50) && p50 <= Duration::from_millis(60));

    let p95 = log.latency_percentile(0.95);
    assert!(p95 >= Duration::from_millis(90));
}

#[test]
fn query_log_respects_capacity() {
    let mut log = QueryLog::with_capacity(5);

    for i in 0..10 {
        log.record(QueryLogEntry::new(
            format!("q{}", i),
            None,
            Duration::from_millis(1),
            0,
            0,
            0,
            0,
        ));
    }

    assert_eq!(log.count(), 5);
    // Should retain the most recent entries.
    assert_eq!(log.entries()[0].query, "q5");
    assert_eq!(log.entries()[4].query, "q9");
}

// ---------------------------------------------------------------------------
// T10-OBS-06: Tracing spans capture duration and result for each operation
// ---------------------------------------------------------------------------

#[test]
fn tracing_span_names_defined() {
    use cortex_observability::tracing_setup::spans::names;

    assert_eq!(names::RETRIEVAL, "cortex.retrieval");
    assert_eq!(names::CONSOLIDATION, "cortex.consolidation");
    assert_eq!(names::DECAY, "cortex.decay");
    assert_eq!(names::VALIDATION, "cortex.validation");
    assert_eq!(names::LEARNING, "cortex.learning");
    assert_eq!(names::EMBEDDING, "cortex.embedding");
}

#[test]
fn tracing_events_do_not_panic() {
    // Ensure structured event functions don't panic when called.
    use cortex_observability::tracing_setup::events;

    events::memory_created("mem-1", "core");
    events::memory_archived("mem-2", "stale");
    events::consolidation_completed(3, 2, 0.95);
    events::contradiction_detected(&["m1".into(), "m2".into()], "direct");
    events::degradation_triggered("embeddings", "timeout", "local_cache");
    events::migration_progress(50, 100, "onnx");
}

// ---------------------------------------------------------------------------
// Integration: ObservabilityEngine
// ---------------------------------------------------------------------------

#[test]
fn engine_full_workflow() {
    let mut engine = ObservabilityEngine::new();

    // Record some metrics.
    engine
        .metrics
        .retrieval
        .record_query(Some(Intent::Recall), true, 500, 1000);
    engine.metrics.embedding.record_lookup(Some(1));
    engine.metrics.session.session_started();

    // Record a degradation.
    engine.record_degradation(DegradationEvent {
        component: "embeddings".into(),
        failure: "provider_timeout".into(),
        fallback_used: "local_onnx".into(),
        timestamp: Utc::now(),
    });

    // Log a query.
    engine.query_log.record(QueryLogEntry::new(
        "find auth patterns",
        Some(Intent::Recall),
        Duration::from_millis(25),
        3,
        1000,
        750,
        1,
    ));

    // Generate health report.
    let snapshot = HealthSnapshot {
        total_memories: 200,
        active_memories: 180,
        archived_memories: 20,
        average_confidence: 0.82,
        db_size_bytes: 5_000_000,
        embedding_cache_hit_rate: 0.70,
        stale_count: 5,
        contradiction_count: 1,
        unresolved_contradictions: 1,
        consolidation_count: 10,
        memories_needing_validation: 3,
        drift_summary: None,
    };

    let report = engine.health_report(snapshot).unwrap();
    assert_eq!(report.overall_status, HealthStatus::Healthy);
    assert_eq!(report.subsystems.len(), 4);
    assert_eq!(report.metrics.total_memories, 200);

    // Recommendations.
    let recs = engine.recommendations();
    assert!(recs
        .iter()
        .any(|r| r.message.contains("3 memories need validation")));
    assert!(recs.iter().any(|r| r.message.contains("1 contradictions")));

    // Degradation alerts (only 1 event, below threshold).
    let alerts = engine.degradation_alerts();
    assert!(alerts.is_empty() || alerts.iter().all(|a| a.level < AlertLevel::Warning));

    // Recovery.
    engine.mark_recovered("embeddings");
    assert!(engine.degradation.active_degradations().is_empty());

    // Query log.
    assert_eq!(engine.query_log.count(), 1);
}

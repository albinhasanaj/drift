//! Phase B tests — B-T01 through B-T06.
//!
//! Tests for contradiction counts in health, privacy health check,
//! MetricsCollector serde, and embedding cache stats.

use cortex_core::models::HealthStatus;
use cortex_observability::health::reporter::HealthSnapshot;
use cortex_observability::health::subsystem_checks::SubsystemChecker;
use cortex_observability::metrics::MetricsCollector;

// ── B-T01: HealthSnapshot contradiction_count flows through ─────────────────

/// B-T01: Contradiction count appears in health report subsystem checks.
#[test]
fn bt01_contradiction_count_in_health() {
    let snapshot = HealthSnapshot {
        total_memories: 100,
        active_memories: 80,
        archived_memories: 20,
        average_confidence: 0.7,
        db_size_bytes: 1_000_000,
        embedding_cache_hit_rate: 0.9,
        stale_count: 5,
        contradiction_count: 15,
        unresolved_contradictions: 0,
        consolidation_count: 3,
        memories_needing_validation: 10,
        drift_summary: None,
    };

    let subsystems = SubsystemChecker::check_all(&snapshot);
    // With 15 contradictions, the privacy check should report degraded.
    let privacy = subsystems.iter().find(|s| s.name == "privacy");
    assert!(privacy.is_some(), "privacy subsystem should be checked");
    let privacy = privacy.unwrap();
    assert_eq!(
        privacy.status,
        HealthStatus::Degraded,
        "privacy should be degraded with >10 contradictions"
    );
    assert!(
        privacy.message.as_ref().unwrap().contains("contradictions"),
        "message should mention contradictions"
    );
}

// ── B-T02: Privacy health check with low confidence ─────────────────────────

/// B-T02: Privacy degrades when average confidence is very low.
#[test]
fn bt02_privacy_low_confidence_degraded() {
    let snapshot = HealthSnapshot {
        total_memories: 50,
        active_memories: 50,
        average_confidence: 0.2, // Very low
        contradiction_count: 0,
        ..Default::default()
    };

    let subsystems = SubsystemChecker::check_all(&snapshot);
    let privacy = subsystems.iter().find(|s| s.name == "privacy").unwrap();
    assert_eq!(
        privacy.status,
        HealthStatus::Degraded,
        "privacy should be degraded with avg confidence < 0.3"
    );
}

/// B-T03: Privacy healthy when everything is normal.
#[test]
fn bt03_privacy_healthy_normal() {
    let snapshot = HealthSnapshot {
        total_memories: 100,
        active_memories: 90,
        average_confidence: 0.8,
        contradiction_count: 2, // Below threshold
        ..Default::default()
    };

    let subsystems = SubsystemChecker::check_all(&snapshot);
    let privacy = subsystems.iter().find(|s| s.name == "privacy").unwrap();
    assert_eq!(
        privacy.status,
        HealthStatus::Healthy,
        "privacy should be healthy with normal metrics"
    );
}

// ── B-T04: MetricsCollector derives Serialize ───────────────────────────────

/// B-T04: MetricsCollector can be serialized to JSON.
#[test]
fn bt04_metrics_collector_serializes() {
    let collector = MetricsCollector::new();
    let json = serde_json::to_value(&collector);
    assert!(json.is_ok(), "MetricsCollector should serialize to JSON");

    let val = json.unwrap();
    assert!(val.is_object(), "serialized metrics should be a JSON object");
    assert!(
        val.get("retrieval").is_some(),
        "should contain retrieval metrics"
    );
    assert!(
        val.get("consolidation").is_some(),
        "should contain consolidation metrics"
    );
    assert!(
        val.get("storage").is_some(),
        "should contain storage metrics"
    );
    assert!(
        val.get("embedding").is_some(),
        "should contain embedding metrics"
    );
    assert!(
        val.get("session").is_some(),
        "should contain session metrics"
    );
}

// ── B-T05: HealthSnapshot default values ────────────────────────────────────

/// B-T05: Default HealthSnapshot has zero contradictions.
#[test]
fn bt05_default_snapshot_zero_contradictions() {
    let snapshot = HealthSnapshot::default();
    assert_eq!(snapshot.contradiction_count, 0);
    assert_eq!(snapshot.unresolved_contradictions, 0);
    assert_eq!(snapshot.total_memories, 0);
    assert!((snapshot.embedding_cache_hit_rate - 0.0).abs() < f64::EPSILON);
}

// ── B-T06: HealthReporter builds from snapshot ──────────────────────────────

/// B-T06: HealthReporter builds a valid report from a populated snapshot.
#[test]
fn bt06_health_reporter_builds_report() {
    use cortex_observability::health::reporter::HealthReporter;

    let snapshot = HealthSnapshot {
        total_memories: 200,
        active_memories: 180,
        archived_memories: 20,
        average_confidence: 0.75,
        db_size_bytes: 5_000_000,
        embedding_cache_hit_rate: 0.85,
        stale_count: 10,
        contradiction_count: 3,
        unresolved_contradictions: 1,
        consolidation_count: 5,
        memories_needing_validation: 15,
        drift_summary: None,
    };

    let report = HealthReporter::build(&snapshot).expect("should build report");
    assert!(!report.subsystems.is_empty(), "report should have subsystems");
    assert_eq!(report.metrics.total_memories, 200);
    assert_eq!(report.metrics.active_memories, 180);
    assert!((report.metrics.average_confidence - 0.75).abs() < f64::EPSILON);
}

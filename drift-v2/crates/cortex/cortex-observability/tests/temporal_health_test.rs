//! Phase D3 tests — TTD3-07 through TTD3-09, TTD3-12: Temporal drift in health reports.

use cortex_core::models::HealthStatus;
use cortex_core::traits::IHealthReporter;
use cortex_observability::health::recommendations::{generate, Severity};
use cortex_observability::health::subsystem_checks::SubsystemChecker;
use cortex_observability::health::{DriftSummary, HealthChecker, HealthSnapshot, TrendIndicator};

// ─── TTD3-07: Health report includes drift summary ───────────────────────────

#[test]
fn ttd3_07_health_report_includes_drift_summary() {
    let snapshot = HealthSnapshot {
        total_memories: 100,
        active_memories: 90,
        archived_memories: 10,
        average_confidence: 0.85,
        db_size_bytes: 1_000_000,
        embedding_cache_hit_rate: 0.75,
        drift_summary: Some(DriftSummary {
            active_alerts: 1,
            overall_ksi: 0.85,
            overall_efi: 0.90,
            ksi_trend: TrendIndicator::Stable,
            efi_trend: TrendIndicator::Improving,
        }),
        ..Default::default()
    };

    let mut checker = HealthChecker::new();
    checker.set_snapshot(snapshot);
    let report = checker.report().unwrap();

    // Should have 5 subsystems now (4 original + temporal).
    assert_eq!(
        report.subsystems.len(),
        5,
        "Should have 5 subsystems including temporal"
    );

    let temporal = report
        .subsystems
        .iter()
        .find(|s| s.name == "temporal")
        .expect("Should have temporal subsystem");
    assert_eq!(temporal.status, HealthStatus::Healthy);
}

// ─── TTD3-08: Subsystem check reports temporal health ────────────────────────

#[test]
fn ttd3_08_subsystem_check_reports_temporal_health() {
    // Healthy temporal system.
    let healthy_snapshot = HealthSnapshot {
        drift_summary: Some(DriftSummary {
            active_alerts: 0,
            overall_ksi: 0.9,
            overall_efi: 0.85,
            ksi_trend: TrendIndicator::Stable,
            efi_trend: TrendIndicator::Stable,
        }),
        ..Default::default()
    };

    let result = SubsystemChecker::check_temporal(&healthy_snapshot);
    assert_eq!(result.name, "temporal");
    assert_eq!(result.status, HealthStatus::Healthy);

    // Degraded temporal system (low KSI).
    let degraded_snapshot = HealthSnapshot {
        drift_summary: Some(DriftSummary {
            active_alerts: 3,
            overall_ksi: 0.35,
            overall_efi: 0.6,
            ksi_trend: TrendIndicator::Declining,
            efi_trend: TrendIndicator::Stable,
        }),
        ..Default::default()
    };

    let result = SubsystemChecker::check_temporal(&degraded_snapshot);
    assert_eq!(result.status, HealthStatus::Degraded);

    // Unhealthy temporal system (many alerts + very low KSI).
    let unhealthy_snapshot = HealthSnapshot {
        drift_summary: Some(DriftSummary {
            active_alerts: 8,
            overall_ksi: 0.15,
            overall_efi: 0.3,
            ksi_trend: TrendIndicator::Declining,
            efi_trend: TrendIndicator::Declining,
        }),
        ..Default::default()
    };

    let result = SubsystemChecker::check_temporal(&unhealthy_snapshot);
    assert_eq!(result.status, HealthStatus::Unhealthy);

    // No drift data — graceful handling.
    let no_drift_snapshot = HealthSnapshot {
        drift_summary: None,
        ..Default::default()
    };

    let result = SubsystemChecker::check_temporal(&no_drift_snapshot);
    assert_eq!(result.status, HealthStatus::Healthy);
    assert!(result.message.is_some());
}

// ─── TTD3-09: Temporal recommendations generated ─────────────────────────────

#[test]
fn ttd3_09_temporal_recommendations_generated() {
    // Low KSI → "investigate knowledge churn".
    let low_ksi_snapshot = HealthSnapshot {
        drift_summary: Some(DriftSummary {
            active_alerts: 1,
            overall_ksi: 0.2,
            overall_efi: 0.8,
            ksi_trend: TrendIndicator::Declining,
            efi_trend: TrendIndicator::Stable,
        }),
        ..Default::default()
    };

    let recs = generate(&low_ksi_snapshot);
    assert!(
        recs.iter().any(|r| r.action.contains("investigate knowledge churn")),
        "Should recommend investigating knowledge churn when KSI < 0.3. Got: {:?}",
        recs
    );

    // Low EFI → "review stale evidence".
    let low_efi_snapshot = HealthSnapshot {
        drift_summary: Some(DriftSummary {
            active_alerts: 0,
            overall_ksi: 0.8,
            overall_efi: 0.3,
            ksi_trend: TrendIndicator::Stable,
            efi_trend: TrendIndicator::Declining,
        }),
        ..Default::default()
    };

    let recs = generate(&low_efi_snapshot);
    assert!(
        recs.iter().any(|r| r.action.contains("review stale evidence")),
        "Should recommend reviewing stale evidence when EFI < 0.5. Got: {:?}",
        recs
    );

    // Many active alerts → "run snapshot compaction".
    let many_alerts_snapshot = HealthSnapshot {
        drift_summary: Some(DriftSummary {
            active_alerts: 5,
            overall_ksi: 0.7,
            overall_efi: 0.7,
            ksi_trend: TrendIndicator::Stable,
            efi_trend: TrendIndicator::Stable,
        }),
        ..Default::default()
    };

    let recs = generate(&many_alerts_snapshot);
    assert!(
        recs.iter().any(|r| r.action.contains("run snapshot compaction")),
        "Should recommend snapshot compaction when many alerts. Got: {:?}",
        recs
    );

    // All temporal recommendations should be Warning severity.
    for rec in &recs {
        if rec.action.contains("compaction")
            || rec.action.contains("stale evidence")
            || rec.action.contains("knowledge churn")
        {
            assert_eq!(
                rec.severity,
                Severity::Warning,
                "Temporal recommendations should be Warning severity"
            );
        }
    }
}

// ─── TTD3-12: No observability test regressions ──────────────────────────────

#[test]
fn ttd3_12_no_drift_summary_still_works() {
    // Ensure health reports work fine without drift data.
    let snapshot = HealthSnapshot {
        total_memories: 50,
        active_memories: 45,
        archived_memories: 5,
        average_confidence: 0.8,
        db_size_bytes: 1_000_000,
        embedding_cache_hit_rate: 0.75,
        drift_summary: None,
        ..Default::default()
    };

    let mut checker = HealthChecker::new();
    checker.set_snapshot(snapshot);
    let report = checker.report().unwrap();

    // Should still have 4 subsystems (no temporal when drift_summary is None).
    assert_eq!(report.subsystems.len(), 4);
    assert_eq!(report.overall_status, HealthStatus::Healthy);

    // Recommendations should not include temporal ones.
    let recs = checker.recommendations();
    assert!(
        !recs.iter().any(|r| r.action.contains("knowledge churn")
            || r.action.contains("stale evidence")
            || r.action.contains("compaction")),
        "Should not have temporal recommendations without drift data"
    );
}

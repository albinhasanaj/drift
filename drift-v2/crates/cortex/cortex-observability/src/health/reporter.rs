//! Aggregate health report generation.

use cortex_core::errors::CortexResult;
use cortex_core::models::{HealthMetrics, HealthReport, HealthStatus, SubsystemHealth};
use serde::{Deserialize, Serialize};

use super::recommendations::Recommendation;
use super::subsystem_checks::SubsystemChecker;

/// Trend indicator for drift metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrendIndicator {
    Improving,
    Stable,
    Declining,
}

/// Summary of drift metrics for inclusion in health reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftSummary {
    /// Number of active drift alerts.
    pub active_alerts: usize,
    /// Overall Knowledge Stability Index [0.0, 1.0].
    pub overall_ksi: f64,
    /// Overall Evidence Freshness Index [0.0, 1.0].
    pub overall_efi: f64,
    /// Trend for KSI over recent windows.
    pub ksi_trend: TrendIndicator,
    /// Trend for EFI over recent windows.
    pub efi_trend: TrendIndicator,
}

/// Snapshot of subsystem data used to build a health report.
#[derive(Debug, Clone, Default)]
pub struct HealthSnapshot {
    pub total_memories: usize,
    pub active_memories: usize,
    pub archived_memories: usize,
    pub average_confidence: f64,
    pub db_size_bytes: u64,
    pub embedding_cache_hit_rate: f64,
    pub stale_count: usize,
    pub contradiction_count: usize,
    pub unresolved_contradictions: usize,
    pub consolidation_count: usize,
    pub memories_needing_validation: usize,
    /// Optional drift summary from the temporal subsystem.
    pub drift_summary: Option<DriftSummary>,
}

/// Builds a [`HealthReport`] from a snapshot and subsystem checks.
pub struct HealthReporter;

impl HealthReporter {
    /// Generate a full health report from the given snapshot.
    pub fn build(snapshot: &HealthSnapshot) -> CortexResult<HealthReport> {
        let subsystems = SubsystemChecker::check_all(snapshot);
        let overall_status = Self::derive_overall(&subsystems);

        Ok(HealthReport {
            overall_status,
            subsystems,
            metrics: HealthMetrics {
                total_memories: snapshot.total_memories,
                active_memories: snapshot.active_memories,
                archived_memories: snapshot.archived_memories,
                average_confidence: snapshot.average_confidence,
                db_size_bytes: snapshot.db_size_bytes,
                embedding_cache_hit_rate: snapshot.embedding_cache_hit_rate,
            },
        })
    }

    /// Generate recommendations alongside the report.
    pub fn recommendations(snapshot: &HealthSnapshot) -> Vec<Recommendation> {
        super::recommendations::generate(snapshot)
    }

    /// Derive overall status: unhealthy if any subsystem is unhealthy,
    /// degraded if any is degraded, otherwise healthy.
    fn derive_overall(subsystems: &[SubsystemHealth]) -> HealthStatus {
        let mut worst = HealthStatus::Healthy;
        for s in subsystems {
            match s.status {
                HealthStatus::Unhealthy => return HealthStatus::Unhealthy,
                HealthStatus::Degraded => worst = HealthStatus::Degraded,
                HealthStatus::Healthy => {}
            }
        }
        worst
    }
}

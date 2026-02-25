//! Per-subsystem health checks: storage, embeddings, causal graph, privacy.
//! Each returns healthy | degraded | unavailable.

use cortex_core::models::{HealthStatus, SubsystemHealth};

use super::reporter::HealthSnapshot;

/// Runs health checks against each subsystem.
pub struct SubsystemChecker;

impl SubsystemChecker {
    /// Run all subsystem checks and return their statuses.
    pub fn check_all(snapshot: &HealthSnapshot) -> Vec<SubsystemHealth> {
        let mut checks = vec![
            Self::check_storage(snapshot),
            Self::check_embeddings(snapshot),
            Self::check_causal(snapshot),
            Self::check_privacy(snapshot),
        ];
        // Temporal subsystem check is additive — only included when drift data exists.
        if snapshot.drift_summary.is_some() {
            checks.push(Self::check_temporal(snapshot));
        }
        checks
    }

    /// Storage: degraded if >80% archived, unhealthy if db_size > 1 GB.
    fn check_storage(snapshot: &HealthSnapshot) -> SubsystemHealth {
        const ONE_GB: u64 = 1_073_741_824;
        let (status, message) = if snapshot.db_size_bytes > ONE_GB {
            (
                HealthStatus::Unhealthy,
                Some("database exceeds 1 GB".into()),
            )
        } else if snapshot.total_memories > 0
            && snapshot.archived_memories * 100 / snapshot.total_memories > 80
        {
            (
                HealthStatus::Degraded,
                Some("over 80% of memories are archived".into()),
            )
        } else {
            (HealthStatus::Healthy, None)
        };
        SubsystemHealth {
            name: "storage".into(),
            status,
            message,
        }
    }

    /// Embeddings: degraded if cache hit rate < 50%, unhealthy if < 10%.
    fn check_embeddings(snapshot: &HealthSnapshot) -> SubsystemHealth {
        let (status, message) = if snapshot.embedding_cache_hit_rate < 0.10 {
            (
                HealthStatus::Unhealthy,
                Some("embedding cache hit rate below 10%".into()),
            )
        } else if snapshot.embedding_cache_hit_rate < 0.50 {
            (
                HealthStatus::Degraded,
                Some("embedding cache hit rate below 50%".into()),
            )
        } else {
            (HealthStatus::Healthy, None)
        };
        SubsystemHealth {
            name: "embeddings".into(),
            status,
            message,
        }
    }

    /// Causal graph: degraded if >10 unresolved contradictions.
    fn check_causal(snapshot: &HealthSnapshot) -> SubsystemHealth {
        let (status, message) = if snapshot.unresolved_contradictions > 10 {
            (
                HealthStatus::Degraded,
                Some(format!(
                    "{} unresolved contradictions",
                    snapshot.unresolved_contradictions
                )),
            )
        } else {
            (HealthStatus::Healthy, None)
        };
        SubsystemHealth {
            name: "causal_graph".into(),
            status,
            message,
        }
    }

    /// B-02: Privacy health check — reports degraded if contradictions exist
    /// (indicating potential data quality issues) or if the snapshot signals
    /// privacy-related problems. In a full implementation, this would query
    /// the PrivacyEngine's DegradationTracker for pattern compilation failures.
    fn check_privacy(snapshot: &HealthSnapshot) -> SubsystemHealth {
        // If contradictions are detected, privacy might be impacted
        // (contradictory memories could leak sensitive data through inconsistency).
        if snapshot.contradiction_count > 10 {
            return SubsystemHealth {
                name: "privacy".into(),
                status: HealthStatus::Degraded,
                message: Some(format!(
                    "{} contradictions detected — review for potential data quality issues",
                    snapshot.contradiction_count
                )),
            };
        }
        // If average confidence is very low, memories may contain unvalidated content.
        if snapshot.average_confidence < 0.3 && snapshot.total_memories > 0 {
            return SubsystemHealth {
                name: "privacy".into(),
                status: HealthStatus::Degraded,
                message: Some(
                    "average confidence below 0.3 — unvalidated memories may contain sensitive data".into(),
                ),
            };
        }
        SubsystemHealth {
            name: "privacy".into(),
            status: HealthStatus::Healthy,
            message: None,
        }
    }

    /// Temporal: checks drift alert count, KSI health, and EFI health.
    pub fn check_temporal(snapshot: &HealthSnapshot) -> SubsystemHealth {
        let drift = match &snapshot.drift_summary {
            Some(d) => d,
            None => {
                return SubsystemHealth {
                    name: "temporal".into(),
                    status: HealthStatus::Healthy,
                    message: Some("temporal system not yet initialized".into()),
                }
            }
        };

        let (status, message) = if drift.active_alerts > 5 || drift.overall_ksi < 0.2 {
            (
                HealthStatus::Unhealthy,
                Some(format!(
                    "{} active drift alerts, KSI={:.2}, EFI={:.2}",
                    drift.active_alerts, drift.overall_ksi, drift.overall_efi
                )),
            )
        } else if drift.active_alerts > 2 || drift.overall_ksi < 0.4 || drift.overall_efi < 0.4 {
            (
                HealthStatus::Degraded,
                Some(format!(
                    "{} active drift alerts, KSI={:.2}, EFI={:.2}",
                    drift.active_alerts, drift.overall_ksi, drift.overall_efi
                )),
            )
        } else {
            (HealthStatus::Healthy, None)
        };

        SubsystemHealth {
            name: "temporal".into(),
            status,
            message,
        }
    }
}

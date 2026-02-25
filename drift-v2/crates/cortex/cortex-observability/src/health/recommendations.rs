//! Actionable recommendations based on system health.
//!
//! Examples: "5 memories need validation", "3 contradictions unresolved".

use serde::{Deserialize, Serialize};

use super::reporter::HealthSnapshot;

/// Severity of a recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// An actionable recommendation surfaced through the health report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub severity: Severity,
    pub message: String,
    pub action: String,
}

/// Generate recommendations from the current health snapshot.
pub fn generate(snapshot: &HealthSnapshot) -> Vec<Recommendation> {
    let mut recs = Vec::new();

    if snapshot.memories_needing_validation > 0 {
        let sev = if snapshot.memories_needing_validation > 10 {
            Severity::Warning
        } else {
            Severity::Info
        };
        recs.push(Recommendation {
            severity: sev,
            message: format!(
                "{} memories need validation",
                snapshot.memories_needing_validation
            ),
            action: "run validation sweep".into(),
        });
    }

    if snapshot.unresolved_contradictions > 0 {
        let sev = if snapshot.unresolved_contradictions > 5 {
            Severity::Warning
        } else {
            Severity::Info
        };
        recs.push(Recommendation {
            severity: sev,
            message: format!(
                "{} contradictions unresolved",
                snapshot.unresolved_contradictions
            ),
            action: "review and resolve contradictions".into(),
        });
    }

    if snapshot.stale_count > 20 {
        recs.push(Recommendation {
            severity: Severity::Warning,
            message: format!("{} stale memories detected", snapshot.stale_count),
            action: "run decay sweep to archive stale memories".into(),
        });
    }

    if snapshot.embedding_cache_hit_rate < 0.30 {
        recs.push(Recommendation {
            severity: Severity::Warning,
            message: format!(
                "embedding cache hit rate is {:.0}%",
                snapshot.embedding_cache_hit_rate * 100.0
            ),
            action: "consider warming the embedding cache".into(),
        });
    }

    if snapshot.average_confidence < 0.5 && snapshot.total_memories > 0 {
        recs.push(Recommendation {
            severity: Severity::Critical,
            message: format!(
                "average confidence is {:.2}, below 0.50 threshold",
                snapshot.average_confidence
            ),
            action: "run consolidation to improve memory quality".into(),
        });
    }

    // Temporal-specific recommendations (only when drift data is available).
    if let Some(ref drift) = snapshot.drift_summary {
        if drift.overall_ksi < 0.3 {
            recs.push(Recommendation {
                severity: Severity::Warning,
                message: format!(
                    "Knowledge Stability Index is {:.2}, below 0.30 threshold",
                    drift.overall_ksi
                ),
                action: "investigate knowledge churn".into(),
            });
        }

        if drift.overall_efi < 0.5 {
            recs.push(Recommendation {
                severity: Severity::Warning,
                message: format!(
                    "Evidence Freshness Index is {:.2}, below 0.50 threshold",
                    drift.overall_efi
                ),
                action: "review stale evidence".into(),
            });
        }

        if drift.active_alerts > 3 {
            recs.push(Recommendation {
                severity: Severity::Warning,
                message: format!(
                    "{} active drift alerts — temporal event store may need compaction",
                    drift.active_alerts
                ),
                action: "run snapshot compaction".into(),
            });
        }
    }

    recs
}

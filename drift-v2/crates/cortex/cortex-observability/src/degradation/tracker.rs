//! Record every degradation event: component, failure mode, fallback used, timestamp, recovery status.

use chrono::{DateTime, Utc};
use cortex_core::models::DegradationEvent;
use serde::{Deserialize, Serialize};

/// Recovery status of a degradation event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryStatus {
    /// Still in degraded mode.
    Active,
    /// Recovered to normal operation.
    Recovered,
}

/// A tracked degradation event with recovery status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedDegradation {
    pub event: DegradationEvent,
    pub recovery_status: RecoveryStatus,
    pub recovered_at: Option<DateTime<Utc>>,
}

/// Tracks all degradation events for alerting and reporting.
#[derive(Debug, Clone, Default)]
pub struct DegradationTracker {
    events: Vec<TrackedDegradation>,
}

impl DegradationTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new degradation event.
    pub fn record(&mut self, event: DegradationEvent) {
        crate::tracing_setup::events::degradation_triggered(
            &event.component,
            &event.failure,
            &event.fallback_used,
        );
        self.events.push(TrackedDegradation {
            event,
            recovery_status: RecoveryStatus::Active,
            recovered_at: None,
        });
    }

    /// Mark a component as recovered.
    pub fn mark_recovered(&mut self, component: &str) {
        let now = Utc::now();
        for tracked in self.events.iter_mut().rev() {
            if tracked.event.component == component
                && tracked.recovery_status == RecoveryStatus::Active
            {
                tracked.recovery_status = RecoveryStatus::Recovered;
                tracked.recovered_at = Some(now);
                break;
            }
        }
    }

    /// Get all events (for persistence to degradation_log table).
    pub fn events(&self) -> &[TrackedDegradation] {
        &self.events
    }

    /// Get active (unrecovered) degradations.
    pub fn active_degradations(&self) -> Vec<&TrackedDegradation> {
        self.events
            .iter()
            .filter(|t| t.recovery_status == RecoveryStatus::Active)
            .collect()
    }

    /// Count events in the last N seconds for a given component.
    pub fn count_recent(&self, component: &str, window_secs: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs);
        self.events
            .iter()
            .filter(|t| t.event.component == component && t.event.timestamp > cutoff)
            .count()
    }

    /// Count events in the last N seconds across all components.
    pub fn count_all_recent(&self, window_secs: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs);
        self.events
            .iter()
            .filter(|t| t.event.timestamp > cutoff)
            .count()
    }

    /// Duration a component has been continuously degraded, or None if not degraded.
    pub fn degraded_duration(&self, component: &str) -> Option<chrono::Duration> {
        // Find the earliest active degradation for this component.
        let earliest = self
            .events
            .iter()
            .filter(|t| {
                t.event.component == component && t.recovery_status == RecoveryStatus::Active
            })
            .map(|t| t.event.timestamp)
            .min()?;
        Some(Utc::now() - earliest)
    }
}

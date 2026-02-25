//! Alert thresholds: >3 degradations in 1 hour → warning, same component >24h → critical.

use serde::{Deserialize, Serialize};

use super::tracker::DegradationTracker;

/// Alert severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    None,
    Warning,
    Critical,
}

/// A degradation alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradationAlert {
    pub level: AlertLevel,
    pub component: String,
    pub message: String,
}

/// Evaluate alerts based on the current degradation tracker state.
pub fn evaluate_alerts(tracker: &DegradationTracker) -> Vec<DegradationAlert> {
    let mut alerts = Vec::new();
    let mut seen_components = std::collections::HashSet::new();

    for tracked in tracker.events() {
        let component = &tracked.event.component;
        if !seen_components.insert(component.clone()) {
            continue;
        }

        // Check: same component degraded > 24 hours → critical.
        if let Some(duration) = tracker.degraded_duration(component) {
            if duration > chrono::Duration::hours(24) {
                alerts.push(DegradationAlert {
                    level: AlertLevel::Critical,
                    component: component.clone(),
                    message: format!("{} has been degraded for over 24 hours", component),
                });
                continue;
            }
        }

        // Check: >3 degradations in 1 hour → warning.
        let recent_count = tracker.count_recent(component, 3600);
        if recent_count > 3 {
            alerts.push(DegradationAlert {
                level: AlertLevel::Warning,
                component: component.clone(),
                message: format!(
                    "{} has {} degradation events in the last hour",
                    component, recent_count
                ),
            });
        }
    }

    alerts
}

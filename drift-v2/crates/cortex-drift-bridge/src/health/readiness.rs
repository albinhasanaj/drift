//! Readiness probe: are all required subsystems initialized?

use super::checks::SubsystemCheck;
use super::status::BridgeHealth;

/// Tiered readiness state for the bridge.
#[derive(Debug, Clone)]
pub struct ReadinessState {
    /// Core bridge functional (bridge_store + drift_db)
    pub ready: bool,
    /// Cortex memory system available
    pub cortex_ready: bool,
    /// Some subsystems unhealthy but core works
    pub degraded: bool,
    /// Human-readable status message
    pub message: String,
}

/// Run all health checks and compute overall bridge health.
pub fn compute_health(checks: &[SubsystemCheck]) -> BridgeHealth {
    if checks.is_empty() {
        return BridgeHealth::Unavailable;
    }

    let unhealthy: Vec<String> = checks
        .iter()
        .filter(|c| !c.healthy)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();

    if unhealthy.is_empty() {
        BridgeHealth::Available
    } else if checks.iter().any(|c| c.healthy) {
        // At least one subsystem works — degraded, not unavailable
        BridgeHealth::Degraded(unhealthy)
    } else {
        BridgeHealth::Unavailable
    }
}

/// Check if the bridge is ready to serve requests.
/// Core bridge is ready if bridge_db or drift_db is available.
/// Cortex is optional — its absence does not block readiness.
pub fn is_ready(checks: &[SubsystemCheck]) -> bool {
    let state = evaluate_readiness(checks);
    state.ready
}

/// Evaluate tiered readiness across all subsystems.
pub fn evaluate_readiness(checks: &[SubsystemCheck]) -> ReadinessState {
    let core_healthy = checks
        .iter()
        .filter(|c| c.name == "bridge_db" || c.name == "drift_db")
        .all(|c| c.healthy);

    let cortex_healthy = checks
        .iter()
        .any(|c| c.name == "cortex_db" && c.healthy);

    let all_healthy = checks.iter().all(|c| c.healthy);

    ReadinessState {
        ready: core_healthy,
        cortex_ready: cortex_healthy,
        degraded: core_healthy && !all_healthy,
        message: if !core_healthy {
            "Core bridge subsystems unhealthy".to_string()
        } else if !cortex_healthy {
            "Bridge ready. Cortex not initialized — run `drift setup` or any `drift cortex` command.".to_string()
        } else if all_healthy {
            "All subsystems healthy".to_string()
        } else {
            "Bridge ready with degraded subsystems".to_string()
        },
    }
}

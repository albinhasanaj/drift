//! drift_health MCP tool: expose bridge health status.

use serde_json::json;

use crate::errors::BridgeResult;
use crate::traits::IBridgeStorage;
use crate::health;

/// Handle the drift_health MCP tool request.
///
/// Returns a JSON response with:
/// - status: "available", "degraded", or "unavailable"
/// - subsystem_checks: per-subsystem status
/// - degradations: list of degraded features (if any)
pub fn handle_drift_health(
    bridge_store: Option<&dyn IBridgeStorage>,
    drift_db: Option<&std::sync::Mutex<rusqlite::Connection>>,
    causal_engine: Option<&cortex_causal::CausalEngine>,
) -> BridgeResult<serde_json::Value> {
    let checks = vec![
        match bridge_store {
            Some(store) => match store.health_check() {
                Ok(status) => crate::health::checks::SubsystemCheck::ok("bridge_store", if status.connected { "connected" } else { "disconnected" }),
                Err(e) => crate::health::checks::SubsystemCheck::unhealthy("bridge_store", format!("health check failed: {}", e)),
            },
            None => crate::health::checks::SubsystemCheck::unhealthy("bridge_store", "not configured"),
        },
        health::checks::check_drift_db(drift_db),
        health::checks::check_causal_engine(causal_engine),
    ];

    let overall = health::compute_health(&checks);
    let ready = health::is_ready(&checks);

    let subsystem_json: Vec<serde_json::Value> = checks
        .iter()
        .map(|c| {
            json!({
                "name": c.name,
                "healthy": c.healthy,
                "detail": c.detail,
            })
        })
        .collect();

    let status_str = match &overall {
        health::BridgeHealth::Available => "available",
        health::BridgeHealth::Degraded(_) => "degraded",
        health::BridgeHealth::Unavailable => "unavailable",
    };

    Ok(json!({
        "status": status_str,
        "ready": ready,
        "subsystem_checks": subsystem_json,
        "degradation_reasons": overall.degradation_reasons(),
    }))
}

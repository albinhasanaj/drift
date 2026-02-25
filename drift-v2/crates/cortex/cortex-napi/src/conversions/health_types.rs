//! HealthReport, DegradationEvent ↔ serde_json::Value conversions.

use cortex_core::models::{DegradationEvent, HealthReport};

/// Serialize a HealthReport to JSON.
pub fn health_report_to_json(report: &HealthReport) -> napi::Result<serde_json::Value> {
    serde_json::to_value(report)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize HealthReport: {e}")))
}

/// Serialize a Vec<DegradationEvent> to JSON.
pub fn degradation_events_to_json(events: &[DegradationEvent]) -> napi::Result<serde_json::Value> {
    serde_json::to_value(events).map_err(|e| {
        napi::Error::from_reason(format!("Failed to serialize DegradationEvent vec: {e}"))
    })
}

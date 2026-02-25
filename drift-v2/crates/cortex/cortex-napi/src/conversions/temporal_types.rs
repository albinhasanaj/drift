//! Temporal type conversions: Rust ↔ serde_json::Value for NAPI interchange.
//!
//! All temporal types in cortex-core derive Serialize/Deserialize, so we
//! leverage serde_json for zero-boilerplate roundtrip conversion — same
//! pattern as memory_types.rs.

use cortex_core::models::{
    DecisionReplay, DiffStats, DriftAlert, DriftSnapshot, HindsightItem,
    MaterializedTemporalView, MemoryEvent, TemporalDiff,
};
use cortex_core::traits::TemporalTraversalResult;

// ─── MemoryEvent ─────────────────────────────────────────────────────────────

/// Serialize a MemoryEvent to JSON for JS consumption.
pub fn event_to_json(event: &MemoryEvent) -> napi::Result<serde_json::Value> {
    serde_json::to_value(event)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize MemoryEvent: {e}")))
}

/// Serialize a Vec<MemoryEvent> to JSON array.
pub fn events_to_json(events: &[MemoryEvent]) -> napi::Result<serde_json::Value> {
    serde_json::to_value(events)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize events: {e}")))
}

// ─── DriftSnapshot ───────────────────────────────────────────────────────────

/// Serialize a DriftSnapshot to JSON.
pub fn drift_snapshot_to_json(snapshot: &DriftSnapshot) -> napi::Result<serde_json::Value> {
    serde_json::to_value(snapshot)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize DriftSnapshot: {e}")))
}

/// Deserialize a DriftSnapshot from JSON.
pub fn drift_snapshot_from_json(value: serde_json::Value) -> napi::Result<DriftSnapshot> {
    serde_json::from_value(value)
        .map_err(|e| napi::Error::from_reason(format!("Failed to deserialize DriftSnapshot: {e}")))
}

// ─── DriftAlert ──────────────────────────────────────────────────────────────

/// Serialize a DriftAlert to JSON.
pub fn drift_alert_to_json(alert: &DriftAlert) -> napi::Result<serde_json::Value> {
    serde_json::to_value(alert)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize DriftAlert: {e}")))
}

/// Serialize a Vec<DriftAlert> to JSON array.
pub fn drift_alerts_to_json(alerts: &[DriftAlert]) -> napi::Result<serde_json::Value> {
    serde_json::to_value(alerts)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize DriftAlerts: {e}")))
}

// ─── TemporalDiff ────────────────────────────────────────────────────────────

/// Serialize a TemporalDiff to JSON.
pub fn temporal_diff_to_json(diff: &TemporalDiff) -> napi::Result<serde_json::Value> {
    serde_json::to_value(diff)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize TemporalDiff: {e}")))
}

/// Deserialize a TemporalDiff from JSON.
pub fn temporal_diff_from_json(value: serde_json::Value) -> napi::Result<TemporalDiff> {
    serde_json::from_value(value)
        .map_err(|e| napi::Error::from_reason(format!("Failed to deserialize TemporalDiff: {e}")))
}

// ─── DecisionReplay ──────────────────────────────────────────────────────────

/// Serialize a DecisionReplay to JSON.
pub fn decision_replay_to_json(replay: &DecisionReplay) -> napi::Result<serde_json::Value> {
    serde_json::to_value(replay)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize DecisionReplay: {e}")))
}

/// Deserialize a DecisionReplay from JSON.
pub fn decision_replay_from_json(value: serde_json::Value) -> napi::Result<DecisionReplay> {
    serde_json::from_value(value).map_err(|e| {
        napi::Error::from_reason(format!("Failed to deserialize DecisionReplay: {e}"))
    })
}

// ─── HindsightItem ───────────────────────────────────────────────────────────

/// Serialize a HindsightItem to JSON.
pub fn hindsight_item_to_json(item: &HindsightItem) -> napi::Result<serde_json::Value> {
    serde_json::to_value(item)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize HindsightItem: {e}")))
}

// ─── DiffStats ───────────────────────────────────────────────────────────────

/// Serialize DiffStats to JSON.
pub fn diff_stats_to_json(stats: &DiffStats) -> napi::Result<serde_json::Value> {
    serde_json::to_value(stats)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize DiffStats: {e}")))
}

// ─── MaterializedTemporalView ────────────────────────────────────────────────

/// Serialize a MaterializedTemporalView to JSON.
pub fn materialized_view_to_json(
    view: &MaterializedTemporalView,
) -> napi::Result<serde_json::Value> {
    serde_json::to_value(view).map_err(|e| {
        napi::Error::from_reason(format!("Failed to serialize MaterializedTemporalView: {e}"))
    })
}

/// Serialize a Vec<MaterializedTemporalView> to JSON array.
pub fn materialized_views_to_json(
    views: &[MaterializedTemporalView],
) -> napi::Result<serde_json::Value> {
    serde_json::to_value(views).map_err(|e| {
        napi::Error::from_reason(format!("Failed to serialize MaterializedTemporalViews: {e}"))
    })
}

// ─── TemporalTraversalResult ─────────────────────────────────────────────────

/// Serialize a TemporalTraversalResult to JSON.
pub fn traversal_result_to_json(
    result: &TemporalTraversalResult,
) -> napi::Result<serde_json::Value> {
    serde_json::to_value(result).map_err(|e| {
        napi::Error::from_reason(format!(
            "Failed to serialize TemporalTraversalResult: {e}"
        ))
    })
}

// ─── Roundtrip Validation ────────────────────────────────────────────────────

/// Validate that a DriftSnapshot can roundtrip through JSON.
pub fn validate_drift_snapshot_roundtrip(value: &serde_json::Value) -> napi::Result<()> {
    let snapshot: DriftSnapshot = serde_json::from_value(value.clone()).map_err(|e| {
        napi::Error::from_reason(format!("DriftSnapshot roundtrip failed (deserialize): {e}"))
    })?;
    let _back = serde_json::to_value(&snapshot).map_err(|e| {
        napi::Error::from_reason(format!("DriftSnapshot roundtrip failed (serialize): {e}"))
    })?;
    Ok(())
}

/// Validate that a TemporalDiff can roundtrip through JSON.
pub fn validate_temporal_diff_roundtrip(value: &serde_json::Value) -> napi::Result<()> {
    let diff: TemporalDiff = serde_json::from_value(value.clone()).map_err(|e| {
        napi::Error::from_reason(format!("TemporalDiff roundtrip failed (deserialize): {e}"))
    })?;
    let _back = serde_json::to_value(&diff).map_err(|e| {
        napi::Error::from_reason(format!("TemporalDiff roundtrip failed (serialize): {e}"))
    })?;
    Ok(())
}

/// Validate that a DecisionReplay can roundtrip through JSON.
pub fn validate_decision_replay_roundtrip(value: &serde_json::Value) -> napi::Result<()> {
    let replay: DecisionReplay = serde_json::from_value(value.clone()).map_err(|e| {
        napi::Error::from_reason(format!("DecisionReplay roundtrip failed (deserialize): {e}"))
    })?;
    let _back = serde_json::to_value(&replay).map_err(|e| {
        napi::Error::from_reason(format!("DecisionReplay roundtrip failed (serialize): {e}"))
    })?;
    Ok(())
}

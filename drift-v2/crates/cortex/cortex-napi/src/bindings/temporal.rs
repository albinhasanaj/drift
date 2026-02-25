//! Temporal bindings: 10 #[napi] functions for temporal queries, drift, and views.
//!
//! All time parameters are ISO 8601 strings parsed to DateTime<Utc>.
//! Follows the same pattern as other binding modules: parse inputs → call engine → convert → return.

use chrono::{DateTime, Utc};
use napi_derive::napi;

use cortex_core::models::{
    AsOfQuery, DecisionReplayQuery, DiffScope, MemoryFilter, TemporalCausalQuery,
    TemporalDiffQuery, TemporalRangeMode, TemporalRangeQuery, TraversalDirection,
};
use cortex_core::traits::ITemporalEngine;

use crate::conversions::{error_types, memory_types, temporal_types};
use crate::runtime;

/// B-06: Run an async future on the current tokio runtime instead of creating
/// a new Runtime per call. Falls back to creating one if no runtime is available.
fn temporal_block_on<F, T>(future: F) -> napi::Result<T>
where
    F: std::future::Future<Output = cortex_core::errors::CortexResult<T>>,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(future).map_err(error_types::to_napi_error),
        Err(_) => {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| napi::Error::from_reason(format!("Tokio runtime error: {e}")))?;
            rt.block_on(future).map_err(error_types::to_napi_error)
        }
    }
}

/// Parse an ISO 8601 string to DateTime<Utc>.
fn parse_time(s: &str) -> napi::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| napi::Error::from_reason(format!("Invalid ISO 8601 time '{s}': {e}")))
}

/// Parse a TemporalRangeMode from a string.
fn parse_range_mode(s: &str) -> napi::Result<TemporalRangeMode> {
    match s {
        "overlaps" => Ok(TemporalRangeMode::Overlaps),
        "contains" => Ok(TemporalRangeMode::Contains),
        "started_during" => Ok(TemporalRangeMode::StartedDuring),
        "ended_during" => Ok(TemporalRangeMode::EndedDuring),
        _ => Err(napi::Error::from_reason(format!(
            "Invalid range mode '{s}': expected overlaps|contains|started_during|ended_during"
        ))),
    }
}

/// Parse a TraversalDirection from a string.
fn parse_direction(s: &str) -> napi::Result<TraversalDirection> {
    match s {
        "forward" => Ok(TraversalDirection::Forward),
        "backward" => Ok(TraversalDirection::Backward),
        "both" => Ok(TraversalDirection::Both),
        _ => Err(napi::Error::from_reason(format!(
            "Invalid direction '{s}': expected forward|backward|both"
        ))),
    }
}

/// Parse a DiffScope from an optional string.
fn parse_scope(s: Option<String>) -> DiffScope {
    match s.as_deref() {
        Some("all") | None => DiffScope::All,
        Some(other) => {
            // Try to parse as namespace
            DiffScope::Namespace(other.to_string())
        }
    }
}

/// Parse an optional filter string (JSON) into a MemoryFilter.
fn parse_filter(filter: Option<String>) -> napi::Result<Option<MemoryFilter>> {
    match filter {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => {
            let f: MemoryFilter = serde_json::from_str(&s).map_err(|e| {
                napi::Error::from_reason(format!("Invalid filter JSON: {e}"))
            })?;
            Ok(Some(f))
        }
    }
}

// ─── Query Functions ─────────────────────────────────────────────────────────

/// Point-in-time knowledge query using bitemporal semantics.
#[napi]
pub fn cortex_temporal_query_as_of(
    system_time: String,
    valid_time: String,
    filter: Option<String>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let query = AsOfQuery {
        system_time: parse_time(&system_time)?,
        valid_time: parse_time(&valid_time)?,
        filter: parse_filter(filter)?,
    };
    let memories = temporal_block_on(rt.temporal.query_as_of(&query))?;
    memory_types::memories_to_json(&memories)
}

/// Range query for memories valid during a time range.
#[napi]
pub fn cortex_temporal_query_range(
    from: String,
    to: String,
    mode: String,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let query = TemporalRangeQuery {
        from: parse_time(&from)?,
        to: parse_time(&to)?,
        mode: parse_range_mode(&mode)?,
    };
    let memories = temporal_block_on(rt.temporal.query_range(&query))?;
    memory_types::memories_to_json(&memories)
}

/// Compare knowledge between two time points.
#[napi]
pub fn cortex_temporal_query_diff(
    time_a: String,
    time_b: String,
    scope: Option<String>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let query = TemporalDiffQuery {
        time_a: parse_time(&time_a)?,
        time_b: parse_time(&time_b)?,
        scope: parse_scope(scope),
    };
    let diff = temporal_block_on(rt.temporal.query_diff(&query))?;
    temporal_types::temporal_diff_to_json(&diff)
}

/// Replay a decision with historical context and hindsight.
#[napi]
pub fn cortex_temporal_replay_decision(
    decision_id: String,
    budget: Option<u32>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let query = DecisionReplayQuery {
        decision_memory_id: decision_id,
        budget_override: budget.map(|b| b as usize),
    };
    let replay = temporal_block_on(rt.temporal.replay_decision(&query))?;
    temporal_types::decision_replay_to_json(&replay)
}

/// Temporal causal graph traversal at a specific point in time.
#[napi]
pub fn cortex_temporal_query_temporal_causal(
    memory_id: String,
    as_of: String,
    direction: String,
    depth: u32,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let query = TemporalCausalQuery {
        memory_id,
        as_of: parse_time(&as_of)?,
        direction: parse_direction(&direction)?,
        max_depth: depth as usize,
    };
    let result = temporal_block_on(rt.temporal.query_temporal_causal(&query))?;
    temporal_types::traversal_result_to_json(&result)
}

// ─── Drift Functions ─────────────────────────────────────────────────────────

/// Get drift metrics for a time window.
#[napi]
pub fn cortex_temporal_get_drift_metrics(
    window_hours: Option<u32>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let hours = window_hours.unwrap_or(168) as u64; // default 1 week
    let snapshot = temporal_block_on(rt.temporal.compute_drift_metrics(hours))?;
    temporal_types::drift_snapshot_to_json(&snapshot)
}

/// Get active drift alerts.
#[napi]
pub fn cortex_temporal_get_drift_alerts() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let alerts = temporal_block_on(rt.temporal.get_drift_alerts())?;
    temporal_types::drift_alerts_to_json(&alerts)
}

// ─── View Functions ──────────────────────────────────────────────────────────

/// Create a materialized temporal view.
#[napi]
pub fn cortex_temporal_create_materialized_view(
    label: String,
    timestamp: String,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let ts = parse_time(&timestamp)?;
    let view = temporal_block_on(rt.temporal.create_view(&label, ts))?;
    temporal_types::materialized_view_to_json(&view)
}

/// Get a materialized view by label.
#[napi]
pub fn cortex_temporal_get_materialized_view(
    label: String,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let view = temporal_block_on(rt.temporal.get_view(&label))?;
    match view {
        Some(v) => temporal_types::materialized_view_to_json(&v),
        None => Ok(serde_json::Value::Null),
    }
}

/// List all materialized views.
#[napi]
pub fn cortex_temporal_list_materialized_views() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let views = cortex_temporal::views::query::list_views(&rt.temporal.readers)
        .map_err(error_types::to_napi_error)?;
    temporal_types::materialized_views_to_json(&views)
}

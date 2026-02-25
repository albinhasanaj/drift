//! Cloud bindings: sync, getStatus, resolveConflict.

use napi_derive::napi;
use serde_json::json;

use crate::conversions::error_types;
use crate::runtime;

/// Trigger a cloud sync cycle.
#[napi]
pub fn cortex_cloud_sync() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let cloud = rt
        .cloud
        .as_ref()
        .ok_or_else(|| napi::Error::from_reason("Cloud sync not enabled"))?;
    let mut engine = cloud
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Cloud lock poisoned: {e}")))?;
    let result = engine.sync(&[]).map_err(error_types::to_napi_error)?;
    Ok(json!({
        "status": format!("{:?}", result.status),
        "pushed": result.pushed,
        "pulled": result.pulled,
        "conflicts_resolved": result.conflicts_resolved,
        "manual_conflicts": result.manual_conflicts,
    }))
}

/// Get cloud sync status.
#[napi]
pub fn cortex_cloud_get_status() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let cloud = rt
        .cloud
        .as_ref()
        .ok_or_else(|| napi::Error::from_reason("Cloud sync not enabled"))?;
    let engine = cloud
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Cloud lock poisoned: {e}")))?;
    Ok(json!({
        "status": format!("{:?}", engine.status()),
        "is_online": engine.is_online(),
        "offline_queue_length": engine.offline_queue_len(),
    }))
}

/// Resolve a sync conflict manually.
#[napi]
pub fn cortex_cloud_resolve_conflict(
    memory_id: String,
    resolution: String,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let cloud = rt
        .cloud
        .as_ref()
        .ok_or_else(|| napi::Error::from_reason("Cloud sync not enabled"))?;
    let mut engine = cloud
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Cloud lock poisoned: {e}")))?;

    // Parse the resolution strategy from the input string.
    let strategy = match resolution.as_str() {
        "local_wins" => cortex_cloud::conflict::Strategy::LocalWins,
        "remote_wins" => cortex_cloud::conflict::Strategy::RemoteWins,
        "last_write_wins" => cortex_cloud::conflict::Strategy::LastWriteWins,
        "crdt_merge" => cortex_cloud::conflict::Strategy::CrdtMerge,
        "manual" => cortex_cloud::conflict::Strategy::Manual,
        other => {
            return Err(napi::Error::from_reason(format!(
                "Invalid resolution strategy '{other}'. Expected: local_wins, remote_wins, last_write_wins, crdt_merge, manual"
            )));
        }
    };

    // Apply the strategy to the conflict resolver.
    let resolver = engine.conflict_resolver();
    let old_strategy = resolver.strategy();
    resolver.set_strategy(strategy);

    Ok(json!({
        "memory_id": memory_id,
        "resolution": resolution,
        "previous_strategy": format!("{:?}", old_strategy),
        "applied": true,
    }))
}

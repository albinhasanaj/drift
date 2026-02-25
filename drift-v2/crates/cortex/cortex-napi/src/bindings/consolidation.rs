//! Consolidation bindings: consolidate, getMetrics, getStatus.

use napi_derive::napi;

use cortex_core::traits::IMemoryStorage;

use crate::conversions::error_types;
use crate::runtime;

/// Run memory consolidation on eligible candidates.
#[napi]
pub fn cortex_consolidation_consolidate(
    memory_type: Option<String>,
) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;

    // Gather candidates — either a specific type or all episodic memories.
    let candidates = match memory_type {
        Some(type_str) => {
            let mt = crate::conversions::memory_types::memory_type_from_string(&type_str)?;
            rt.storage
                .query_by_type(mt)
                .map_err(error_types::to_napi_error)?
        }
        None => rt
            .storage
            .query_by_type(cortex_core::MemoryType::Episodic)
            .map_err(error_types::to_napi_error)?,
    };

    let mut consolidation = rt
        .consolidation
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Consolidation lock poisoned: {e}")))?;
    let result = consolidation
        .consolidate_with_context(&candidates, &[])
        .map_err(error_types::to_napi_error)?;
    serde_json::to_value(&result).map_err(|e| {
        napi::Error::from_reason(format!("Failed to serialize ConsolidationResult: {e}"))
    })
}

/// Get consolidation quality metrics from the dashboard.
#[napi]
pub fn cortex_consolidation_get_metrics() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let consolidation = rt
        .consolidation
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Consolidation lock poisoned: {e}")))?;
    let dashboard = consolidation.dashboard();
    Ok(serde_json::json!({
        "total_runs": dashboard.total_runs,
        "successful_runs": dashboard.successful_runs,
        "success_rate": dashboard.success_rate,
        "is_running": consolidation.is_running(),
    }))
}

/// Get consolidation status (running or idle).
#[napi]
pub fn cortex_consolidation_get_status() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let consolidation = rt
        .consolidation
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Consolidation lock poisoned: {e}")))?;
    Ok(serde_json::json!({
        "is_running": consolidation.is_running(),
    }))
}

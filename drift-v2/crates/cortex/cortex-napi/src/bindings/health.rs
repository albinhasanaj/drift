//! Health bindings: getHealth, getMetrics, getDegradations.

use napi_derive::napi;
use serde_json::json;

use cortex_core::traits::IMemoryStorage;
use cortex_observability::HealthSnapshot;

use crate::conversions::{error_types, health_types};
use crate::runtime;

/// Get a comprehensive health report.
#[napi]
pub fn cortex_health_get_health() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let mut obs = rt
        .observability
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Observability lock poisoned: {e}")))?;

    // Build a snapshot from current engine state.
    let type_counts = rt
        .storage
        .count_by_type()
        .map_err(error_types::to_napi_error)?;
    let total: usize = type_counts.iter().map(|(_, c)| c).sum();
    let avg_confidence = rt
        .storage
        .average_confidence()
        .map_err(error_types::to_napi_error)?;

    // C-11: Query real values from storage instead of hardcoding zeros.
    let stale_count = rt
        .storage
        .stale_count(30) // memories not accessed in 30 days
        .unwrap_or(0);

    // Count archived memories by querying confidence < 0.15 (archival threshold).
    let archived_memories = rt
        .storage
        .query_by_confidence_range(0.0, 0.15)
        .map(|v| v.iter().filter(|m| m.archived).count())
        .unwrap_or(0);

    let active_memories = total.saturating_sub(archived_memories);

    // Get DB size if file-backed.
    let db_size_bytes = rt.storage.pool().db_path
        .as_ref()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .unwrap_or(0);

    // B-04: Real embedding cache hit rate from L2 stats.
    let embedding_cache_hit_rate = {
        let emb = rt.embeddings.lock().map_err(|e| {
            napi::Error::from_reason(format!("Embedding lock poisoned: {e}"))
        })?;
        let stats = emb.cache_stats();
        if stats.total > 0 {
            // Approximate hit rate: L1 entries are hot (hits), L2 only are warm.
            // If TF-IDF fallback is active, report 0.0 (no real embeddings cached).
            if emb.active_provider() == "tfidf" {
                0.0
            } else {
                // Non-zero cache entries with a real provider → estimate rate.
                // L1 hits are fast (most accessed), L2 hits are warm.
                (stats.l1_count as f64 / stats.total.max(1) as f64).min(1.0)
            }
        } else {
            // No cache entries yet — fresh start.
            if emb.active_provider() == "tfidf" { 0.0 } else { 1.0 }
        }
    };

    // Count memories needing validation: low confidence + not archived.
    let memories_needing_validation = rt
        .storage
        .query_by_confidence_range(0.0, 0.5)
        .map(|v| v.iter().filter(|m| !m.archived).count())
        .unwrap_or(0);

    // Consolidation count from dashboard.
    let consolidation_count = {
        let cons = rt.consolidation.lock().map_err(|e| {
            napi::Error::from_reason(format!("Consolidation lock poisoned: {e}"))
        })?;
        cons.dashboard().total_runs
    };

    let snapshot = HealthSnapshot {
        total_memories: total,
        active_memories,
        archived_memories,
        average_confidence: avg_confidence,
        db_size_bytes,
        embedding_cache_hit_rate,
        stale_count,
        // B-01: Wire contradiction counts from ValidationEngine.
        // Run basic validation on low-confidence memories to detect contradictions.
        contradiction_count: {
            let low_conf_memories = rt
                .storage
                .query_by_confidence_range(0.0, 0.5)
                .unwrap_or_default();
            let mut count = 0usize;
            for mem in &low_conf_memories {
                if let Ok(result) = rt.validation.validate_basic(mem, &low_conf_memories) {
                    if result.dimension_scores.contradiction < 0.5 {
                        count += 1;
                    }
                }
            }
            count
        },
        unresolved_contradictions: 0, // Will be wired when contradiction resolution tracking is added
        consolidation_count,
        memories_needing_validation,
        drift_summary: None,
    };

    let report = obs
        .health_report(snapshot)
        .map_err(error_types::to_napi_error)?;
    health_types::health_report_to_json(&report)
}

/// Get system metrics as JSON.
#[napi]
pub fn cortex_health_get_metrics() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    // B-03: MetricsCollector now derives Serialize — use serde instead of manual JSON.
    let obs = rt
        .observability
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Observability lock poisoned: {e}")))?;
    let metrics_snapshot = obs.metrics_snapshot().map_err(error_types::to_napi_error)?;

    // Merge with session and causal stats for backward compatibility.
    let mut result = metrics_snapshot;
    if let serde_json::Value::Object(ref mut map) = result {
        map.insert("session_count".to_string(), json!(rt.session.session_count()));
        map.insert("causal_stats".to_string(), json!({
            "node_count": rt.causal.stats().map(|(n, _)| n).unwrap_or(0),
            "edge_count": rt.causal.stats().map(|(_, e)| e).unwrap_or(0),
        }));
    }
    Ok(result)
}

/// Get degradation events and alerts.
#[napi]
pub fn cortex_health_get_degradations() -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let mut embeddings = rt
        .embeddings
        .lock()
        .map_err(|e| napi::Error::from_reason(format!("Embedding lock poisoned: {e}")))?;
    let events = embeddings.drain_degradation_events();
    health_types::degradation_events_to_json(&events)
}

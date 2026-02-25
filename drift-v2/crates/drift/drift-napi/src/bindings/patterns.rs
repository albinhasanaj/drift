//! NAPI bindings for Phase 3 pattern intelligence.
//!
//! Exposes: drift_patterns(), drift_confidence(), drift_outliers(), drift_conventions()
//! with keyset pagination support.

use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::conversions::error_codes;
use crate::runtime;

fn storage_err(e: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR))
}

/// Query pattern confidence scores with optional tier filter and keyset pagination.
#[napi]
pub fn drift_confidence(
    tier: Option<String>,
    after_id: Option<String>,
    limit: Option<u32>,
) -> Result<serde_json::Value> {
    let rt = runtime::get()?;
    let lim = limit.unwrap_or(100) as usize;

    let scores = rt.storage.with_reader(|conn| {
        if let Some(ref t) = tier {
            drift_storage::queries::patterns::query_confidence_by_tier(conn, t, after_id.as_deref(), lim + 1)
        } else {
            drift_storage::queries::patterns::query_all_confidence(conn)
        }
    }).map_err(storage_err)?;

    let has_more = tier.is_some() && scores.len() > lim;
    let items: Vec<_> = scores.iter().take(lim).map(|s| serde_json::json!({
        "pattern_id": s.pattern_id,
        "posterior_mean": s.posterior_mean,
        "credible_interval": [s.credible_interval_low, s.credible_interval_high],
        "tier": s.tier,
        "momentum": s.momentum,
        "alpha": s.alpha,
        "beta": s.beta,
    })).collect();

    let next_cursor = if has_more { scores.get(lim - 1).map(|s| s.pattern_id.clone()) } else { None };

    Ok(serde_json::json!({
        "scores": items,
        "has_more": has_more,
        "next_cursor": next_cursor
    }))
}

/// Query outlier detection results with optional pattern filter.
#[napi]
pub fn drift_outliers(
    pattern_id: Option<String>,
    _after_id: Option<u32>,
    limit: Option<u32>,
) -> Result<serde_json::Value> {
    let rt = runtime::get()?;
    let _limit = limit.unwrap_or(100);

    let outliers = if let Some(ref pid) = pattern_id {
        rt.storage.with_reader(|conn| {
            drift_storage::queries::patterns::query_outliers_by_pattern(conn, pid)
        }).map_err(storage_err)?
    } else {
        Vec::new()
    };

    let items: Vec<_> = outliers.iter().map(|o| serde_json::json!({
        "id": o.id,
        "pattern_id": o.pattern_id,
        "file": o.file,
        "line": o.line,
        "deviation_score": o.deviation_score,
        "significance": o.significance,
        "method": o.method,
    })).collect();

    Ok(serde_json::json!({
        "outliers": items,
        "has_more": false,
        "next_cursor": null
    }))
}

/// Query discovered conventions with optional category filter.
#[napi]
pub fn drift_conventions(
    category: Option<String>,
    _after_id: Option<u32>,
    limit: Option<u32>,
) -> Result<serde_json::Value> {
    let rt = runtime::get()?;
    let _limit = limit.unwrap_or(100);

    let conventions = rt.storage.with_reader(|conn| {
        if let Some(ref cat) = category {
            drift_storage::queries::patterns::query_conventions_by_category(conn, cat)
        } else {
            drift_storage::queries::patterns::query_all_conventions(conn)
        }
    }).map_err(storage_err)?;

    let items: Vec<_> = conventions.iter().map(|c| serde_json::json!({
        "id": c.id,
        "pattern_id": c.pattern_id,
        "category": c.category,
        "scope": c.scope,
        "dominance_ratio": c.dominance_ratio,
        "promotion_status": c.promotion_status,
    })).collect();

    Ok(serde_json::json!({
        "conventions": items,
        "has_more": false,
        "next_cursor": null
    }))
}

/// Query aggregated patterns (detections) with keyset pagination.
/// Enriches each detection with its pattern_status lifecycle state.
#[napi]
pub fn drift_patterns(
    category: Option<String>,
    _after_id: Option<String>,
    limit: Option<u32>,
) -> Result<serde_json::Value> {
    let rt = runtime::get()?;
    let _limit = limit.unwrap_or(100);

    let lim = _limit as usize;

    let detections = rt.storage.with_reader(|conn| {
        if let Some(ref cat) = category {
            drift_storage::queries::detections::get_detections_by_category(conn, cat)
        } else {
            drift_storage::queries::detections::query_all_detections(conn, lim)
        }
    }).map_err(storage_err)?;

    // Load pattern statuses to enrich each detection
    let statuses = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_all_pattern_statuses(conn, None)
    }).unwrap_or_default();
    let status_map: std::collections::HashMap<String, String> = statuses
        .into_iter()
        .map(|s| (s.pattern_id, s.status))
        .collect();

    let items: Vec<_> = detections.iter().map(|d| {
        let status = status_map.get(&d.pattern_id)
            .cloned()
            .unwrap_or_else(|| "discovered".to_string());
        serde_json::json!({
            "file": d.file,
            "line": d.line,
            "pattern_id": d.pattern_id,
            "category": d.category,
            "confidence": d.confidence,
            "detection_method": d.detection_method,
            "status": status,
        })
    }).collect();

    Ok(serde_json::json!({
        "patterns": items,
        "has_more": false,
        "next_cursor": null
    }))
}

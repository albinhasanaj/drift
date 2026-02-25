//! NAPI bindings for violation feedback functions (Phase 6).

#[allow(unused_imports)]
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::{Deserialize, Serialize};

use crate::conversions::error_codes;
use crate::runtime;

fn storage_err(e: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR))
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsFeedbackInput {
    pub violation_id: String,
    pub action: String,
    pub reason: Option<String>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsFeedbackResult {
    pub success: bool,
    pub message: String,
}

/// Dismiss a violation.
#[napi]
pub fn drift_dismiss_violation(input: JsFeedbackInput) -> napi::Result<JsFeedbackResult> {
    let rt = runtime::get()?;

    let pattern_id = resolve_pattern_id(&rt, &input.violation_id);

    let detector_id = resolve_detector_id(&rt, &input.violation_id);
    let created_at = unix_timestamp_now();

    let feedback = drift_storage::queries::enforcement::FeedbackRow {
        violation_id: input.violation_id.clone(),
        pattern_id,
        detector_id,
        action: "dismiss".to_string(),
        dismissal_reason: input.reason.clone(),
        reason: input.reason,
        author: None,
        created_at,
    };

    rt.storage.with_writer(|conn| {
        drift_storage::queries::enforcement::insert_feedback(conn, &feedback)
    }).map_err(storage_err)?;

    Ok(JsFeedbackResult {
        success: true,
        message: format!("Violation {} dismissed", input.violation_id),
    })
}

/// Mark a violation as fixed.
#[napi]
pub fn drift_fix_violation(violation_id: String) -> napi::Result<JsFeedbackResult> {
    let rt = runtime::get()?;

    let pattern_id = resolve_pattern_id(&rt, &violation_id);

    let detector_id = resolve_detector_id(&rt, &violation_id);
    let created_at = unix_timestamp_now();

    let feedback = drift_storage::queries::enforcement::FeedbackRow {
        violation_id: violation_id.clone(),
        pattern_id,
        detector_id,
        action: "fix".to_string(),
        dismissal_reason: None,
        reason: None,
        author: None,
        created_at,
    };

    rt.storage.with_writer(|conn| {
        drift_storage::queries::enforcement::insert_feedback(conn, &feedback)
    }).map_err(storage_err)?;

    Ok(JsFeedbackResult {
        success: true,
        message: format!("Violation {violation_id} marked as fixed"),
    })
}

/// Suppress a violation via drift-ignore.
#[napi]
pub fn drift_suppress_violation(
    violation_id: String,
    reason: String,
) -> napi::Result<JsFeedbackResult> {
    let rt = runtime::get()?;

    let pattern_id = resolve_pattern_id(&rt, &violation_id);

    let detector_id = resolve_detector_id(&rt, &violation_id);
    let created_at = unix_timestamp_now();

    let feedback = drift_storage::queries::enforcement::FeedbackRow {
        violation_id: violation_id.clone(),
        pattern_id,
        detector_id,
        action: "suppress".to_string(),
        dismissal_reason: Some(reason.clone()),
        reason: Some(reason.clone()),
        author: None,
        created_at,
    };

    rt.storage.with_writer(|conn| {
        drift_storage::queries::enforcement::insert_feedback(conn, &feedback)
    }).map_err(storage_err)?;

    Ok(JsFeedbackResult {
        success: true,
        message: format!("Violation {violation_id} suppressed: {reason}"),
    })
}

/// Resolve pattern_id from the violations table for a given violation_id.
/// Returns empty string if the violation is not found (graceful degradation).
fn resolve_pattern_id(rt: &crate::runtime::DriftRuntime, violation_id: &str) -> String {
    rt.storage
        .with_reader(|conn| {
            drift_storage::queries::enforcement::get_violation_pattern_id(conn, violation_id)
        })
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Resolve detector_id (rule_id) from the violations table for a given violation_id.
fn resolve_detector_id(rt: &crate::runtime::DriftRuntime, violation_id: &str) -> String {
    rt.storage
        .with_reader(|conn| {
            let result = conn
                .prepare_cached("SELECT rule_id FROM violations WHERE id = ?1")
                .and_then(|mut stmt| {
                    stmt.query_row([violation_id], |row| row.get::<_, String>(0))
                });
            match result {
                Ok(val) => Ok(Some(val)),
                Err(_) => Ok(None),
            }
        })
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Get current Unix timestamp in seconds.
fn unix_timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

//! Session bindings: create, get, cleanup, analytics.

use napi_derive::napi;

use crate::runtime;

/// Create a new session.
#[napi]
pub fn cortex_session_create(session_id: Option<String>) -> napi::Result<String> {
    let rt = runtime::get()?;
    let id = session_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    Ok(rt.session.create_session(id))
}

/// Get a session by ID.
#[napi]
pub fn cortex_session_get(session_id: String) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let ctx = rt
        .session
        .get_session(&session_id)
        .ok_or_else(|| napi::Error::from_reason(format!("Session not found: {session_id}")))?;
    serde_json::to_value(&ctx)
        .map_err(|e| napi::Error::from_reason(format!("Failed to serialize SessionContext: {e}")))
}

/// Clean up stale sessions.
#[napi]
pub fn cortex_session_cleanup() -> napi::Result<i64> {
    let rt = runtime::get()?;
    let removed = cortex_session::cleanup_old_sessions(&rt.session);
    Ok(removed as i64)
}

/// Get analytics for a session.
#[napi]
pub fn cortex_session_analytics(session_id: String) -> napi::Result<serde_json::Value> {
    let rt = runtime::get()?;
    let ctx = rt
        .session
        .get_session(&session_id)
        .ok_or_else(|| napi::Error::from_reason(format!("Session not found: {session_id}")))?;
    // SessionContext doesn't have a separate analytics field;
    // we derive analytics from the context itself.
    Ok(serde_json::json!({
        "session_id": ctx.session_id,
        "created_at": ctx.created_at.to_rfc3339(),
        "last_activity": ctx.last_activity.to_rfc3339(),
        "loaded_memories_count": ctx.loaded_memories.len(),
        "loaded_patterns_count": ctx.loaded_patterns.len(),
        "loaded_files_count": ctx.loaded_files.len(),
        "tokens_sent": ctx.tokens_sent,
        "queries_made": ctx.queries_made,
    }))
}

//! Structured log events for key system operations.
//!
//! Each function emits a `tracing` event with structured fields.

/// Log a memory creation event.
pub fn memory_created(memory_id: &str, memory_type: &str) {
    tracing::info!(
        event = "memory_created",
        memory_id = %memory_id,
        memory_type = %memory_type,
        "memory created"
    );
}

/// Log a memory archival event.
pub fn memory_archived(memory_id: &str, reason: &str) {
    tracing::info!(
        event = "memory_archived",
        memory_id = %memory_id,
        reason = %reason,
        "memory archived"
    );
}

/// Log a consolidation completion event.
pub fn consolidation_completed(created: usize, archived: usize, precision: f64) {
    tracing::info!(
        event = "consolidation_completed",
        created = created,
        archived = archived,
        precision = precision,
        "consolidation completed"
    );
}

/// Log a contradiction detection event.
pub fn contradiction_detected(memory_ids: &[String], contradiction_type: &str) {
    tracing::warn!(
        event = "contradiction_detected",
        memory_ids = ?memory_ids,
        contradiction_type = %contradiction_type,
        "contradiction detected"
    );
}

/// Log a degradation trigger event.
pub fn degradation_triggered(component: &str, failure: &str, fallback: &str) {
    tracing::warn!(
        event = "degradation_triggered",
        component = %component,
        failure = %failure,
        fallback = %fallback,
        "degradation triggered"
    );
}

/// Log embedding migration progress.
pub fn migration_progress(completed: u64, total: u64, provider: &str) {
    tracing::info!(
        event = "migration_progress",
        completed = completed,
        total = total,
        provider = %provider,
        "embedding migration progress"
    );
}

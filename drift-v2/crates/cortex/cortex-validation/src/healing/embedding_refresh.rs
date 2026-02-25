//! Re-embed memories whose context has changed.

/// A request to re-embed a memory.
#[derive(Debug, Clone)]
pub struct RefreshRequest {
    pub memory_id: String,
    pub reason: String,
}

/// Collect memories that need re-embedding based on validation results.
///
/// This doesn't perform the actual embedding — it produces a list of
/// requests that the caller (engine) passes to the embedding system.
pub fn collect_refresh_requests(
    memory_id: &str,
    citation_changed: bool,
    content_hash_drifted: bool,
) -> Option<RefreshRequest> {
    if citation_changed || content_hash_drifted {
        Some(RefreshRequest {
            memory_id: memory_id.to_string(),
            reason: if content_hash_drifted {
                "Content hash drift detected — linked file content changed".into()
            } else {
                "Citation updated — context may have changed".into()
            },
        })
    } else {
        None
    }
}

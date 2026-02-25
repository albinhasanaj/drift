//! Pull remote changes to local.
//!
//! Fetches changes since the last sync timestamp, applies them to the
//! local store, and detects conflicts.

use cortex_core::errors::CortexResult;

use crate::transport::protocol::{MemoryPayload, PullResponse};
use crate::transport::HttpClient;

/// Pull remote changes from the cloud.
///
/// Returns the pulled payloads and the new sync token.
pub fn pull_changes(client: &HttpClient, sync_token: Option<&str>) -> CortexResult<PullResult> {
    let path = match sync_token {
        Some(token) => format!("/api/v1/sync/pull?since={token}"),
        None => "/api/v1/sync/pull".to_string(),
    };

    match client.get::<PullResponse>(&path) {
        Ok(response) => {
            if let Some(data) = response.data {
                Ok(PullResult {
                    changes: data.changes,
                    has_more: data.has_more,
                    sync_token: Some(data.sync_token),
                })
            } else {
                Ok(PullResult::default())
            }
        }
        Err(e) => {
            tracing::warn!("cloud: pull failed: {e}");
            Err(e)
        }
    }
}

/// Result of a pull operation.
#[derive(Debug, Default)]
pub struct PullResult {
    /// Memories that changed on the remote.
    pub changes: Vec<MemoryPayload>,
    /// Whether there are more changes to pull.
    pub has_more: bool,
    /// New sync token after this pull.
    pub sync_token: Option<String>,
}

impl PullResult {
    /// Whether any changes were pulled.
    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Number of changes pulled.
    pub fn change_count(&self) -> usize {
        self.changes.len()
    }
}

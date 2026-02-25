//! Push local changes to the cloud.
//!
//! Reads the sync log for unpushed mutations, batches them, uploads
//! with retry + backoff, and marks them as synced.

use cortex_core::errors::CortexResult;

use crate::transport::protocol::{MemoryPayload, PushResponse, SyncBatch};
use crate::transport::HttpClient;

use super::sync_log::{SyncDirection, SyncLog};

/// Push pending local mutations to the cloud.
///
/// Returns the number of memories successfully pushed.
pub fn push_pending(
    client: &HttpClient,
    sync_log: &mut SyncLog,
    pending_payloads: &[MemoryPayload],
    batch_size: usize,
) -> CortexResult<PushResult> {
    let pending = sync_log.pending(SyncDirection::Push);
    if pending.is_empty() && pending_payloads.is_empty() {
        return Ok(PushResult::default());
    }

    let mut result = PushResult::default();

    // Batch the payloads.
    for chunk in pending_payloads.chunks(batch_size.max(1)) {
        let batch = SyncBatch {
            upserts: chunk.to_vec(),
            deletes: vec![],
            sync_token: None,
        };

        match client.post::<SyncBatch, PushResponse>("/api/v1/sync/push", &batch) {
            Ok(response) => {
                if let Some(data) = response.data {
                    result.accepted += data.accepted;
                    result.conflicts.extend(data.conflicts.clone());
                    result.sync_token = Some(data.sync_token);

                    // Mark successfully pushed entries.
                    for mem in chunk {
                        if !data.conflicts.contains(&mem.id) {
                            sync_log.mark_completed(&mem.id, SyncDirection::Push);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("cloud: push batch failed: {e}");
                result.failed += chunk.len();
                for mem in chunk {
                    sync_log.mark_failed(&mem.id, SyncDirection::Push);
                }
            }
        }
    }

    Ok(result)
}

/// Result of a push operation.
#[derive(Debug, Default)]
pub struct PushResult {
    /// Number of memories accepted by the cloud.
    pub accepted: usize,
    /// Number of memories that failed to push.
    pub failed: usize,
    /// Memory IDs that conflicted.
    pub conflicts: Vec<String>,
    /// New sync token after push.
    pub sync_token: Option<String>,
}

impl PushResult {
    /// Whether the push was fully successful (no failures or conflicts).
    pub fn is_clean(&self) -> bool {
        self.failed == 0 && self.conflicts.is_empty()
    }
}

//! Conflict detection: identifies when the same memory was modified on both
//! local and remote sides since the last sync.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::transport::protocol::MemoryPayload;

/// A detected conflict between local and remote versions of a memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedConflict {
    /// The memory ID in conflict.
    pub memory_id: String,
    /// Local content hash.
    pub local_hash: String,
    /// Remote content hash.
    pub remote_hash: String,
    /// When the local version was last modified.
    pub local_modified: DateTime<Utc>,
    /// When the remote version was last modified.
    pub remote_modified: DateTime<Utc>,
    /// Full local payload.
    pub local_payload: MemoryPayload,
    /// Full remote payload.
    pub remote_payload: MemoryPayload,
}

/// Detect conflicts between local and remote memory sets.
///
/// A conflict exists when both sides have the same memory ID but different
/// content hashes — meaning both were modified since the last sync.
pub fn detect_conflicts(
    local: &[MemoryPayload],
    remote: &[MemoryPayload],
) -> Vec<DetectedConflict> {
    let mut conflicts = Vec::new();

    // Build a lookup of remote memories by ID.
    let remote_map: std::collections::HashMap<&str, &MemoryPayload> =
        remote.iter().map(|m| (m.id.as_str(), m)).collect();

    for local_mem in local {
        if let Some(remote_mem) = remote_map.get(local_mem.id.as_str()) {
            if local_mem.content_hash != remote_mem.content_hash {
                conflicts.push(DetectedConflict {
                    memory_id: local_mem.id.clone(),
                    local_hash: local_mem.content_hash.clone(),
                    remote_hash: remote_mem.content_hash.clone(),
                    local_modified: local_mem.modified_at,
                    remote_modified: remote_mem.modified_at,
                    local_payload: local_mem.clone(),
                    remote_payload: (*remote_mem).clone(),
                });
            }
        }
    }

    conflicts
}

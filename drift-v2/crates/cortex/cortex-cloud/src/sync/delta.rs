//! Delta computation — determines what changed between local and remote
//! using content hash comparison.

use std::collections::HashMap;

use crate::transport::protocol::MemoryPayload;

/// The result of computing a delta between local and remote states.
#[derive(Debug, Default)]
pub struct SyncDelta {
    /// Memories that exist locally but not remotely (need push).
    pub local_only: Vec<MemoryPayload>,
    /// Memories that exist remotely but not locally (need pull).
    pub remote_only: Vec<MemoryPayload>,
    /// Memories that exist on both sides with different hashes (conflicts).
    pub diverged: Vec<(MemoryPayload, MemoryPayload)>,
    /// Memories that are identical on both sides (no action needed).
    pub in_sync: usize,
}

/// Compute the delta between local and remote memory sets.
///
/// Uses content hashes for efficient comparison — no need to diff
/// the full memory content.
pub fn compute_delta(local: &[MemoryPayload], remote: &[MemoryPayload]) -> SyncDelta {
    let local_map: HashMap<&str, &MemoryPayload> =
        local.iter().map(|m| (m.id.as_str(), m)).collect();
    let remote_map: HashMap<&str, &MemoryPayload> =
        remote.iter().map(|m| (m.id.as_str(), m)).collect();

    let mut delta = SyncDelta::default();

    // Check local memories against remote.
    for (id, local_mem) in &local_map {
        match remote_map.get(id) {
            Some(remote_mem) => {
                if local_mem.content_hash == remote_mem.content_hash {
                    delta.in_sync += 1;
                } else {
                    delta
                        .diverged
                        .push(((*local_mem).clone(), (*remote_mem).clone()));
                }
            }
            None => {
                delta.local_only.push((*local_mem).clone());
            }
        }
    }

    // Find remote-only memories.
    for (id, remote_mem) in &remote_map {
        if !local_map.contains_key(id) {
            delta.remote_only.push((*remote_mem).clone());
        }
    }

    delta
}

impl SyncDelta {
    /// Whether there are any changes to sync.
    pub fn has_changes(&self) -> bool {
        !self.local_only.is_empty() || !self.remote_only.is_empty() || !self.diverged.is_empty()
    }

    /// Total number of changes detected.
    pub fn change_count(&self) -> usize {
        self.local_only.len() + self.remote_only.len() + self.diverged.len()
    }
}

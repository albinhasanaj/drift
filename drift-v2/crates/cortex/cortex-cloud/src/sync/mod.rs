//! Bidirectional sync: push local changes, pull remote changes, delta computation.

pub mod delta;
pub mod pull;
pub mod push;
pub mod sync_log;

use chrono::{DateTime, Utc};
use cortex_core::errors::CortexResult;

use crate::conflict::ConflictResolver;
use crate::transport::protocol::MemoryPayload;
use crate::transport::HttpClient;

use delta::compute_delta;
use pull::pull_changes;
use push::push_pending;
use sync_log::SyncLog;

pub use delta::SyncDelta;
pub use pull::PullResult;
pub use push::PushResult;
pub use sync_log::{SyncDirection, SyncLogEntry, SyncStatus};

/// Orchestrates bidirectional sync.
#[derive(Debug)]
pub struct SyncManager {
    pub log: SyncLog,
    last_sync_token: Option<String>,
    last_sync_at: Option<DateTime<Utc>>,
    batch_size: usize,
}

impl SyncManager {
    pub fn new(batch_size: usize) -> Self {
        Self {
            log: SyncLog::new(),
            last_sync_token: None,
            last_sync_at: None,
            batch_size,
        }
    }

    /// Perform a full sync cycle: push then pull.
    pub fn sync(
        &mut self,
        client: &HttpClient,
        local_changes: &[MemoryPayload],
        conflict_resolver: &mut ConflictResolver,
    ) -> CortexResult<SyncReport> {
        let mut report = SyncReport::default();

        // 1. Push local changes.
        let push_result = push_pending(client, &mut self.log, local_changes, self.batch_size)?;
        report.pushed = push_result.accepted;
        report.push_conflicts = push_result.conflicts.clone();
        if let Some(token) = push_result.sync_token {
            self.last_sync_token = Some(token);
        }

        // 2. Pull remote changes.
        let pull_result = pull_changes(client, self.last_sync_token.as_deref())?;
        report.pulled = pull_result.change_count();
        if let Some(token) = pull_result.sync_token {
            self.last_sync_token = Some(token);
        }

        // 3. Detect and resolve conflicts between local and pulled.
        if !pull_result.changes.is_empty() {
            let delta = compute_delta(local_changes, &pull_result.changes);
            for (local, remote) in &delta.diverged {
                let conflict = crate::conflict::detection::DetectedConflict {
                    memory_id: local.id.clone(),
                    local_hash: local.content_hash.clone(),
                    remote_hash: remote.content_hash.clone(),
                    local_modified: local.modified_at,
                    remote_modified: remote.modified_at,
                    local_payload: local.clone(),
                    remote_payload: remote.clone(),
                };
                let outcome = conflict_resolver.resolve(&conflict);
                report.conflicts_resolved += 1;
                if outcome.needs_manual_resolution {
                    report.manual_conflicts += 1;
                }
            }
        }

        self.last_sync_at = Some(Utc::now());
        report.sync_token = self.last_sync_token.clone();
        Ok(report)
    }

    /// Last sync timestamp.
    pub fn last_sync_at(&self) -> Option<DateTime<Utc>> {
        self.last_sync_at
    }

    /// Current sync token.
    pub fn sync_token(&self) -> Option<&str> {
        self.last_sync_token.as_deref()
    }
}

impl Default for SyncManager {
    fn default() -> Self {
        Self::new(100)
    }
}

/// Summary of a sync cycle.
#[derive(Debug, Default)]
pub struct SyncReport {
    /// Number of memories pushed.
    pub pushed: usize,
    /// Number of memories pulled.
    pub pulled: usize,
    /// Memory IDs that conflicted during push.
    pub push_conflicts: Vec<String>,
    /// Number of conflicts resolved.
    pub conflicts_resolved: usize,
    /// Number of conflicts requiring manual resolution.
    pub manual_conflicts: usize,
    /// New sync token.
    pub sync_token: Option<String>,
}

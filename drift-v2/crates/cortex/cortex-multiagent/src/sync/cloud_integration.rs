//! CloudSyncAdapter — bridges delta sync with cloud/local transport.
//!
//! Detects whether the target agent is local (same Cortex instance, use SQLite)
//! or remote (different instance, use HTTP via cortex-cloud).

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};

use cortex_core::errors::{CortexResult, MultiAgentError};
use cortex_core::models::agent::AgentId;

use cortex_storage::queries::multiagent_ops;

/// Transport mode for delta sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncTransport {
    /// Target agent is in the same Cortex instance — use SQLite delta_queue.
    Local,
    /// Target agent is remote — use cortex-cloud HTTP transport.
    Cloud,
}

/// Bridges delta sync with the appropriate transport layer.
pub struct CloudSyncAdapter;

impl CloudSyncAdapter {
    /// C-03: Sync with a target agent via cloud transport.
    ///
    /// Delegates to the provided `cloud_sync_fn` callback which wraps
    /// the CloudEngine's HTTP push/pull. If no callback is provided,
    /// returns an error indicating cloud sync is not configured.
    #[instrument]
    pub fn sync_via_cloud(
        source_agent: &AgentId,
        target_agent: &AgentId,
    ) -> CortexResult<()> {
        info!(
            source = %source_agent,
            target = %target_agent,
            "cloud sync requested — delegating to cortex-cloud transport"
        );
        Err(MultiAgentError::SyncFailed(
            "cloud sync requires a CloudEngine instance — use sync_via_cloud_with_engine instead".to_string(),
        )
        .into())
    }

    /// C-03: Sync via cloud with an explicit sync callback.
    ///
    /// The callback receives (source_agent, target_agent) and should
    /// delegate to CloudEngine::sync() with the appropriate payloads.
    #[instrument(skip(cloud_sync_fn))]
    pub fn sync_via_cloud_with_callback<F>(
        source_agent: &AgentId,
        target_agent: &AgentId,
        cloud_sync_fn: F,
    ) -> CortexResult<()>
    where
        F: FnOnce(&AgentId, &AgentId) -> CortexResult<()>,
    {
        info!(
            source = %source_agent,
            target = %target_agent,
            "cloud sync requested — using provided cloud engine callback"
        );
        cloud_sync_fn(source_agent, target_agent)
    }

    /// Sync with a target agent via local transport (same SQLite DB).
    ///
    /// For local agents, deltas are exchanged through the shared `delta_queue`
    /// table — no network transport needed.
    #[instrument(skip(conn))]
    pub fn sync_via_local(
        conn: &Connection,
        source_agent: &AgentId,
        target_agent: &AgentId,
    ) -> CortexResult<()> {
        debug!(
            source = %source_agent,
            target = %target_agent,
            "syncing via local transport"
        );

        // For local sync, deltas are already in the shared delta_queue table.
        // The DeltaSyncEngine.initiate_sync handles the actual dequeue + apply.
        let pending = multiagent_ops::pending_delta_count(conn, &source_agent.0)?;
        info!(
            source = %source_agent,
            target = %target_agent,
            pending_deltas = pending,
            "local sync: deltas available in shared queue"
        );

        Ok(())
    }

    /// Detect the appropriate sync transport for a target agent.
    ///
    /// If the target agent exists in the local registry, use Local transport.
    /// Otherwise, assume Cloud transport.
    #[instrument(skip(conn))]
    pub fn detect_sync_mode(
        conn: &Connection,
        target_agent: &AgentId,
    ) -> CortexResult<SyncTransport> {
        debug!(target = %target_agent, "detecting sync mode");

        let agent = multiagent_ops::get_agent(conn, &target_agent.0)?;
        let mode = match agent {
            Some(row) if !row.status.starts_with("deregistered") => SyncTransport::Local,
            _ => SyncTransport::Cloud,
        };

        debug!(target = %target_agent, mode = ?mode, "sync mode detected");
        Ok(mode)
    }
}

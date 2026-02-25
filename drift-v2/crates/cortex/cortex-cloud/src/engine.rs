//! CloudEngine — sync orchestrator, auth state, scheduling, conflict resolution,
//! offline detection.

use cortex_core::errors::{CloudError, CortexResult};

use crate::auth::login_flow::AuthMethod;
use crate::auth::offline_mode::{MutationOp, QueuedMutation};
use crate::auth::AuthManager;
use crate::conflict::ConflictResolver;
use crate::quota::{QuotaLimits, QuotaManager, QuotaUsage};
use crate::sync::SyncManager;
use crate::transport::protocol::MemoryPayload;
use crate::transport::{HttpClient, HttpClientConfig};

/// Status of the cloud engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudStatus {
    /// Not initialized or not authenticated.
    Disconnected,
    /// Authenticated and ready to sync.
    Connected,
    /// Currently syncing.
    Syncing,
    /// Operating in offline mode.
    Offline,
    /// An error occurred.
    Error,
}

/// The main cloud engine. Orchestrates auth, sync, conflict resolution,
/// quota enforcement, and offline mode.
#[derive(Debug)]
pub struct CloudEngine {
    auth: AuthManager,
    sync: SyncManager,
    conflicts: ConflictResolver,
    quota: QuotaManager,
    client: HttpClient,
    status: CloudStatus,
}

impl CloudEngine {
    /// Create a new cloud engine.
    pub fn new(
        auth_method: AuthMethod,
        client_config: HttpClientConfig,
        quota_limits: QuotaLimits,
    ) -> Self {
        Self {
            auth: AuthManager::new(auth_method),
            sync: SyncManager::default(),
            conflicts: ConflictResolver::default(),
            quota: QuotaManager::new(quota_limits),
            client: HttpClient::new(client_config),
            status: CloudStatus::Disconnected,
        }
    }

    /// Connect to the cloud (authenticate).
    pub fn connect(&mut self) -> CortexResult<()> {
        self.auth.login()?;
        if let Some(token) = self.auth.bearer_token() {
            self.client.set_bearer_token(token.to_string());
        }
        self.status = CloudStatus::Connected;
        tracing::info!("cloud: connected");
        Ok(())
    }

    /// Disconnect and clear auth state.
    pub fn disconnect(&mut self) {
        self.auth.logout();
        self.client.clear_bearer_token();
        self.status = CloudStatus::Disconnected;
        tracing::info!("cloud: disconnected");
    }

    /// Perform a full sync cycle.
    ///
    /// 1. Check quota
    /// 2. Ensure valid auth token
    /// 3. Replay any offline-queued mutations
    /// 4. Push + pull with conflict resolution
    pub fn sync(&mut self, local_changes: &[MemoryPayload]) -> CortexResult<SyncResult> {
        // Check quota before syncing.
        self.quota.enforce()?;

        // Check sync frequency.
        if !self.quota.check_sync_frequency() {
            return Ok(SyncResult {
                status: SyncResultStatus::Throttled,
                ..Default::default()
            });
        }

        // Ensure we have a valid token.
        match self.auth.ensure_valid_token() {
            Ok(()) => {
                if let Some(token) = self.auth.bearer_token() {
                    self.client.set_bearer_token(token.to_string());
                }
            }
            Err(e) => {
                tracing::warn!("cloud: auth refresh failed, going offline: {e}");
                self.go_offline();
                return Ok(SyncResult {
                    status: SyncResultStatus::Offline,
                    ..Default::default()
                });
            }
        }

        self.status = CloudStatus::Syncing;

        // Replay any queued offline mutations first.
        let mut all_changes: Vec<MemoryPayload> = Vec::new();
        if self.auth.offline.has_pending() {
            let queued = self.auth.offline.drain_queue();
            tracing::info!("cloud: replaying {} offline mutations", queued.len());
            for q in &queued {
                if let Some(ref payload) = q.payload {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(payload) {
                        all_changes.push(MemoryPayload {
                            id: q.memory_id.clone(),
                            content_hash: String::new(),
                            data,
                            modified_at: q.timestamp,
                        });
                    }
                }
            }
        }
        all_changes.extend_from_slice(local_changes);

        // Perform the sync.
        match self
            .sync
            .sync(&self.client, &all_changes, &mut self.conflicts)
        {
            Ok(report) => {
                self.status = CloudStatus::Connected;
                // C-10: Record that sync completed so the frequency throttle resets.
                self.quota.record_sync_completed();
                Ok(SyncResult {
                    status: SyncResultStatus::Success,
                    pushed: report.pushed,
                    pulled: report.pulled,
                    conflicts_resolved: report.conflicts_resolved,
                    manual_conflicts: report.manual_conflicts,
                })
            }
            Err(e) => {
                tracing::warn!("cloud: sync failed: {e}");
                // If it's a network error, go offline.
                if matches!(
                    e,
                    cortex_core::errors::CortexError::CloudSyncError(
                        CloudError::NetworkError { .. }
                    )
                ) {
                    self.go_offline();
                    // Queue the local changes for later.
                    for mem in local_changes {
                        self.queue_mutation(
                            &mem.id,
                            MutationOp::Update,
                            Some(mem.data.to_string()),
                        );
                    }
                    Ok(SyncResult {
                        status: SyncResultStatus::Offline,
                        ..Default::default()
                    })
                } else {
                    self.status = CloudStatus::Error;
                    Err(e)
                }
            }
        }
    }

    /// Queue a mutation for later sync (when offline).
    pub fn queue_mutation(&mut self, memory_id: &str, op: MutationOp, payload: Option<String>) {
        self.auth.offline.enqueue(QueuedMutation {
            memory_id: memory_id.to_string(),
            operation: op,
            timestamp: chrono::Utc::now(),
            payload,
        });
    }

    /// Transition to offline mode.
    fn go_offline(&mut self) {
        self.auth.offline.go_offline();
        self.status = CloudStatus::Offline;
    }

    /// Update quota usage.
    pub fn update_quota_usage(&mut self, usage: QuotaUsage) {
        self.quota.update_usage(usage);
    }

    /// Current engine status.
    pub fn status(&self) -> CloudStatus {
        self.status
    }

    /// Whether we're currently online.
    pub fn is_online(&self) -> bool {
        self.auth.offline.is_online()
    }

    /// Number of queued offline mutations.
    pub fn offline_queue_len(&self) -> usize {
        self.auth.offline.queue_len()
    }

    /// Get the conflict resolver for manual resolution.
    pub fn conflict_resolver(&mut self) -> &mut ConflictResolver {
        &mut self.conflicts
    }

    /// Get the quota manager.
    pub fn quota(&self) -> &QuotaManager {
        &self.quota
    }
}

/// Status of a sync operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncResultStatus {
    #[default]
    Success,
    Offline,
    Throttled,
}

/// Result of a sync operation.
#[derive(Debug, Default)]
pub struct SyncResult {
    pub status: SyncResultStatus,
    pub pushed: usize,
    pub pulled: usize,
    pub conflicts_resolved: usize,
    pub manual_conflicts: usize,
}

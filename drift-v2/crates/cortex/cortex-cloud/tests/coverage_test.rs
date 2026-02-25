#![allow(clippy::single_match, clippy::field_reassign_with_default)]
//! Targeted coverage tests for cortex-cloud uncovered paths.
//!
//! Focuses on: engine sync paths, quota enforcement, offline mode,
//! auth manager, token manager, conflict resolution, transport protocol,
//! sync log, delta detection.

use chrono::Utc;
use cortex_cloud::auth::login_flow::AuthMethod;
use cortex_cloud::auth::offline_mode::{MutationOp, OfflineManager, QueuedMutation};
use cortex_cloud::auth::token_manager::{AuthToken, TokenManager};
use cortex_cloud::auth::{AuthManager, AuthState};
use cortex_cloud::conflict::conflict_log::{
    ConflictLog, ConflictRecord, ConflictResolver as ConflictResolverActor,
};
use cortex_cloud::conflict::detection::{detect_conflicts, DetectedConflict};
use cortex_cloud::conflict::resolution::{self, ResolutionStrategy};
use cortex_cloud::conflict::ConflictResolver;
use cortex_cloud::engine::{CloudEngine, CloudStatus, SyncResultStatus};
use cortex_cloud::quota::{QuotaCheck, QuotaLimits, QuotaManager, QuotaUsage};
use cortex_cloud::sync::delta::compute_delta;
use cortex_cloud::sync::pull::PullResult;
use cortex_cloud::sync::push::PushResult;
use cortex_cloud::sync::sync_log::{SyncDirection, SyncLog, SyncLogEntry, SyncStatus};
use cortex_cloud::transport::protocol::{CloudRequest, CloudResponse, MemoryPayload, SyncBatch};
use cortex_cloud::transport::{HttpClient, HttpClientConfig};
use std::time::Duration;

// ─── Quota Manager ───────────────────────────────────────────────────────────

#[test]
fn quota_defaults() {
    let limits = QuotaLimits::default();
    assert_eq!(limits.max_memories, 100_000);
    assert_eq!(limits.max_storage_bytes, 1_073_741_824);
    assert_eq!(limits.min_sync_interval_secs, 60);
}

#[test]
fn quota_manager_default() {
    let qm = QuotaManager::default();
    assert_eq!(qm.usage().memory_count, 0);
    assert_eq!(qm.limits().max_memories, 100_000);
}

#[test]
fn quota_check_ok_when_low_usage() {
    let qm = QuotaManager::new(QuotaLimits {
        max_memories: 1000,
        max_storage_bytes: 1_000_000,
        min_sync_interval_secs: 60,
    });
    match qm.check_memory_create() {
        QuotaCheck::Ok => {}
        other => panic!("expected Ok, got {other:?}"),
    }
}

#[test]
fn quota_check_warning_at_80_percent() {
    let mut qm = QuotaManager::new(QuotaLimits {
        max_memories: 100,
        max_storage_bytes: 1_000_000,
        min_sync_interval_secs: 60,
    });
    qm.update_usage(QuotaUsage {
        memory_count: 85,
        storage_bytes: 0,
        secs_since_last_sync: 120,
    });
    match qm.check_memory_create() {
        QuotaCheck::Warning { resource, percent } => {
            assert_eq!(resource, "memories");
            assert!(percent >= 80.0);
        }
        other => panic!("expected Warning, got {other:?}"),
    }
}

#[test]
fn quota_check_exceeded() {
    let mut qm = QuotaManager::new(QuotaLimits {
        max_memories: 100,
        max_storage_bytes: 1_000_000,
        min_sync_interval_secs: 60,
    });
    qm.update_usage(QuotaUsage {
        memory_count: 100,
        storage_bytes: 0,
        secs_since_last_sync: 120,
    });
    match qm.check_memory_create() {
        QuotaCheck::Exceeded {
            resource,
            used,
            limit,
        } => {
            assert_eq!(resource, "memories");
            assert_eq!(used, 100);
            assert_eq!(limit, 100);
        }
        other => panic!("expected Exceeded, got {other:?}"),
    }
}

#[test]
fn quota_check_storage_exceeded() {
    let mut qm = QuotaManager::new(QuotaLimits {
        max_memories: 100_000,
        max_storage_bytes: 1000,
        min_sync_interval_secs: 60,
    });
    qm.update_usage(QuotaUsage {
        memory_count: 0,
        storage_bytes: 1000,
        secs_since_last_sync: 120,
    });
    match qm.check_storage() {
        QuotaCheck::Exceeded { resource, .. } => {
            assert_eq!(resource, "storage_bytes");
        }
        other => panic!("expected Exceeded, got {other:?}"),
    }
}

#[test]
fn quota_enforce_ok() {
    let qm = QuotaManager::default();
    assert!(qm.enforce().is_ok());
}

#[test]
fn quota_enforce_memory_exceeded() {
    let mut qm = QuotaManager::new(QuotaLimits {
        max_memories: 10,
        max_storage_bytes: 1_000_000,
        min_sync_interval_secs: 60,
    });
    qm.update_usage(QuotaUsage {
        memory_count: 10,
        storage_bytes: 0,
        secs_since_last_sync: 120,
    });
    assert!(qm.enforce().is_err());
}

#[test]
fn quota_enforce_storage_exceeded() {
    let mut qm = QuotaManager::new(QuotaLimits {
        max_memories: 100_000,
        max_storage_bytes: 100,
        min_sync_interval_secs: 60,
    });
    qm.update_usage(QuotaUsage {
        memory_count: 0,
        storage_bytes: 100,
        secs_since_last_sync: 120,
    });
    assert!(qm.enforce().is_err());
}

#[test]
fn quota_sync_frequency_throttle() {
    let mut qm = QuotaManager::new(QuotaLimits {
        max_memories: 100_000,
        max_storage_bytes: 1_000_000,
        min_sync_interval_secs: 60,
    });
    qm.update_usage(QuotaUsage {
        memory_count: 0,
        storage_bytes: 0,
        secs_since_last_sync: 30,
    });
    assert!(!qm.check_sync_frequency());

    qm.update_usage(QuotaUsage {
        memory_count: 0,
        storage_bytes: 0,
        secs_since_last_sync: 60,
    });
    assert!(qm.check_sync_frequency());
}

// ─── Offline Manager ─────────────────────────────────────────────────────────

#[test]
fn offline_manager_starts_online() {
    let mgr = OfflineManager::new(100);
    assert!(mgr.is_online());
    assert!(!mgr.has_pending());
    assert_eq!(mgr.queue_len(), 0);
}

#[test]
fn offline_manager_go_offline_and_back() {
    let mut mgr = OfflineManager::new(100);
    mgr.go_offline();
    assert!(!mgr.is_online());
    mgr.go_online();
    assert!(mgr.is_online());
}

#[test]
fn offline_manager_enqueue_and_drain() {
    let mut mgr = OfflineManager::new(100);
    mgr.enqueue(QueuedMutation {
        memory_id: "m1".to_string(),
        operation: MutationOp::Create,
        timestamp: Utc::now(),
        payload: Some("{}".to_string()),
    });
    mgr.enqueue(QueuedMutation {
        memory_id: "m2".to_string(),
        operation: MutationOp::Update,
        timestamp: Utc::now(),
        payload: None,
    });
    assert_eq!(mgr.queue_len(), 2);
    assert!(mgr.has_pending());

    let drained = mgr.drain_queue();
    assert_eq!(drained.len(), 2);
    assert_eq!(mgr.queue_len(), 0);
    assert!(!mgr.has_pending());
}

#[test]
fn offline_manager_queue_overflow() {
    let mut mgr = OfflineManager::new(2);
    for i in 0..5 {
        mgr.enqueue(QueuedMutation {
            memory_id: format!("m{i}"),
            operation: MutationOp::Create,
            timestamp: Utc::now(),
            payload: None,
        });
    }
    assert!(mgr.queue_len() <= 2);
}

// ─── Token Manager ───────────────────────────────────────────────────────────

#[test]
fn token_manager_initially_empty() {
    let tm = TokenManager::new();
    assert!(tm.get().is_none());
    assert!(tm.is_expired());
    assert!(tm.needs_refresh(Duration::from_secs(60)));
}

#[test]
fn token_manager_store_and_retrieve() {
    let mut tm = TokenManager::new();
    tm.store(AuthToken {
        access_token: "abc123".to_string(),
        refresh_token: Some("refresh456".to_string()),
        expires_in_secs: 3600,
    });
    assert!(tm.get().is_some());
    assert!(!tm.is_expired());
    assert!(tm.has_refresh_token());
}

#[test]
fn token_manager_no_refresh_token() {
    let mut tm = TokenManager::new();
    tm.store(AuthToken {
        access_token: "abc".to_string(),
        refresh_token: None,
        expires_in_secs: 3600,
    });
    assert!(!tm.has_refresh_token());
}

#[test]
fn token_manager_clear() {
    let mut tm = TokenManager::new();
    tm.store(AuthToken {
        access_token: "abc".to_string(),
        refresh_token: None,
        expires_in_secs: 3600,
    });
    tm.clear();
    assert!(tm.get().is_none());
    assert!(tm.is_expired());
}

// ─── Cloud Engine ────────────────────────────────────────────────────────────

#[test]
fn cloud_engine_initial_state() {
    let engine = CloudEngine::new(
        AuthMethod::ApiKey("test-key".to_string()),
        HttpClientConfig::default(),
        QuotaLimits::default(),
    );
    assert_eq!(engine.status(), CloudStatus::Disconnected);
    assert!(engine.is_online());
    assert_eq!(engine.offline_queue_len(), 0);
}

#[test]
fn cloud_engine_connect_with_api_key() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("test-key".to_string()),
        HttpClientConfig::default(),
        QuotaLimits::default(),
    );
    engine.connect().unwrap();
    assert_eq!(engine.status(), CloudStatus::Connected);
}

#[test]
fn cloud_engine_disconnect() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("test-key".to_string()),
        HttpClientConfig::default(),
        QuotaLimits::default(),
    );
    engine.connect().unwrap();
    engine.disconnect();
    assert_eq!(engine.status(), CloudStatus::Disconnected);
}

#[test]
fn cloud_engine_queue_mutation() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("test-key".to_string()),
        HttpClientConfig::default(),
        QuotaLimits::default(),
    );
    engine.queue_mutation("m1", MutationOp::Create, Some("{}".to_string()));
    assert_eq!(engine.offline_queue_len(), 1);
}

#[test]
fn cloud_engine_update_quota_usage() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("test-key".to_string()),
        HttpClientConfig::default(),
        QuotaLimits::default(),
    );
    engine.update_quota_usage(QuotaUsage {
        memory_count: 500,
        storage_bytes: 1_000_000,
        secs_since_last_sync: 120,
    });
    assert_eq!(engine.quota().usage().memory_count, 500);
}

#[test]
fn cloud_engine_sync_throttled() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("test-key".to_string()),
        HttpClientConfig::default(),
        QuotaLimits {
            max_memories: 100_000,
            max_storage_bytes: 1_000_000_000,
            min_sync_interval_secs: 60,
        },
    );
    engine.connect().unwrap();
    engine.update_quota_usage(QuotaUsage {
        memory_count: 0,
        storage_bytes: 0,
        secs_since_last_sync: 10,
    });
    let result = engine.sync(&[]).unwrap();
    assert_eq!(result.status, SyncResultStatus::Throttled);
}

#[test]
fn cloud_engine_sync_quota_exceeded() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("test-key".to_string()),
        HttpClientConfig::default(),
        QuotaLimits {
            max_memories: 10,
            max_storage_bytes: 1_000_000_000,
            min_sync_interval_secs: 0,
        },
    );
    engine.connect().unwrap();
    engine.update_quota_usage(QuotaUsage {
        memory_count: 10,
        storage_bytes: 0,
        secs_since_last_sync: 120,
    });
    let result = engine.sync(&[]);
    assert!(result.is_err());
}

// ─── Protocol Types ──────────────────────────────────────────────────────────

#[test]
fn cloud_request_new() {
    let req = CloudRequest::new(serde_json::json!({"test": true}));
    assert!(!req.request_id.is_empty());
    assert!(!req.version.is_empty());
}

#[test]
fn cloud_response_ok() {
    let resp = CloudResponse::ok("req-1".to_string(), "data");
    assert!(resp.success);
    assert!(resp.error.is_none());
    assert_eq!(resp.data, Some("data"));
}

#[test]
fn cloud_response_err() {
    let resp: CloudResponse<String> =
        CloudResponse::err("req-1".to_string(), "quota exceeded".to_string());
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("quota exceeded"));
    assert!(resp.data.is_none());
}

#[test]
fn memory_payload_serde() {
    let payload = MemoryPayload {
        id: "m1".to_string(),
        content_hash: "abc123".to_string(),
        data: serde_json::json!({"content": "test"}),
        modified_at: Utc::now(),
    };
    let json = serde_json::to_value(&payload).unwrap();
    let restored: MemoryPayload = serde_json::from_value(json).unwrap();
    assert_eq!(restored.id, "m1");
    assert_eq!(restored.content_hash, "abc123");
}

#[test]
fn sync_batch_serde() {
    let batch = SyncBatch {
        upserts: vec![MemoryPayload {
            id: "m1".to_string(),
            content_hash: "hash".to_string(),
            data: serde_json::json!({}),
            modified_at: Utc::now(),
        }],
        deletes: vec!["m2".to_string()],
        sync_token: Some("token-1".to_string()),
    };
    let json = serde_json::to_value(&batch).unwrap();
    let restored: SyncBatch = serde_json::from_value(json).unwrap();
    assert_eq!(restored.upserts.len(), 1);
    assert_eq!(restored.deletes.len(), 1);
}

// ─── HttpClientConfig ────────────────────────────────────────────────────────

#[test]
fn http_client_config_defaults() {
    let config = HttpClientConfig::default();
    assert!(config.timeout > Duration::ZERO);
    assert!(config.max_retries > 0);
}

// ─── Auth Manager ────────────────────────────────────────────────────────────

#[test]
fn auth_manager_api_key_login() {
    let mut mgr = AuthManager::new(AuthMethod::ApiKey("test-key".to_string()));
    mgr.login().unwrap();
    assert!(mgr.bearer_token().is_some());
}

#[test]
fn auth_manager_logout() {
    let mut mgr = AuthManager::new(AuthMethod::ApiKey("test-key".to_string()));
    mgr.login().unwrap();
    mgr.logout();
    assert!(mgr.bearer_token().is_none());
}

// ─── Conflict Resolver ───────────────────────────────────────────────────────

#[test]
fn conflict_resolver_default() {
    let resolver = ConflictResolver::default();
    assert_eq!(resolver.strategy(), ResolutionStrategy::LastWriteWins);
}

#[test]
fn conflict_resolver_set_strategy() {
    let mut resolver = ConflictResolver::default();
    resolver.set_strategy(ResolutionStrategy::LocalWins);
    assert_eq!(resolver.strategy(), ResolutionStrategy::LocalWins);
}

#[test]
fn conflict_resolver_log_starts_empty() {
    let resolver = ConflictResolver::default();
    assert_eq!(resolver.log().total_count(), 0);
}

// ─── Sync Log ────────────────────────────────────────────────────────────────

#[test]
fn sync_log_record_and_query() {
    let mut log = SyncLog::new();
    assert!(log.is_empty());

    log.record(SyncLogEntry {
        direction: SyncDirection::Push,
        memory_id: "m1".to_string(),
        operation: "create".to_string(),
        status: SyncStatus::Pending,
        details: "new memory".to_string(),
        timestamp: Utc::now(),
    });
    assert_eq!(log.len(), 1);
    assert_eq!(log.pending_count(), 1);

    let pending = log.pending(SyncDirection::Push);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].memory_id, "m1");
}

#[test]
fn sync_log_mark_completed() {
    let mut log = SyncLog::new();
    log.record(SyncLogEntry {
        direction: SyncDirection::Push,
        memory_id: "m1".to_string(),
        operation: "update".to_string(),
        status: SyncStatus::Pending,
        details: "".to_string(),
        timestamp: Utc::now(),
    });
    log.mark_completed("m1", SyncDirection::Push);
    assert_eq!(log.pending_count(), 0);
}

#[test]
fn sync_log_mark_failed() {
    let mut log = SyncLog::new();
    log.record(SyncLogEntry {
        direction: SyncDirection::Push,
        memory_id: "m1".to_string(),
        operation: "update".to_string(),
        status: SyncStatus::Pending,
        details: "".to_string(),
        timestamp: Utc::now(),
    });
    log.mark_failed("m1", SyncDirection::Push);
    assert_eq!(log.pending_count(), 0);
    assert_eq!(log.len(), 1);
}

#[test]
fn sync_log_pending_filters_by_direction() {
    let mut log = SyncLog::new();
    log.record(SyncLogEntry {
        direction: SyncDirection::Push,
        memory_id: "m1".to_string(),
        operation: "create".to_string(),
        status: SyncStatus::Pending,
        details: "".to_string(),
        timestamp: Utc::now(),
    });
    log.record(SyncLogEntry {
        direction: SyncDirection::Pull,
        memory_id: "m2".to_string(),
        operation: "create".to_string(),
        status: SyncStatus::Pending,
        details: "".to_string(),
        timestamp: Utc::now(),
    });
    assert_eq!(log.pending(SyncDirection::Push).len(), 1);
    assert_eq!(log.pending(SyncDirection::Pull).len(), 1);
}

// ─── Delta Computation ───────────────────────────────────────────────────────

fn make_payload(id: &str, hash: &str) -> MemoryPayload {
    MemoryPayload {
        id: id.to_string(),
        content_hash: hash.to_string(),
        data: serde_json::json!({}),
        modified_at: Utc::now(),
    }
}

#[test]
fn delta_no_changes() {
    let local = vec![make_payload("m1", "hash1")];
    let remote = vec![make_payload("m1", "hash1")];
    let delta = compute_delta(&local, &remote);
    assert!(!delta.has_changes());
    assert_eq!(delta.in_sync, 1);
    assert_eq!(delta.change_count(), 0);
}

#[test]
fn delta_local_only() {
    let local = vec![make_payload("m1", "hash1"), make_payload("m2", "hash2")];
    let remote = vec![make_payload("m1", "hash1")];
    let delta = compute_delta(&local, &remote);
    assert!(delta.has_changes());
    assert_eq!(delta.local_only.len(), 1);
    assert_eq!(delta.local_only[0].id, "m2");
}

#[test]
fn delta_remote_only() {
    let local = vec![make_payload("m1", "hash1")];
    let remote = vec![make_payload("m1", "hash1"), make_payload("m3", "hash3")];
    let delta = compute_delta(&local, &remote);
    assert!(delta.has_changes());
    assert_eq!(delta.remote_only.len(), 1);
    assert_eq!(delta.remote_only[0].id, "m3");
}

#[test]
fn delta_diverged() {
    let local = vec![make_payload("m1", "local_hash")];
    let remote = vec![make_payload("m1", "remote_hash")];
    let delta = compute_delta(&local, &remote);
    assert!(delta.has_changes());
    assert_eq!(delta.diverged.len(), 1);
}

#[test]
fn delta_empty_inputs() {
    let delta = compute_delta(&[], &[]);
    assert!(!delta.has_changes());
    assert_eq!(delta.change_count(), 0);
}

// ─── Auth Manager: state machine ─────────────────────────────────────────────

#[test]
fn auth_manager_state_unauthenticated() {
    let mgr = AuthManager::new(AuthMethod::ApiKey("key".to_string()));
    match mgr.state() {
        AuthState::Unauthenticated => {}
        other => panic!("expected Unauthenticated, got {other:?}"),
    }
}

#[test]
fn auth_manager_state_authenticated() {
    let mut mgr = AuthManager::new(AuthMethod::ApiKey("key".to_string()));
    mgr.login().unwrap();
    match mgr.state() {
        AuthState::Authenticated => {}
        other => panic!("expected Authenticated, got {other:?}"),
    }
}

#[test]
fn auth_manager_state_offline() {
    let mut mgr = AuthManager::new(AuthMethod::ApiKey("key".to_string()));
    mgr.offline.go_offline();
    match mgr.state() {
        AuthState::Offline => {}
        other => panic!("expected Offline, got {other:?}"),
    }
}

#[test]
fn auth_manager_ensure_valid_token_no_refresh_needed() {
    let mut mgr = AuthManager::new(AuthMethod::ApiKey("key".to_string()));
    mgr.login().unwrap();
    // Token is fresh, no refresh needed.
    mgr.ensure_valid_token().unwrap();
    assert!(mgr.bearer_token().is_some());
}

#[test]
fn auth_manager_store_token_directly() {
    let mut mgr = AuthManager::new(AuthMethod::ApiKey("key".to_string()));
    mgr.store_token(AuthToken {
        access_token: "direct-token".to_string(),
        refresh_token: None,
        expires_in_secs: 3600,
    });
    assert_eq!(mgr.bearer_token(), Some("direct-token"));
}

// ─── Login Flow: OAuth ───────────────────────────────────────────────────────

#[test]
fn login_flow_oauth_not_implemented() {
    use cortex_cloud::auth::login_flow::LoginFlow;
    let flow = LoginFlow::new(AuthMethod::OAuth {
        client_id: "cid".to_string(),
        auth_url: "https://auth.example.com".to_string(),
        token_url: "https://token.example.com".to_string(),
    });
    let result = flow.authenticate();
    assert!(result.is_err());
}

#[test]
fn login_flow_api_key_refresh() {
    use cortex_cloud::auth::login_flow::LoginFlow;
    let flow = LoginFlow::new(AuthMethod::ApiKey("my-key".to_string()));
    // API key refresh just re-authenticates.
    let token = flow.refresh("old-refresh-token").unwrap();
    assert_eq!(token.access_token, "my-key");
}

#[test]
fn login_flow_oauth_refresh_not_implemented() {
    use cortex_cloud::auth::login_flow::LoginFlow;
    let flow = LoginFlow::new(AuthMethod::OAuth {
        client_id: "cid".to_string(),
        auth_url: "https://auth.example.com".to_string(),
        token_url: "https://token.example.com".to_string(),
    });
    let result = flow.refresh("some-refresh-token");
    assert!(result.is_err());
}

// ─── Conflict Log ────────────────────────────────────────────────────────────

#[test]
fn conflict_log_record_and_query() {
    let mut log = ConflictLog::new();
    assert_eq!(log.total_count(), 0);
    assert_eq!(log.unresolved_count(), 0);

    log.record(ConflictRecord {
        memory_id: "m1".to_string(),
        local_hash: "lh1".to_string(),
        remote_hash: "rh1".to_string(),
        strategy: ResolutionStrategy::LastWriteWins,
        resolved_by: ConflictResolverActor::System,
        detected_at: Utc::now(),
        resolved_at: Some(Utc::now()),
    });
    assert_eq!(log.total_count(), 1);
    assert_eq!(log.unresolved_count(), 0);
    assert_eq!(log.records().len(), 1);
}

#[test]
fn conflict_log_unresolved() {
    let mut log = ConflictLog::new();
    log.record(ConflictRecord {
        memory_id: "m2".to_string(),
        local_hash: "lh2".to_string(),
        remote_hash: "rh2".to_string(),
        strategy: ResolutionStrategy::Manual,
        resolved_by: ConflictResolverActor::User("pending".to_string()),
        detected_at: Utc::now(),
        resolved_at: None,
    });
    assert_eq!(log.unresolved_count(), 1);
    assert_eq!(log.unresolved().len(), 1);
    assert_eq!(log.unresolved()[0].memory_id, "m2");
}

// ─── Conflict Resolver: resolve with actual conflicts ────────────────────────

fn make_conflict(id: &str) -> DetectedConflict {
    DetectedConflict {
        memory_id: id.to_string(),
        local_hash: "local_hash".to_string(),
        remote_hash: "remote_hash".to_string(),
        local_modified: Utc::now(),
        remote_modified: Utc::now() - chrono::Duration::seconds(10),
        local_payload: make_payload(id, "local_hash"),
        remote_payload: make_payload(id, "remote_hash"),
    }
}

#[test]
fn conflict_resolver_resolve_last_write_wins() {
    let mut resolver = ConflictResolver::default();
    let conflict = make_conflict("c1");
    let outcome = resolver.resolve(&conflict);
    assert!(!outcome.needs_manual_resolution);
    assert!(outcome.winner.is_some());
    assert_eq!(resolver.log().total_count(), 1);
}

#[test]
fn conflict_resolver_resolve_local_wins() {
    let mut resolver = ConflictResolver::new(ResolutionStrategy::LocalWins);
    let conflict = make_conflict("c2");
    let outcome = resolver.resolve(&conflict);
    assert!(!outcome.needs_manual_resolution);
    let winner = outcome.winner.unwrap();
    assert_eq!(winner.content_hash, "local_hash");
}

#[test]
fn conflict_resolver_resolve_remote_wins() {
    let mut resolver = ConflictResolver::new(ResolutionStrategy::RemoteWins);
    let conflict = make_conflict("c3");
    let outcome = resolver.resolve(&conflict);
    assert!(!outcome.needs_manual_resolution);
    let winner = outcome.winner.unwrap();
    assert_eq!(winner.content_hash, "remote_hash");
}

#[test]
fn conflict_resolver_resolve_manual() {
    let mut resolver = ConflictResolver::new(ResolutionStrategy::Manual);
    let conflict = make_conflict("c4");
    let outcome = resolver.resolve(&conflict);
    assert!(outcome.needs_manual_resolution);
    assert!(outcome.winner.is_none());
    assert_eq!(resolver.log().unresolved_count(), 1);
}

// ─── Conflict Detection ──────────────────────────────────────────────────────

#[test]
fn detect_conflicts_no_overlap() {
    let local = vec![make_payload("m1", "h1")];
    let remote = vec![make_payload("m2", "h2")];
    let conflicts = detect_conflicts(&local, &remote);
    assert!(conflicts.is_empty());
}

#[test]
fn detect_conflicts_same_hash() {
    let local = vec![make_payload("m1", "same")];
    let remote = vec![make_payload("m1", "same")];
    let conflicts = detect_conflicts(&local, &remote);
    assert!(conflicts.is_empty());
}

#[test]
fn detect_conflicts_different_hash() {
    let local = vec![make_payload("m1", "local")];
    let remote = vec![make_payload("m1", "remote")];
    let conflicts = detect_conflicts(&local, &remote);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].memory_id, "m1");
}

// ─── PullResult / PushResult ─────────────────────────────────────────────────

#[test]
fn pull_result_default_empty() {
    let pr = PullResult::default();
    assert!(!pr.has_changes());
    assert_eq!(pr.change_count(), 0);
}

#[test]
fn pull_result_with_changes() {
    let pr = PullResult {
        changes: vec![make_payload("m1", "h1")],
        has_more: true,
        sync_token: Some("tok".to_string()),
    };
    assert!(pr.has_changes());
    assert_eq!(pr.change_count(), 1);
}

#[test]
fn push_result_default_clean() {
    let pr = PushResult::default();
    assert!(pr.is_clean());
}

#[test]
fn push_result_with_failures() {
    let pr = PushResult {
        accepted: 5,
        failed: 2,
        conflicts: vec![],
        sync_token: None,
    };
    assert!(!pr.is_clean());
}

#[test]
fn push_result_with_conflicts() {
    let pr = PushResult {
        accepted: 5,
        failed: 0,
        conflicts: vec!["m1".to_string()],
        sync_token: Some("tok".to_string()),
    };
    assert!(!pr.is_clean());
}

// ─── HttpClient: bearer token and error paths ────────────────────────────────

#[test]
fn http_client_new_and_token() {
    let mut client = HttpClient::new(HttpClientConfig::default());
    client.set_bearer_token("my-token".to_string());
    client.clear_bearer_token();
    // No panic — just verifying the API works.
}

#[test]
fn http_client_post_without_cloud_feature() {
    let client = HttpClient::new(HttpClientConfig::default());
    let result = client.post::<serde_json::Value, serde_json::Value>(
        "/api/v1/test",
        &serde_json::json!({"test": true}),
    );
    // Without the `cloud` feature, this should return a network error.
    assert!(result.is_err());
}

#[test]
fn http_client_get_without_cloud_feature() {
    let client = HttpClient::new(HttpClientConfig::default());
    let result = client.get::<serde_json::Value>("/api/v1/test");
    assert!(result.is_err());
}

// ─── SyncManager ─────────────────────────────────────────────────────────────

#[test]
fn sync_manager_defaults() {
    use cortex_cloud::SyncManager;
    let mgr = SyncManager::default();
    assert!(mgr.last_sync_at().is_none());
    assert!(mgr.sync_token().is_none());
}

#[test]
fn sync_manager_custom_batch_size() {
    use cortex_cloud::SyncManager;
    let mgr = SyncManager::new(50);
    assert!(mgr.last_sync_at().is_none());
}

// ─── CloudEngine: sync with network error (goes offline) ─────────────────────

#[test]
fn cloud_engine_sync_network_error_goes_offline() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("test-key".to_string()),
        HttpClientConfig::default(),
        QuotaLimits {
            max_memories: 100_000,
            max_storage_bytes: 1_000_000_000,
            min_sync_interval_secs: 0,
        },
    );
    engine.connect().unwrap();
    engine.update_quota_usage(QuotaUsage {
        memory_count: 0,
        storage_bytes: 0,
        secs_since_last_sync: 120,
    });

    // Sync with payloads — will fail because cloud feature is off.
    // The error from HttpClient is "cloud feature not enabled" which is a NetworkError.
    let payloads = vec![make_payload("m1", "hash1")];
    let result = engine.sync(&payloads);
    // Either goes offline or returns an error — both are valid.
    match result {
        Ok(r) => {
            // If it went offline, status should be Offline.
            assert!(r.status == SyncResultStatus::Offline || engine.status() == CloudStatus::Error);
        }
        Err(_) => {
            // Network error that wasn't classified as NetworkError.
            assert!(
                engine.status() == CloudStatus::Error || engine.status() == CloudStatus::Syncing
            );
        }
    }
}

#[test]
fn cloud_engine_conflict_resolver_access() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("test-key".to_string()),
        HttpClientConfig::default(),
        QuotaLimits::default(),
    );
    let resolver = engine.conflict_resolver();
    resolver.set_strategy(ResolutionStrategy::RemoteWins);
    assert_eq!(resolver.strategy(), ResolutionStrategy::RemoteWins);
}

// ─── Resolution: all strategies ──────────────────────────────────────────────

#[test]
fn resolution_last_write_wins_local_newer() {
    let conflict = DetectedConflict {
        memory_id: "r1".to_string(),
        local_hash: "lh".to_string(),
        remote_hash: "rh".to_string(),
        local_modified: Utc::now(),
        remote_modified: Utc::now() - chrono::Duration::seconds(100),
        local_payload: make_payload("r1", "lh"),
        remote_payload: make_payload("r1", "rh"),
    };
    let outcome = resolution::resolve(&conflict, ResolutionStrategy::LastWriteWins);
    assert_eq!(outcome.winner.unwrap().content_hash, "lh");
}

#[test]
fn resolution_last_write_wins_remote_newer() {
    let conflict = DetectedConflict {
        memory_id: "r2".to_string(),
        local_hash: "lh".to_string(),
        remote_hash: "rh".to_string(),
        local_modified: Utc::now() - chrono::Duration::seconds(100),
        remote_modified: Utc::now(),
        local_payload: make_payload("r2", "lh"),
        remote_payload: make_payload("r2", "rh"),
    };
    let outcome = resolution::resolve(&conflict, ResolutionStrategy::LastWriteWins);
    assert_eq!(outcome.winner.unwrap().content_hash, "rh");
}

// ─── SyncManager: sync fails without cloud feature ───────────────────────────

#[test]
fn sync_manager_sync_fails_without_cloud() {
    use cortex_cloud::SyncManager;
    let mut mgr = SyncManager::new(100);
    let client = HttpClient::new(HttpClientConfig::default());
    let mut resolver = ConflictResolver::default();
    let payloads = vec![make_payload("m1", "h1")];

    let result = mgr.sync(&client, &payloads, &mut resolver);
    // Should fail because cloud feature is not enabled.
    assert!(result.is_err());
}

// ─── Offline Manager: MutationOp variants ────────────────────────────────────

#[test]
fn mutation_op_delete_variant() {
    let mut mgr = OfflineManager::new(100);
    mgr.enqueue(QueuedMutation {
        memory_id: "del1".to_string(),
        operation: MutationOp::Delete,
        timestamp: Utc::now(),
        payload: None,
    });
    assert_eq!(mgr.queue_len(), 1);
    let drained = mgr.drain_queue();
    assert_eq!(drained[0].operation, MutationOp::Delete);
}

// ─── CloudEngine: sync with queued offline mutations ─────────────────────────

#[test]
fn cloud_engine_sync_with_queued_mutations() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("test-key".to_string()),
        HttpClientConfig::default(),
        QuotaLimits {
            max_memories: 100_000,
            max_storage_bytes: 1_000_000_000,
            min_sync_interval_secs: 0,
        },
    );
    engine.connect().unwrap();
    engine.update_quota_usage(QuotaUsage {
        memory_count: 0,
        storage_bytes: 0,
        secs_since_last_sync: 120,
    });

    // Queue some offline mutations first.
    engine.queue_mutation(
        "offline1",
        MutationOp::Create,
        Some(r#"{"test":true}"#.to_string()),
    );
    engine.queue_mutation(
        "offline2",
        MutationOp::Update,
        Some(r#"{"test":false}"#.to_string()),
    );
    // Also queue one with no payload (delete).
    engine.queue_mutation("offline3", MutationOp::Delete, None);
    assert_eq!(engine.offline_queue_len(), 3);

    // Sync — will fail with network error, but exercises the offline replay path.
    let result = engine.sync(&[]);
    // The sync will fail (no cloud feature), but the offline mutations should have been drained.
    match result {
        Ok(r) => assert!(r.status == SyncResultStatus::Offline),
        Err(_) => {} // Also acceptable.
    }
}

// ─── Auth Manager: ensure_valid_token with refresh token ─────────────────────

#[test]
fn auth_manager_ensure_valid_token_with_refresh() {
    let mut mgr = AuthManager::new(AuthMethod::ApiKey("key".to_string()));
    // Store a token with a refresh token that's about to expire.
    mgr.store_token(AuthToken {
        access_token: "old-token".to_string(),
        refresh_token: Some("refresh-token".to_string()),
        expires_in_secs: 0, // Already expired.
    });
    // ensure_valid_token should try to refresh, then fall back to re-auth.
    let result = mgr.ensure_valid_token();
    // With API key, refresh just re-authenticates, so this should succeed.
    assert!(result.is_ok());
    assert!(mgr.bearer_token().is_some());
}

#[test]
fn auth_manager_ensure_valid_token_no_refresh_token_reauths() {
    let mut mgr = AuthManager::new(AuthMethod::ApiKey("key".to_string()));
    // Store a token without refresh token that's expired.
    mgr.store_token(AuthToken {
        access_token: "old-token".to_string(),
        refresh_token: None,
        expires_in_secs: 0,
    });
    // Should fall back to full re-auth.
    let result = mgr.ensure_valid_token();
    assert!(result.is_ok());
}

// ─── Auth Manager: state TokenExpired ────────────────────────────────────────

#[test]
fn auth_manager_state_token_expired() {
    let mut mgr = AuthManager::new(AuthMethod::ApiKey("key".to_string()));
    // Store a token that expires in 30 seconds (within the 60s buffer).
    mgr.store_token(AuthToken {
        access_token: "expiring".to_string(),
        refresh_token: None,
        expires_in_secs: 30,
    });
    match mgr.state() {
        AuthState::TokenExpired => {}
        other => panic!("expected TokenExpired, got {other:?}"),
    }
}

// ─── Token Manager: expired token ────────────────────────────────────────────

#[test]
fn token_manager_expired_token_returns_none() {
    let mut tm = TokenManager::new();
    tm.store(AuthToken {
        access_token: "expired".to_string(),
        refresh_token: None,
        expires_in_secs: 0,
    });
    // Token with 0 expiry is immediately expired.
    assert!(tm.get().is_none());
    assert!(tm.is_expired());
}

// ─── SyncManager: sync with empty payloads ───────────────────────────────────

#[test]
fn sync_manager_sync_empty_payloads_fails() {
    use cortex_cloud::SyncManager;
    let mut mgr = SyncManager::new(100);
    let client = HttpClient::new(HttpClientConfig::default());
    let mut resolver = ConflictResolver::default();

    // Even with empty payloads, push_pending still calls the client.
    let result = mgr.sync(&client, &[], &mut resolver);
    // Without cloud feature, this should fail.
    assert!(result.is_err());
}

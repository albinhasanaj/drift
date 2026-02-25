//! Tests for cortex-cloud: T11-CLD-01 through T11-CLD-06.

use chrono::Utc;

use cortex_cloud::auth::login_flow::AuthMethod;
use cortex_cloud::auth::offline_mode::{MutationOp, OfflineManager, QueuedMutation};
use cortex_cloud::auth::token_manager::{AuthToken, TokenManager};
use cortex_cloud::auth::AuthManager;
use cortex_cloud::conflict::detection::detect_conflicts;
use cortex_cloud::conflict::resolution::{resolve, ResolutionStrategy};
use cortex_cloud::conflict::ConflictResolver;
use cortex_cloud::quota::{QuotaCheck, QuotaLimits, QuotaManager, QuotaUsage};
use cortex_cloud::sync::delta::compute_delta;
use cortex_cloud::sync::sync_log::{SyncDirection, SyncLog, SyncLogEntry, SyncStatus};
use cortex_cloud::transport::protocol::{
    CloudRequest, CloudResponse, MemoryPayload, PROTOCOL_VERSION,
};
use cortex_cloud::transport::HttpClientConfig;
use cortex_cloud::{CloudEngine, CloudStatus};

// ─── Helpers ───────────────────────────────────────────────

fn make_payload(id: &str, hash: &str, mins_ago: i64) -> MemoryPayload {
    MemoryPayload {
        id: id.to_string(),
        content_hash: hash.to_string(),
        data: serde_json::json!({"summary": id}),
        modified_at: Utc::now() - chrono::Duration::minutes(mins_ago),
    }
}

// ─── T11-CLD-01: Push syncs unpushed mutations ────────────

#[test]
fn test_sync_log_tracks_pending_mutations() {
    let mut log = SyncLog::new();
    assert!(log.is_empty());

    log.record(SyncLogEntry {
        direction: SyncDirection::Push,
        memory_id: "mem-001".into(),
        operation: "create".into(),
        status: SyncStatus::Pending,
        details: "{}".into(),
        timestamp: Utc::now(),
    });
    log.record(SyncLogEntry {
        direction: SyncDirection::Push,
        memory_id: "mem-002".into(),
        operation: "update".into(),
        status: SyncStatus::Pending,
        details: "{}".into(),
        timestamp: Utc::now(),
    });

    assert_eq!(log.len(), 2);
    assert_eq!(log.pending_count(), 2);
    assert_eq!(log.pending(SyncDirection::Push).len(), 2);
    assert_eq!(log.pending(SyncDirection::Pull).len(), 0);

    // Mark one as completed.
    log.mark_completed("mem-001", SyncDirection::Push);
    assert_eq!(log.pending_count(), 1);
    assert_eq!(log.pending(SyncDirection::Push).len(), 1);
}

#[test]
fn test_push_marks_failed_on_error() {
    let mut log = SyncLog::new();
    log.record(SyncLogEntry {
        direction: SyncDirection::Push,
        memory_id: "mem-fail".into(),
        operation: "create".into(),
        status: SyncStatus::Pending,
        details: "{}".into(),
        timestamp: Utc::now(),
    });

    log.mark_failed("mem-fail", SyncDirection::Push);
    assert_eq!(log.pending_count(), 0);
}

// ─── T11-CLD-02: Pull applies remote changes to local ────

#[test]
fn test_delta_detects_remote_only_changes() {
    let local = vec![make_payload("mem-001", "hash-a", 10)];
    let remote = vec![
        make_payload("mem-001", "hash-a", 10), // same
        make_payload("mem-002", "hash-b", 5),  // remote only
    ];

    let delta = compute_delta(&local, &remote);
    assert_eq!(delta.in_sync, 1);
    assert_eq!(delta.remote_only.len(), 1);
    assert_eq!(delta.remote_only[0].id, "mem-002");
    assert!(delta.local_only.is_empty());
    assert!(delta.diverged.is_empty());
    assert!(delta.has_changes());
}

#[test]
fn test_delta_detects_local_only_changes() {
    let local = vec![
        make_payload("mem-001", "hash-a", 10),
        make_payload("mem-003", "hash-c", 2),
    ];
    let remote = vec![make_payload("mem-001", "hash-a", 10)];

    let delta = compute_delta(&local, &remote);
    assert_eq!(delta.in_sync, 1);
    assert_eq!(delta.local_only.len(), 1);
    assert_eq!(delta.local_only[0].id, "mem-003");
}

#[test]
fn test_delta_no_changes_when_in_sync() {
    let local = vec![make_payload("mem-001", "hash-a", 10)];
    let remote = vec![make_payload("mem-001", "hash-a", 10)];

    let delta = compute_delta(&local, &remote);
    assert_eq!(delta.in_sync, 1);
    assert!(!delta.has_changes());
    assert_eq!(delta.change_count(), 0);
}

// ─── T11-CLD-03: Conflict detected when same memory modified on both sides ──

#[test]
fn test_conflict_detection_diverged_hashes() {
    let local = vec![make_payload("mem-001", "hash-local", 5)];
    let remote = vec![make_payload("mem-001", "hash-remote", 3)];

    let conflicts = detect_conflicts(&local, &remote);
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].memory_id, "mem-001");
    assert_eq!(conflicts[0].local_hash, "hash-local");
    assert_eq!(conflicts[0].remote_hash, "hash-remote");
}

#[test]
fn test_conflict_detection_no_conflict_when_same_hash() {
    let local = vec![make_payload("mem-001", "same-hash", 5)];
    let remote = vec![make_payload("mem-001", "same-hash", 3)];

    let conflicts = detect_conflicts(&local, &remote);
    assert!(conflicts.is_empty());
}

#[test]
fn test_delta_detects_diverged_as_conflicts() {
    let local = vec![make_payload("mem-001", "hash-v1", 10)];
    let remote = vec![make_payload("mem-001", "hash-v2", 5)];

    let delta = compute_delta(&local, &remote);
    assert_eq!(delta.diverged.len(), 1);
    assert_eq!(delta.in_sync, 0);
}

// ─── T11-CLD-04: Last-write-wins resolution works correctly ──

#[test]
fn test_last_write_wins_picks_newer() {
    let local = make_payload("mem-001", "hash-local", 10); // 10 mins ago
    let remote = make_payload("mem-001", "hash-remote", 2); // 2 mins ago (newer)

    let conflict = cortex_cloud::conflict::detection::DetectedConflict {
        memory_id: "mem-001".into(),
        local_hash: local.content_hash.clone(),
        remote_hash: remote.content_hash.clone(),
        local_modified: local.modified_at,
        remote_modified: remote.modified_at,
        local_payload: local,
        remote_payload: remote,
    };

    let outcome = resolve(&conflict, ResolutionStrategy::LastWriteWins);
    assert!(!outcome.needs_manual_resolution);
    let winner = outcome.winner.unwrap();
    // Remote is newer (2 mins ago vs 10 mins ago), so remote wins.
    assert_eq!(winner.content_hash, "hash-remote");
}

#[test]
fn test_local_wins_strategy() {
    let local = make_payload("mem-001", "hash-local", 10);
    let remote = make_payload("mem-001", "hash-remote", 2);

    let conflict = cortex_cloud::conflict::detection::DetectedConflict {
        memory_id: "mem-001".into(),
        local_hash: "hash-local".into(),
        remote_hash: "hash-remote".into(),
        local_modified: local.modified_at,
        remote_modified: remote.modified_at,
        local_payload: local,
        remote_payload: remote,
    };

    let outcome = resolve(&conflict, ResolutionStrategy::LocalWins);
    assert_eq!(outcome.winner.unwrap().content_hash, "hash-local");
}

#[test]
fn test_remote_wins_strategy() {
    let local = make_payload("mem-001", "hash-local", 2);
    let remote = make_payload("mem-001", "hash-remote", 10);

    let conflict = cortex_cloud::conflict::detection::DetectedConflict {
        memory_id: "mem-001".into(),
        local_hash: "hash-local".into(),
        remote_hash: "hash-remote".into(),
        local_modified: local.modified_at,
        remote_modified: remote.modified_at,
        local_payload: local,
        remote_payload: remote,
    };

    let outcome = resolve(&conflict, ResolutionStrategy::RemoteWins);
    assert_eq!(outcome.winner.unwrap().content_hash, "hash-remote");
}

#[test]
fn test_manual_strategy_defers_to_user() {
    let local = make_payload("mem-001", "hash-local", 5);
    let remote = make_payload("mem-001", "hash-remote", 3);

    let conflict = cortex_cloud::conflict::detection::DetectedConflict {
        memory_id: "mem-001".into(),
        local_hash: "hash-local".into(),
        remote_hash: "hash-remote".into(),
        local_modified: local.modified_at,
        remote_modified: remote.modified_at,
        local_payload: local,
        remote_payload: remote,
    };

    let outcome = resolve(&conflict, ResolutionStrategy::Manual);
    assert!(outcome.needs_manual_resolution);
    assert!(outcome.winner.is_none());
}

#[test]
fn test_conflict_resolver_logs_resolutions() {
    let mut resolver = ConflictResolver::default();
    assert_eq!(resolver.strategy(), ResolutionStrategy::LastWriteWins);

    let local = make_payload("mem-001", "hash-local", 10);
    let remote = make_payload("mem-001", "hash-remote", 2);

    let conflict = cortex_cloud::conflict::detection::DetectedConflict {
        memory_id: "mem-001".into(),
        local_hash: "hash-local".into(),
        remote_hash: "hash-remote".into(),
        local_modified: local.modified_at,
        remote_modified: remote.modified_at,
        local_payload: local,
        remote_payload: remote,
    };

    let outcome = resolver.resolve(&conflict);
    assert!(!outcome.needs_manual_resolution);
    assert_eq!(resolver.log().total_count(), 1);
    assert_eq!(resolver.log().unresolved_count(), 0);
}

// ─── T11-CLD-05: Offline mode queues mutations and replays on reconnect ──

#[test]
fn test_offline_manager_queues_mutations() {
    let mut mgr = OfflineManager::new(100);
    assert!(mgr.is_online());
    assert!(!mgr.has_pending());

    mgr.go_offline();
    assert!(!mgr.is_online());

    mgr.enqueue(QueuedMutation {
        memory_id: "mem-001".into(),
        operation: MutationOp::Create,
        timestamp: Utc::now(),
        payload: Some(r#"{"summary":"test"}"#.into()),
    });
    mgr.enqueue(QueuedMutation {
        memory_id: "mem-002".into(),
        operation: MutationOp::Update,
        timestamp: Utc::now(),
        payload: Some(r#"{"summary":"updated"}"#.into()),
    });

    assert_eq!(mgr.queue_len(), 2);
    assert!(mgr.has_pending());

    // Go back online and drain.
    mgr.go_online();
    assert!(mgr.is_online());

    let drained = mgr.drain_queue();
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].memory_id, "mem-001");
    assert_eq!(drained[1].memory_id, "mem-002");
    assert!(!mgr.has_pending());
}

#[test]
fn test_offline_queue_drops_oldest_when_full() {
    let mut mgr = OfflineManager::new(2);
    mgr.go_offline();

    mgr.enqueue(QueuedMutation {
        memory_id: "mem-001".into(),
        operation: MutationOp::Create,
        timestamp: Utc::now(),
        payload: None,
    });
    mgr.enqueue(QueuedMutation {
        memory_id: "mem-002".into(),
        operation: MutationOp::Create,
        timestamp: Utc::now(),
        payload: None,
    });
    // This should drop mem-001.
    mgr.enqueue(QueuedMutation {
        memory_id: "mem-003".into(),
        operation: MutationOp::Create,
        timestamp: Utc::now(),
        payload: None,
    });

    assert_eq!(mgr.queue_len(), 2);
    let drained = mgr.drain_queue();
    assert_eq!(drained[0].memory_id, "mem-002");
    assert_eq!(drained[1].memory_id, "mem-003");
}

// ─── T11-CLD-06: Quota enforcement prevents exceeding limits ──

#[test]
fn test_quota_ok_when_within_limits() {
    let mut mgr = QuotaManager::new(QuotaLimits {
        max_memories: 1000,
        max_storage_bytes: 1_000_000,
        min_sync_interval_secs: 60,
    });
    mgr.update_usage(QuotaUsage {
        memory_count: 100,
        storage_bytes: 50_000,
        secs_since_last_sync: 120,
    });

    assert!(mgr.enforce().is_ok());
    assert!(matches!(mgr.check_memory_create(), QuotaCheck::Ok));
    assert!(matches!(mgr.check_storage(), QuotaCheck::Ok));
    assert!(mgr.check_sync_frequency());
}

#[test]
fn test_quota_warning_at_80_percent() {
    let mut mgr = QuotaManager::new(QuotaLimits {
        max_memories: 100,
        max_storage_bytes: 1_000_000,
        min_sync_interval_secs: 60,
    });
    mgr.update_usage(QuotaUsage {
        memory_count: 85,
        storage_bytes: 50_000,
        secs_since_last_sync: 120,
    });

    match mgr.check_memory_create() {
        QuotaCheck::Warning { resource, percent } => {
            assert_eq!(resource, "memories");
            assert!(percent >= 80.0);
        }
        other => panic!("expected Warning, got {:?}", other),
    }
}

#[test]
fn test_quota_exceeded_blocks_operation() {
    let mut mgr = QuotaManager::new(QuotaLimits {
        max_memories: 100,
        max_storage_bytes: 1_000_000,
        min_sync_interval_secs: 60,
    });
    mgr.update_usage(QuotaUsage {
        memory_count: 100,
        storage_bytes: 50_000,
        secs_since_last_sync: 120,
    });

    assert!(mgr.enforce().is_err());
    assert!(matches!(
        mgr.check_memory_create(),
        QuotaCheck::Exceeded { .. }
    ));
}

#[test]
fn test_quota_sync_frequency_throttle() {
    let mut mgr = QuotaManager::new(QuotaLimits {
        max_memories: 1000,
        max_storage_bytes: 1_000_000,
        min_sync_interval_secs: 60,
    });
    mgr.update_usage(QuotaUsage {
        memory_count: 10,
        storage_bytes: 1000,
        secs_since_last_sync: 30, // too soon
    });

    assert!(!mgr.check_sync_frequency());
}

// ─── Auth tests ──────────────────────────────────────────

#[test]
fn test_api_key_auth_flow() {
    let mut auth = AuthManager::new(AuthMethod::ApiKey("test-key-123".into()));
    assert!(matches!(
        auth.state(),
        cortex_cloud::AuthState::Unauthenticated
    ));

    auth.login().unwrap();
    assert!(matches!(
        auth.state(),
        cortex_cloud::AuthState::Authenticated
    ));
    assert_eq!(auth.bearer_token(), Some("test-key-123"));

    auth.logout();
    assert!(matches!(
        auth.state(),
        cortex_cloud::AuthState::Unauthenticated
    ));
    assert!(auth.bearer_token().is_none());
}

#[test]
fn test_token_manager_expiry() {
    let mut tm = TokenManager::new();
    assert!(tm.is_expired());
    assert!(tm.get().is_none());

    tm.store(AuthToken {
        access_token: "tok-123".into(),
        refresh_token: None,
        expires_in_secs: u64::MAX,
    });

    assert!(!tm.is_expired());
    assert_eq!(tm.get().unwrap().access_token, "tok-123");
    assert!(!tm.has_refresh_token());

    tm.clear();
    assert!(tm.is_expired());
}

// ─── Protocol tests ──────────────────────────────────────

#[test]
fn test_cloud_request_envelope() {
    let req = CloudRequest::new("hello");
    assert_eq!(req.version, PROTOCOL_VERSION);
    assert!(!req.request_id.is_empty());
}

#[test]
fn test_cloud_response_ok() {
    let resp = CloudResponse::ok("req-1".into(), 42);
    assert!(resp.success);
    assert_eq!(resp.data, Some(42));
    assert!(resp.error.is_none());
}

#[test]
fn test_cloud_response_err() {
    let resp = CloudResponse::<()>::err("req-1".into(), "something broke".into());
    assert!(!resp.success);
    assert!(resp.data.is_none());
    assert_eq!(resp.error.unwrap(), "something broke");
}

// ─── Engine integration tests ────────────────────────────

#[test]
fn test_cloud_engine_initial_state() {
    let engine = CloudEngine::new(
        AuthMethod::ApiKey("key".into()),
        HttpClientConfig::default(),
        QuotaLimits::default(),
    );
    assert_eq!(engine.status(), CloudStatus::Disconnected);
    assert!(engine.is_online());
    assert_eq!(engine.offline_queue_len(), 0);
}

#[test]
fn test_cloud_engine_connect_with_api_key() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("my-api-key".into()),
        HttpClientConfig::default(),
        QuotaLimits::default(),
    );

    engine.connect().unwrap();
    assert_eq!(engine.status(), CloudStatus::Connected);
}

#[test]
fn test_cloud_engine_disconnect() {
    let mut engine = CloudEngine::new(
        AuthMethod::ApiKey("key".into()),
        HttpClientConfig::default(),
        QuotaLimits::default(),
    );

    engine.connect().unwrap();
    engine.disconnect();
    assert_eq!(engine.status(), CloudStatus::Disconnected);
}

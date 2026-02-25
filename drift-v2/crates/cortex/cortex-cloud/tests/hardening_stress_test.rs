//! Enterprise stress tests for Cortex Cloud hardening fixes.
//!
//! Covers:
//! - P0-4: Cloud resolve_conflict — strategy parsing, validation, application, repeated switching
//! - P1-6: Cloud quota — record_sync_completed resets timer, repeated sync cycles
//!
//! Every test targets a specific production failure mode. No happy-path-only tests.

use cortex_cloud::conflict::{ConflictResolver, Strategy};
use cortex_cloud::conflict::detection::DetectedConflict;
use cortex_cloud::transport::protocol::MemoryPayload;
use cortex_cloud::quota::{QuotaLimits, QuotaManager, QuotaUsage};

// ═══════════════════════════════════════════════════════════════════════════════
// P0-4: CONFLICT RESOLVER — strategy switching
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: resolve_conflict was a no-op — acquired the resolver but
/// never called set_strategy(). Verify strategy actually changes.
#[test]
fn hst_p04_01_set_strategy_changes_resolver_state() {
    let mut resolver = ConflictResolver::default();
    assert_eq!(resolver.strategy(), Strategy::LastWriteWins);

    resolver.set_strategy(Strategy::LocalWins);
    assert_eq!(resolver.strategy(), Strategy::LocalWins);

    resolver.set_strategy(Strategy::RemoteWins);
    assert_eq!(resolver.strategy(), Strategy::RemoteWins);
}

/// Rapidly switch between all 5 strategies — no panic, no corruption.
#[test]
fn hst_p04_02_rapid_strategy_switching_all_five() {
    let mut resolver = ConflictResolver::default();
    let strategies = [
        Strategy::LastWriteWins,
        Strategy::LocalWins,
        Strategy::RemoteWins,
        Strategy::CrdtMerge,
        Strategy::Manual,
    ];

    // 100 rapid switches across all strategies.
    for i in 0..100 {
        let s = strategies[i % strategies.len()];
        resolver.set_strategy(s);
        assert_eq!(resolver.strategy(), s, "Strategy mismatch at iteration {i}");
    }
}

/// Set same strategy twice — idempotent, no state corruption.
#[test]
fn hst_p04_03_set_strategy_idempotent() {
    let mut resolver = ConflictResolver::default();
    resolver.set_strategy(Strategy::CrdtMerge);
    resolver.set_strategy(Strategy::CrdtMerge);
    assert_eq!(resolver.strategy(), Strategy::CrdtMerge);
}

/// Default strategy is LastWriteWins — verify initial state.
#[test]
fn hst_p04_04_default_strategy_is_last_write_wins() {
    let resolver = ConflictResolver::default();
    assert_eq!(resolver.strategy(), Strategy::LastWriteWins);
}

/// After resolving a conflict, strategy must persist.
#[test]
fn hst_p04_05_strategy_persists_after_resolve() {
    let mut resolver = ConflictResolver::default();
    resolver.set_strategy(Strategy::RemoteWins);

    let conflict = DetectedConflict {
        memory_id: "mem-001".to_string(),
        local_hash: "abc".to_string(),
        remote_hash: "def".to_string(),
        local_payload: MemoryPayload {
            id: "mem-001".to_string(),
            content_hash: "abc".to_string(),
            data: serde_json::json!({"summary": "local"}),
            modified_at: chrono::Utc::now(),
        },
        remote_payload: MemoryPayload {
            id: "mem-001".to_string(),
            content_hash: "def".to_string(),
            data: serde_json::json!({"summary": "remote"}),
            modified_at: chrono::Utc::now(),
        },
        local_modified: chrono::Utc::now(),
        remote_modified: chrono::Utc::now(),
    };

    let outcome = resolver.resolve(&conflict);
    // RemoteWins → winner should be the remote payload.
    assert!(!outcome.needs_manual_resolution);
    assert!(outcome.winner.is_some());
    assert_eq!(outcome.winner.unwrap().content_hash, "def");

    // Strategy still set after resolve.
    assert_eq!(resolver.strategy(), Strategy::RemoteWins);
}

/// Manual strategy → needs_manual_resolution = true, no winner.
#[test]
fn hst_p04_06_manual_strategy_defers_to_user() {
    let mut resolver = ConflictResolver::default();
    resolver.set_strategy(Strategy::Manual);

    let conflict = DetectedConflict {
        memory_id: "mem-002".to_string(),
        local_hash: "aaa".to_string(),
        remote_hash: "bbb".to_string(),
        local_payload: MemoryPayload {
            id: "mem-002".to_string(),
            content_hash: "aaa".to_string(),
            data: serde_json::json!({"summary": "local"}),
            modified_at: chrono::Utc::now(),
        },
        remote_payload: MemoryPayload {
            id: "mem-002".to_string(),
            content_hash: "bbb".to_string(),
            data: serde_json::json!({"summary": "remote"}),
            modified_at: chrono::Utc::now(),
        },
        local_modified: chrono::Utc::now(),
        remote_modified: chrono::Utc::now(),
    };

    let outcome = resolver.resolve(&conflict);
    assert!(outcome.needs_manual_resolution);
    assert!(outcome.winner.is_none());
}

/// Resolve 1000 conflicts in sequence — stress the log, no OOM/panic.
#[test]
fn hst_p04_07_stress_1000_sequential_resolves() {
    let mut resolver = ConflictResolver::new(Strategy::LastWriteWins);

    for i in 0..1000 {
        let conflict = DetectedConflict {
            memory_id: format!("stress-{i}"),
            local_hash: format!("local-{i}"),
            remote_hash: format!("remote-{i}"),
            local_payload: MemoryPayload {
                id: format!("stress-{i}"),
                content_hash: format!("local-{i}"),
                data: serde_json::json!({}),
                modified_at: chrono::Utc::now(),
            },
            remote_payload: MemoryPayload {
                id: format!("stress-{i}"),
                content_hash: format!("remote-{i}"),
                data: serde_json::json!({}),
                modified_at: chrono::Utc::now(),
            },
            local_modified: chrono::Utc::now(),
            remote_modified: chrono::Utc::now(),
        };

        let outcome = resolver.resolve(&conflict);
        assert!(!outcome.needs_manual_resolution);
    }

    // Log should have 1000 records.
    assert_eq!(resolver.log().total_count(), 1000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// P1-6: QUOTA MANAGER — record_sync_completed resets timer
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: secs_since_last_sync was never reset → permanent throttling.
/// After record_sync_completed(), check_sync_frequency() must return false
/// if min_sync_interval > 0 because we *just* synced.
#[test]
fn hst_p16_01_record_sync_resets_timer_to_zero() {
    let limits = QuotaLimits {
        min_sync_interval_secs: 60,
        ..Default::default()
    };
    let mut manager = QuotaManager::new(limits);

    // Simulate 120 seconds elapsed.
    manager.update_usage(QuotaUsage {
        secs_since_last_sync: 120,
        ..Default::default()
    });
    assert!(manager.check_sync_frequency(), "Should allow sync after 120s");

    // Record sync completed.
    manager.record_sync_completed();
    assert_eq!(manager.usage().secs_since_last_sync, 0);
    assert!(!manager.check_sync_frequency(), "Should NOT allow sync immediately after completing one");
}

/// Repeated sync cycles: elapsed → sync → reset → elapsed → sync → reset.
#[test]
fn hst_p16_02_repeated_sync_cycles_no_permanent_throttle() {
    let limits = QuotaLimits {
        min_sync_interval_secs: 10,
        ..Default::default()
    };
    let mut manager = QuotaManager::new(limits);

    for cycle in 0..50 {
        // Simulate time passing.
        manager.update_usage(QuotaUsage {
            secs_since_last_sync: 15,
            ..Default::default()
        });
        assert!(
            manager.check_sync_frequency(),
            "Should allow sync in cycle {cycle}"
        );

        // Sync completes.
        manager.record_sync_completed();
        assert_eq!(
            manager.usage().secs_since_last_sync, 0,
            "Timer not reset in cycle {cycle}"
        );
        assert!(!manager.check_sync_frequency());
    }
}

/// Edge case: min_sync_interval_secs = 0 → always allow.
#[test]
fn hst_p16_03_zero_interval_always_allows_sync() {
    let limits = QuotaLimits {
        min_sync_interval_secs: 0,
        ..Default::default()
    };
    let mut manager = QuotaManager::new(limits);

    manager.record_sync_completed();
    // 0 >= 0 is true → should always allow.
    assert!(manager.check_sync_frequency());
}

/// QuotaManager::enforce() doesn't fail on fresh manager.
#[test]
fn hst_p16_04_enforce_fresh_manager_ok() {
    let manager = QuotaManager::default();
    assert!(manager.enforce().is_ok());
}

/// QuotaManager::enforce() fails when memory limit exceeded.
#[test]
fn hst_p16_05_enforce_exceeds_memory_limit() {
    let limits = QuotaLimits {
        max_memories: 10,
        ..Default::default()
    };
    let mut manager = QuotaManager::new(limits);
    manager.update_usage(QuotaUsage {
        memory_count: 15,
        ..Default::default()
    });
    assert!(manager.enforce().is_err());
}

/// Warning at 80% usage — not a hard failure.
#[test]
fn hst_p16_06_warning_at_80_percent() {
    let limits = QuotaLimits {
        max_memories: 100,
        ..Default::default()
    };
    let mut manager = QuotaManager::new(limits);
    manager.update_usage(QuotaUsage {
        memory_count: 85,
        ..Default::default()
    });
    // 85% → warning, but enforce still passes.
    assert!(manager.enforce().is_ok());

    // Check that check_memory_create returns Warning variant.
    match manager.check_memory_create() {
        cortex_cloud::quota::QuotaCheck::Warning { percent, .. } => {
            assert!((80.0..=90.0).contains(&percent));
        }
        other => panic!("Expected Warning, got {:?}", other),
    }
}

//! Phase C cloud quota tests (C-21, C-22).

use cortex_cloud::quota::{QuotaLimits, QuotaManager, QuotaUsage};

/// C-21: Cloud rejects/warns on empty API key at init.
/// (The actual rejection happens at the runtime level via tracing::warn;
/// here we verify that QuotaManager itself works correctly regardless.)
#[test]
fn c21_quota_manager_initializes_with_defaults() {
    let qm = QuotaManager::new(QuotaLimits::default());
    // Default usage: 0 memories, 0 bytes, 0 secs since sync.
    assert_eq!(qm.usage().memory_count, 0);
    assert_eq!(qm.usage().storage_bytes, 0);
    assert_eq!(qm.usage().secs_since_last_sync, 0);
    // With 0 secs since last sync, check_sync_frequency should return false
    // (we just "synced" — need to wait min_sync_interval_secs).
    assert!(
        !qm.check_sync_frequency(),
        "should NOT allow sync immediately (0 < 60)"
    );
}

/// C-22: Quota allows sync after successful sync (not permanently throttled).
/// After record_sync_completed() resets the timer, a subsequent update with
/// enough elapsed time should allow syncing again.
#[test]
fn c22_quota_allows_sync_after_record() {
    let mut qm = QuotaManager::new(QuotaLimits {
        max_memories: 1000,
        max_storage_bytes: 1_000_000,
        min_sync_interval_secs: 60,
    });

    // Simulate: time has passed, sync is allowed.
    qm.update_usage(QuotaUsage {
        memory_count: 10,
        storage_bytes: 1000,
        secs_since_last_sync: 120, // 120 > 60
    });
    assert!(qm.check_sync_frequency(), "should allow sync after 120s");

    // Record sync completed (C-10 fix).
    qm.record_sync_completed();
    assert_eq!(qm.usage().secs_since_last_sync, 0, "should reset to 0");
    assert!(
        !qm.check_sync_frequency(),
        "should NOT allow sync immediately after reset"
    );

    // Simulate more time passing.
    qm.update_usage(QuotaUsage {
        memory_count: 10,
        storage_bytes: 1000,
        secs_since_last_sync: 61,
    });
    assert!(
        qm.check_sync_frequency(),
        "should allow sync again after enough time"
    );
}

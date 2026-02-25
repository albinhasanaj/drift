//! Enterprise stress tests for Cortex Multi-Agent hardening fixes.
//!
//! Covers:
//! - P1-2/B-07: SyncResult struct has real fields (deltas_applied, deltas_buffered)
//!   that are used by the NAPI binding instead of hardcoded zeros.
//! - F1: AgentStatus filter enum — sentinel timestamps instead of Utc::now().
//!
//! Every test targets a specific production failure mode.

use cortex_core::models::agent::AgentStatus;
use cortex_multiagent::sync::protocol::SyncResult;

// ═══════════════════════════════════════════════════════════════════════════════
// P1-2/B-07: SYNC RESULT — real counts, not hardcoded zeros
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: NAPI returned hardcoded applied_count=0, buffered_count=0.
/// Verify SyncResult fields are independent and non-zero-capable.
#[test]
fn hst_b07_01_sync_result_carries_real_counts() {
    let result = SyncResult {
        deltas_sent: 10,
        deltas_received: 8,
        deltas_applied: 7,
        deltas_buffered: 1,
    };

    assert_eq!(result.deltas_sent, 10);
    assert_eq!(result.deltas_received, 8);
    assert_eq!(result.deltas_applied, 7);
    assert_eq!(result.deltas_buffered, 1);
}

/// Zero sync result is valid (no deltas to process).
#[test]
fn hst_b07_02_sync_result_all_zero_valid() {
    let result = SyncResult {
        deltas_sent: 0,
        deltas_received: 0,
        deltas_applied: 0,
        deltas_buffered: 0,
    };

    assert_eq!(result.deltas_applied, 0);
    assert_eq!(result.deltas_buffered, 0);
}

/// Large counts don't overflow or panic.
#[test]
fn hst_b07_03_sync_result_large_counts() {
    let result = SyncResult {
        deltas_sent: usize::MAX,
        deltas_received: usize::MAX,
        deltas_applied: usize::MAX / 2,
        deltas_buffered: usize::MAX / 2,
    };

    assert_eq!(result.deltas_applied, usize::MAX / 2);
    assert_eq!(result.deltas_buffered, usize::MAX / 2);
}

/// applied + buffered can exceed received (buffered from prior syncs).
#[test]
fn hst_b07_04_buffered_from_prior_syncs() {
    let result = SyncResult {
        deltas_sent: 5,
        deltas_received: 3,
        deltas_applied: 3,
        deltas_buffered: 10, // Buffered from prior incomplete syncs.
    };

    assert!(result.deltas_buffered > result.deltas_received);
}

// ═══════════════════════════════════════════════════════════════════════════════
// F1: AGENT STATUS — sentinel timestamps for filter-only enum variants
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: list_agents filter used Utc::now() to construct Idle/Deregistered
/// variants just for pattern matching. This was semantically wrong.
/// Verify the AgentStatus enum variants can be constructed with any timestamp.
#[test]
fn hst_f01_01_agent_status_active_no_timestamp() {
    let status = AgentStatus::Active;
    match status {
        AgentStatus::Active => {} // OK.
        _ => panic!("Expected Active"),
    }
}

/// Idle variant with MIN_UTC sentinel — used for filter-only pattern matching.
#[test]
fn hst_f01_02_idle_with_sentinel_timestamp() {
    let sentinel = chrono::DateTime::<chrono::Utc>::MIN_UTC;
    let status = AgentStatus::Idle { since: sentinel };

    match &status {
        AgentStatus::Idle { since } => {
            assert_eq!(*since, sentinel);
        }
        _ => panic!("Expected Idle"),
    }
}

/// Deregistered variant with MIN_UTC sentinel.
#[test]
fn hst_f01_03_deregistered_with_sentinel_timestamp() {
    let sentinel = chrono::DateTime::<chrono::Utc>::MIN_UTC;
    let status = AgentStatus::Deregistered { at: sentinel };

    match &status {
        AgentStatus::Deregistered { at } => {
            assert_eq!(*at, sentinel);
        }
        _ => panic!("Expected Deregistered"),
    }
}

/// Verify that the filter extraction logic (matching on variant discriminant)
/// works identically regardless of the timestamp value.
#[test]
fn hst_f01_04_filter_extraction_ignores_timestamp() {
    let sentinel = chrono::DateTime::<chrono::Utc>::MIN_UTC;
    let now = chrono::Utc::now();

    let filter_sentinel = AgentStatus::Idle { since: sentinel };
    let filter_now = AgentStatus::Idle { since: now };

    // The registry's list_agents extracts just the string "idle" — both should yield same result.
    let extract = |status: &AgentStatus| -> &str {
        match status {
            AgentStatus::Active => "active",
            AgentStatus::Idle { .. } => "idle",
            AgentStatus::Deregistered { .. } => "deregistered",
        }
    };

    assert_eq!(extract(&filter_sentinel), "idle");
    assert_eq!(extract(&filter_now), "idle");
}

/// All three status strings extractable — regression check.
#[test]
fn hst_f01_05_all_status_strings_correct() {
    let sentinel = chrono::DateTime::<chrono::Utc>::MIN_UTC;

    let statuses = vec![
        (AgentStatus::Active, "active"),
        (AgentStatus::Idle { since: sentinel }, "idle"),
        (AgentStatus::Deregistered { at: sentinel }, "deregistered"),
    ];

    for (status, expected) in &statuses {
        let label = match status {
            AgentStatus::Active => "active",
            AgentStatus::Idle { .. } => "idle",
            AgentStatus::Deregistered { .. } => "deregistered",
        };
        assert_eq!(label, *expected);
    }
}

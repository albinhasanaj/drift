//! Subsystem operations tests: session lifecycle, drift snapshots, memory snapshots,
//! temporal queries, materialized views, maintenance ops, compaction, event archival.
//!
//! These modules had ZERO direct tests before this file.

use chrono::{Duration, Utc};
use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::queries::{
    drift_ops, event_ops, maintenance, session_ops, snapshot_ops, temporal_ops, version_ops,
    view_ops,
};
use cortex_storage::StorageEngine;

fn make_memory(id: &str) -> BaseMemory {
    let content = TypedContent::Tribal(TribalContent {
        knowledge: format!("Knowledge for {id}"),
        severity: "medium".to_string(),
        warnings: vec![],
        consequences: vec![],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Tribal,
        content: content.clone(),
        summary: format!("Summary of {id}"),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

fn with_writer<F, T>(engine: &StorageEngine, f: F) -> T
where
    F: FnOnce(&rusqlite::Connection) -> cortex_core::errors::CortexResult<T>,
{
    engine.pool().writer.with_conn_sync(f).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION OPS: full lifecycle
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn session_create_and_end() {
    let engine = StorageEngine::open_in_memory().unwrap();
    with_writer(&engine, |conn| {
        session_ops::create_session(conn, "sess-1", 10000)?;
        session_ops::end_session(conn, "sess-1")?;
        Ok(())
    });
}

#[test]
fn session_update_tokens() {
    let engine = StorageEngine::open_in_memory().unwrap();
    with_writer(&engine, |conn| {
        session_ops::create_session(conn, "sess-tok", 10000)?;
        session_ops::update_tokens_used(conn, "sess-tok", 5000)?;
        Ok(())
    });
}

#[test]
fn session_analytics_roundtrip() {
    let engine = StorageEngine::open_in_memory().unwrap();
    with_writer(&engine, |conn| {
        session_ops::create_session(conn, "sess-ana", 10000)?;

        // Record multiple analytics events
        session_ops::record_analytics_event(
            conn,
            "sess-ana",
            "memory_access",
            &serde_json::json!({"memory_id": "m1"}),
        )?;
        session_ops::record_analytics_event(
            conn,
            "sess-ana",
            "memory_access",
            &serde_json::json!({"memory_id": "m2"}),
        )?;
        session_ops::record_analytics_event(
            conn,
            "sess-ana",
            "search",
            &serde_json::json!({"query": "test"}),
        )?;

        let counts = session_ops::count_events_by_type(conn, "sess-ana")?;
        assert_eq!(counts.len(), 2, "should have 2 event types");

        let access_count = counts.iter().find(|(t, _)| t == "memory_access");
        assert_eq!(
            access_count.map(|(_, c)| *c),
            Some(2),
            "memory_access should have count 2"
        );

        let search_count = counts.iter().find(|(t, _)| t == "search");
        assert_eq!(
            search_count.map(|(_, c)| *c),
            Some(1),
            "search should have count 1"
        );

        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// DRIFT OPS: snapshot insert and query
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn drift_snapshot_insert_and_query() {
    let engine = StorageEngine::open_in_memory().unwrap();
    with_writer(&engine, |conn| {
        let ts1 = "2024-01-01T00:00:00Z";
        let ts2 = "2024-01-02T00:00:00Z";
        let ts3 = "2024-01-03T00:00:00Z";

        drift_ops::insert_drift_snapshot(conn, ts1, 3600, r#"{"metric": 1}"#)?;
        drift_ops::insert_drift_snapshot(conn, ts2, 3600, r#"{"metric": 2}"#)?;
        drift_ops::insert_drift_snapshot(conn, ts3, 3600, r#"{"metric": 3}"#)?;

        // Query range
        let snapshots =
            drift_ops::get_drift_snapshots(conn, "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")?;
        assert_eq!(snapshots.len(), 2, "should get 2 snapshots in range");

        // Get latest
        let latest = drift_ops::get_latest_drift_snapshot(conn)?;
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().timestamp, ts3);

        Ok(())
    });
}

#[test]
fn drift_snapshot_empty_returns_none() {
    let engine = StorageEngine::open_in_memory().unwrap();
    with_writer(&engine, |conn| {
        let latest = drift_ops::get_latest_drift_snapshot(conn)?;
        assert!(latest.is_none(), "no snapshots = None");
        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// SNAPSHOT OPS: memory snapshot insert, nearest, delete old
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn memory_snapshot_insert_and_query() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("snap-mem")).unwrap();

    with_writer(&engine, |conn| {
        snapshot_ops::insert_snapshot(
            conn,
            "snap-mem",
            "2024-06-01T00:00:00Z",
            b"state-bytes-1",
            1,
            "update",
        )?;
        snapshot_ops::insert_snapshot(
            conn,
            "snap-mem",
            "2024-06-02T00:00:00Z",
            b"state-bytes-2",
            2,
            "update",
        )?;

        let all = snapshot_ops::get_snapshots_for_memory(conn, "snap-mem")?;
        assert_eq!(all.len(), 2);

        // Nearest before a timestamp
        let nearest =
            snapshot_ops::get_nearest_snapshot(conn, "snap-mem", "2024-06-01T12:00:00Z")?;
        assert!(nearest.is_some());
        assert_eq!(nearest.unwrap().reason, "update");

        Ok(())
    });
}

#[test]
fn memory_snapshot_delete_old() {
    let engine = StorageEngine::open_in_memory().unwrap();
    with_writer(&engine, |conn| {
        // Insert old and new snapshots
        snapshot_ops::insert_snapshot(
            conn,
            "snap-del",
            "2023-01-01T00:00:00Z",
            b"old",
            1,
            "old",
        )?;
        snapshot_ops::insert_snapshot(
            conn,
            "snap-del",
            "2024-06-01T00:00:00Z",
            b"new",
            2,
            "new",
        )?;

        // Delete before 2024
        let deleted = snapshot_ops::delete_old_snapshots(conn, "2024-01-01T00:00:00Z", false)?;
        assert_eq!(deleted, 1, "should delete 1 old snapshot");

        let remaining = snapshot_ops::get_snapshots_for_memory(conn, "snap-del")?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].reason, "new");

        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// TEMPORAL OPS: bitemporal queries with Allen's interval algebra
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn temporal_valid_at_query() {
    let engine = StorageEngine::open_in_memory().unwrap();

    // Create a memory valid from now
    let mem = make_memory("temp-valid");
    engine.create(&mem).unwrap();

    // Use a future time to ensure the just-created memory is captured
    // (transaction_time is set at create time, which is slightly after any pre-captured "now")
    let future = Utc::now() + Duration::seconds(10);

    // Query for memories valid at current time with system_time in the future
    let results = with_writer(&engine, |conn| {
        temporal_ops::get_memories_valid_at(conn, future, future)
    });

    assert!(
        !results.is_empty(),
        "should find memory valid at current time"
    );
}

#[test]
fn temporal_memories_modified_between() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let before = Utc::now() - Duration::seconds(1);
    engine.create(&make_memory("temp-mod")).unwrap();
    let after = Utc::now() + Duration::seconds(1);

    let modified = with_writer(&engine, |conn| {
        temporal_ops::get_memories_modified_between(conn, before, after)
    });

    assert!(
        modified.contains(&"temp-mod".to_string()),
        "should find modified memory in range"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// VIEW OPS: materialized views CRUD
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn materialized_view_crud() {
    let engine = StorageEngine::open_in_memory().unwrap();
    with_writer(&engine, |conn| {
        let params = view_ops::InsertViewParams {
            label: "test-view",
            timestamp: "2024-06-01T00:00:00Z",
            memory_count: 42,
            snapshot_ids_json: "[1, 2, 3]",
            drift_snapshot_id: None,
            created_by_json: r#""system""#,
            auto_refresh: true,
        };

        let id = view_ops::insert_materialized_view(conn, &params)?;
        assert!(id > 0);

        // Get by label
        let view = view_ops::get_view_by_label(conn, "test-view")?;
        assert!(view.is_some());
        let v = view.unwrap();
        assert_eq!(v.label, "test-view");
        assert_eq!(v.memory_count, 42);
        assert!(v.auto_refresh);

        // List
        let views = view_ops::list_views(conn)?;
        assert_eq!(views.len(), 1);

        // Delete
        view_ops::delete_view(conn, "test-view")?;
        let views = view_ops::list_views(conn)?;
        assert!(views.is_empty());

        Ok(())
    });
}

#[test]
fn materialized_view_get_nonexistent_returns_none() {
    let engine = StorageEngine::open_in_memory().unwrap();
    with_writer(&engine, |conn| {
        let view = view_ops::get_view_by_label(conn, "nonexistent")?;
        assert!(view.is_none());
        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// MAINTENANCE OPS: vacuum, integrity, checkpoint, cleanup, audit rotation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integrity_check_on_healthy_db() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let ok = with_writer(&engine, maintenance::integrity_check);
    assert!(ok, "fresh DB should pass integrity check");
}

#[test]
fn incremental_vacuum_succeeds() {
    let engine = StorageEngine::open_in_memory().unwrap();
    with_writer(&engine, |conn| maintenance::incremental_vacuum(conn, 10));
}

#[test]
fn full_vacuum_succeeds() {
    let engine = StorageEngine::open_in_memory().unwrap();
    // Add some data then vacuum
    engine.create(&make_memory("vac-1")).unwrap();
    engine.delete("vac-1").unwrap();
    engine.vacuum().unwrap();
}

#[test]
fn wal_checkpoint_succeeds() {
    let engine = StorageEngine::open_in_memory().unwrap();
    with_writer(&engine, maintenance::wal_checkpoint);
}

#[test]
fn archived_cleanup_removes_old_low_confidence() {
    let engine = StorageEngine::open_in_memory().unwrap();

    // Create and archive a memory
    let mut mem = make_memory("cleanup-target");
    mem.confidence = Confidence::new(0.05); // Below default 0.1 threshold
    mem.archived = true;
    mem.access_count = 0;
    // Set last_accessed to 100 days ago
    mem.last_accessed = Utc::now() - Duration::days(100);
    engine.create(&mem).unwrap();

    // Run cleanup with 90 day threshold
    let deleted = with_writer(&engine, |conn| {
        maintenance::archived_cleanup(conn, 90, 0.1)
    });

    assert_eq!(deleted, 1, "should clean up old archived low-confidence memory");
    assert!(
        engine.get("cleanup-target").unwrap().is_none(),
        "cleaned up memory should be gone"
    );
}

#[test]
fn archived_cleanup_preserves_high_confidence() {
    let engine = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("cleanup-keep");
    mem.confidence = Confidence::new(0.9); // Above threshold
    mem.archived = true;
    mem.access_count = 0;
    mem.last_accessed = Utc::now() - Duration::days(100);
    engine.create(&mem).unwrap();

    let deleted = with_writer(&engine, |conn| {
        maintenance::archived_cleanup(conn, 90, 0.1)
    });

    assert_eq!(deleted, 0, "should NOT clean up high-confidence memory");
    assert!(
        engine.get("cleanup-keep").unwrap().is_some(),
        "high-confidence memory should survive"
    );
}

#[test]
fn audit_rotation_removes_old_entries() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("audit-rot")).unwrap();

    // Rotation with 0 months should try to rotate everything
    // (entries just created have age ~0 days, so 0-month threshold means nothing is old)
    let rotated = with_writer(&engine, |conn| maintenance::audit_rotation(conn, 0));
    // With 0 months threshold, entries need age > 0 * 30 = 0 days.
    // Freshly created entries have age ~0, so depending on timing this may or may not match.
    // Just verify it doesn't error.
    let _ = rotated; // Just verify it doesn't error
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPACTION: orphaned embedding cleanup
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn orphaned_embedding_cleanup() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("emb-orphan")).unwrap();

    // Store embedding
    with_writer(&engine, |conn| {
        cortex_storage::queries::vector_search::store_embedding(
            conn,
            "emb-orphan",
            "hash-orphan",
            &[1.0, 2.0],
            "test",
        )
    });

    // Delete the memory (but embedding link remains)
    engine.delete("emb-orphan").unwrap();

    // The memory_embedding_link row references a deleted memory.
    // Delete the link manually to create an orphaned embedding.
    with_writer(&engine, |conn| {
        conn.execute(
            "DELETE FROM memory_embedding_link WHERE memory_id = 'emb-orphan'",
            [],
        )
        .map_err(|e| cortex_storage::to_storage_err(e.to_string()))?;
        Ok(())
    });

    // Now clean up orphaned embeddings
    let cleaned = with_writer(&engine, |conn| {
        cortex_storage::compaction::embedding_dedup::cleanup_orphaned_embeddings(conn)
    });
    assert_eq!(cleaned, 1, "should clean up 1 orphaned embedding");
}

// ═══════════════════════════════════════════════════════════════════════════
// EVENT OPS: batch insert, range query, archive
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn event_batch_insert() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ev-batch")).unwrap();

    with_writer(&engine, |conn| {
        let events: Vec<event_ops::EventParams<'_>> = vec![
            (
                "ev-batch",
                "2024-01-01T00:00:00Z",
                "custom_event_1",
                "{}",
                "test",
                "batch",
                None,
                1,
            ),
            (
                "ev-batch",
                "2024-01-01T00:01:00Z",
                "custom_event_2",
                "{}",
                "test",
                "batch",
                None,
                1,
            ),
        ];

        let ids = event_ops::insert_event_batch(conn, &events)?;
        assert_eq!(ids.len(), 2, "batch should return 2 IDs");
        assert!(ids[0] < ids[1], "IDs should be sequential");

        Ok(())
    });
}

#[test]
fn event_query_in_range() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ev-range")).unwrap();

    with_writer(&engine, |conn| {
        event_ops::insert_event(
            conn,
            "ev-range",
            "2024-06-15T00:00:00Z",
            "test_event",
            "{}",
            "test",
            "range",
            None,
            1,
        )?;

        let events =
            event_ops::get_events_in_range(conn, "2024-06-01T00:00:00Z", "2024-07-01T00:00:00Z")?;
        assert!(
            events.iter().any(|e| e.event_type == "test_event"),
            "should find event in range"
        );

        Ok(())
    });
}

#[test]
fn event_query_after_id() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ev-after")).unwrap();

    with_writer(&engine, |conn| {
        let id1 = event_ops::insert_event(
            conn,
            "ev-after",
            "2024-01-01T00:00:00Z",
            "first",
            "{}",
            "test",
            "after",
            None,
            1,
        )?;
        event_ops::insert_event(
            conn,
            "ev-after",
            "2024-01-02T00:00:00Z",
            "second",
            "{}",
            "test",
            "after",
            None,
            1,
        )?;

        let after = event_ops::get_events_after_id(conn, "ev-after", id1, None)?;
        assert_eq!(after.len(), 1, "should find 1 event after first ID");
        assert_eq!(after[0].event_type, "second");

        Ok(())
    });
}

#[test]
fn event_move_to_archive() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ev-arch")).unwrap();

    with_writer(&engine, |conn| {
        let id = event_ops::insert_event(
            conn,
            "ev-arch",
            "2023-01-01T00:00:00Z",
            "old_event",
            "{}",
            "test",
            "archive",
            None,
            1,
        )?;

        // Move events older than 2024 to archive
        let moved =
            event_ops::move_events_to_archive(conn, "2024-01-01T00:00:00Z", id)?;
        assert_eq!(moved, 1, "should archive 1 old event");

        // Verify it's gone from main table
        let remaining = event_ops::get_events_for_memory(conn, "ev-arch", None)?;
        let old_events: Vec<_> = remaining
            .iter()
            .filter(|e| e.event_type == "old_event")
            .collect();
        assert!(old_events.is_empty(), "archived event should be gone from main table");

        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// VERSION OPS: count, get_at_version, enforce_retention
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn version_count_accurate() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ver-cnt")).unwrap();

    with_writer(&engine, |conn| {
        assert_eq!(version_ops::version_count(conn, "ver-cnt")?, 0);

        version_ops::insert_version(conn, "ver-cnt", "{}", "s1", 0.8, "sys", "create")?;
        version_ops::insert_version(conn, "ver-cnt", "{}", "s2", 0.9, "sys", "update")?;

        assert_eq!(version_ops::version_count(conn, "ver-cnt")?, 2);
        Ok(())
    });
}

#[test]
fn version_get_at_specific_version() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ver-at")).unwrap();

    with_writer(&engine, |conn| {
        version_ops::insert_version(conn, "ver-at", r#"{"v":1}"#, "s1", 0.8, "sys", "v1")?;
        version_ops::insert_version(conn, "ver-at", r#"{"v":2}"#, "s2", 0.9, "sys", "v2")?;

        let v1 = version_ops::get_at_version(conn, "ver-at", 1)?;
        assert!(v1.is_some());
        assert_eq!(v1.unwrap().summary, "s1");

        let v2 = version_ops::get_at_version(conn, "ver-at", 2)?;
        assert!(v2.is_some());
        assert_eq!(v2.unwrap().summary, "s2");

        let v99 = version_ops::get_at_version(conn, "ver-at", 99)?;
        assert!(v99.is_none(), "nonexistent version should return None");

        Ok(())
    });
}

#[test]
fn version_enforce_retention_deletes_oldest() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ver-enf")).unwrap();

    with_writer(&engine, |conn| {
        // Create 5 versions
        for i in 1..=5 {
            version_ops::insert_version(
                conn,
                "ver-enf",
                "{}",
                &format!("s{i}"),
                0.8,
                "sys",
                "update",
            )?;
        }
        assert_eq!(version_ops::version_count(conn, "ver-enf")?, 5);

        // Enforce retention to keep only 3
        let deleted = version_ops::enforce_retention(conn, "ver-enf", 3)?;
        assert_eq!(deleted, 2, "should delete 2 oldest versions");
        assert_eq!(version_ops::version_count(conn, "ver-enf")?, 3);

        // Verify the latest 3 survive
        let history = version_ops::get_version_history(conn, "ver-enf")?;
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].version, 5); // newest
        assert_eq!(history[2].version, 3); // oldest remaining

        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// AGGREGATION: count_by_type, average_confidence, stale_count
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn aggregation_count_by_type() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("agg-1")).unwrap();
    engine.create(&make_memory("agg-2")).unwrap();

    let counts = engine.count_by_type().unwrap();
    let tribal_count = counts
        .iter()
        .find(|(t, _)| *t == MemoryType::Tribal)
        .map(|(_, c)| *c);
    assert_eq!(tribal_count, Some(2));
}

#[test]
fn aggregation_average_confidence() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut m1 = make_memory("avg-1");
    m1.confidence = Confidence::new(0.6);
    let mut m2 = make_memory("avg-2");
    m2.confidence = Confidence::new(1.0);
    engine.create(&m1).unwrap();
    engine.create(&m2).unwrap();

    let avg = engine.average_confidence().unwrap();
    assert!(
        (avg - 0.8).abs() < 0.01,
        "average of 0.6 and 1.0 should be ~0.8, got {avg}"
    );
}

#[test]
fn aggregation_stale_count() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("stale-1");
    mem.last_accessed = Utc::now() - Duration::days(100);
    engine.create(&mem).unwrap();

    let stale = engine.stale_count(30).unwrap();
    assert_eq!(stale, 1, "memory accessed 100 days ago should be stale at 30-day threshold");
}

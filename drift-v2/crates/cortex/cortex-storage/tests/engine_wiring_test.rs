//! Phase C engine wiring tests (C-23, C-24, C-25).
//!
//! Verify health data queries, read pool distribution, and WAL checkpoint.


use chrono::{Duration, Utc};
use cortex_core::memory::*;
use cortex_core::traits::{ICausalStorage, IMemoryStorage};
use cortex_storage::StorageEngine;

fn make_memory(id: &str, confidence: f64, archived: bool) -> BaseMemory {
    let now = Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: format!("observation for {id}"),
        evidence: vec![],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Insight,
        content: tc.clone(),
        summary: format!("memory {id}"),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(confidence),
        importance: Importance::Normal,
        last_accessed: if archived {
            now - Duration::days(180)
        } else {
            now
        },
        access_count: 1,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&tc).unwrap(),
    }
}

/// C-23: Health snapshot has real values — insert 10 memories (3 archived) → verify counts.
#[test]
fn c23_health_snapshot_real_values() {
    let storage = StorageEngine::open_in_memory().expect("in-memory storage");

    // Insert 7 active memories (high confidence).
    for i in 0..7 {
        let mem = make_memory(&format!("active-{i}"), 0.8, false);
        storage.create(&mem).expect("create");
    }

    // Insert 3 archived memories (low confidence).
    for i in 0..3 {
        let mem = make_memory(&format!("archived-{i}"), 0.1, true);
        storage.create(&mem).expect("create");
    }

    // count_by_type only counts active (non-archived) memories.
    let type_counts = storage.count_by_type().expect("count_by_type");
    let active_count: usize = type_counts.iter().map(|(_, c)| c).sum();
    assert_eq!(active_count, 7, "should have 7 active memories (3 archived excluded)");

    // Verify average_confidence is reasonable (computed from active memories only).
    let avg = storage.average_confidence().expect("avg confidence");
    assert!(avg > 0.5, "average confidence of active memories should be > 0.5");
    assert!(avg < 1.0, "average confidence should be < 1.0");

    // Verify stale_count finds old memories (stale = not accessed in 30+ days, non-archived).
    // Our archived memories have last_accessed 180 days ago but are archived=true,
    // so stale_count (which filters archived=0) should return 0 for active memories
    // (since active memories were accessed "now").
    let stale = storage.stale_count(30).expect("stale count");
    assert_eq!(
        stale, 0,
        "active memories were accessed recently, stale count should be 0, got {stale}"
    );

    // Verify we can retrieve individual archived memories by ID.
    for i in 0..3 {
        let found = storage.get(&format!("archived-{i}")).expect("get archived");
        assert!(found.is_some(), "archived memory should be retrievable by ID");
        assert!(found.unwrap().archived, "memory should be marked archived");
    }
}

/// C-24: Read pool distributes reads in file-backed mode.
#[test]
fn c24_read_pool_distributes_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("read-pool-test.db");
    let storage = StorageEngine::open(&db_path).expect("open");

    // Insert some data.
    for i in 0..10 {
        let mem = make_memory(&format!("read-pool-{i}"), 0.7, false);
        storage.create(&mem).expect("create");
    }

    // Perform 100 reads. These should go through the read pool (not the writer).
    // We can't directly verify which connection was used, but we verify correctness.
    for i in 0..100 {
        let id = format!("read-pool-{}", i % 10);
        let found = storage.get(&id).expect("get");
        assert!(found.is_some(), "memory {id} should be found via read pool");
    }

    // Verify aggregate reads also work through read pool.
    let count = storage.count_by_type().expect("count");
    let total: usize = count.iter().map(|(_, c)| c).sum();
    assert_eq!(total, 10);

    // Verify causal reads also go through read pool.
    let edge_count = storage.edge_count().expect("edge_count");
    assert_eq!(edge_count, 0, "no causal edges inserted");

    let node_ids = storage.list_all_node_ids().expect("list_all_node_ids");
    assert!(node_ids.is_empty(), "no causal nodes");
}

/// C-25: Shutdown WAL checkpoint — write data, checkpoint, verify data persists.
#[test]
fn c25_shutdown_checkpoints_wal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("wal-checkpoint.db");

    // Write some data.
    {
        let storage = StorageEngine::open(&db_path).expect("open");
        for i in 0..5 {
            let mem = make_memory(&format!("wal-{i}"), 0.9, false);
            storage.create(&mem).expect("create");
        }

        // Checkpoint WAL (simulating what cortex_shutdown does).
        storage
            .pool()
            .writer
            .with_conn_sync(|conn| {
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                    .map_err(|e| {
                        cortex_core::errors::CortexError::StorageError(
                            cortex_core::errors::StorageError::SqliteError {
                                message: format!("checkpoint failed: {e}"),
                            },
                        )
                    })
            })
            .expect("checkpoint should succeed");
    }
    // StorageEngine dropped here.

    // Re-open and verify data survived.
    {
        let storage = StorageEngine::open(&db_path).expect("re-open");
        for i in 0..5 {
            let found = storage.get(&format!("wal-{i}")).expect("get after restart");
            assert!(found.is_some(), "memory wal-{i} should survive checkpoint + reopen");
        }
    }
}

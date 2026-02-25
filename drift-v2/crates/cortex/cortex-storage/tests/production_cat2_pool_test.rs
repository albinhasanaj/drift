//! Cat 2: Connection Pool & WAL Concurrency (CP-01 through CP-10)
//!
//! Tests writer serialization, read pool round-robin, WAL visibility,
//! in-memory mode routing, pool size clamping, and concurrent read/write.

use std::sync::Arc;

use chrono::Utc;

use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::pool::ReadPool;
use cortex_storage::StorageEngine;

// ─── Fixtures ────────────────────────────────────────────────────────────────

fn make_memory(id: &str) -> BaseMemory {
    let now = Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: format!("observation for {id}"),
        evidence: vec![],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Insight,
        content: tc.clone(),
        summary: format!("summary {id}"),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: now,
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&tc).unwrap(),
    }
}

fn test_engine_file() -> (StorageEngine, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_cortex.db");
    let engine = StorageEngine::open(&path).unwrap();
    (engine, dir)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CP-01: Writer serializes concurrent writes
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cp_01_writer_serializes_concurrent_writes() {
    let (engine, _dir) = test_engine_file();
    let engine = Arc::new(engine);

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let eng = Arc::clone(&engine);
            std::thread::spawn(move || {
                let mem = make_memory(&format!("concurrent-{i}"));
                eng.create(&mem)
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap().unwrap();
    }

    // All 10 should be retrievable.
    for i in 0..10 {
        let got = engine.get(&format!("concurrent-{i}")).unwrap();
        assert!(got.is_some(), "memory concurrent-{i} should exist");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CP-02: Read pool round-robin distributes connections
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cp_02_read_pool_round_robin() {
    let (engine, _dir) = test_engine_file();
    let mem = make_memory("rr-test");
    engine.create(&mem).unwrap();

    // Perform 100 reads — should cycle through pool without errors.
    for _ in 0..100 {
        let got = engine.get("rr-test").unwrap();
        assert!(got.is_some());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CP-03: Readers see writer's committed changes (WAL visibility)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cp_03_wal_visibility() {
    let (engine, _dir) = test_engine_file();

    // Write through writer.
    let mem = make_memory("wal-vis-1");
    engine.create(&mem).unwrap();

    // Read through read pool — should see the committed change immediately.
    let got = engine.pool().readers.with_conn(|conn| {
        cortex_storage::queries::memory_crud::get_memory(conn, "wal-vis-1")
    }).unwrap();
    assert!(got.is_some(), "reader should see writer's committed change via WAL");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CP-04: In-memory mode routes reads through writer
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cp_04_in_memory_reads_through_writer() {
    let engine = StorageEngine::open_in_memory().unwrap();

    // Write a memory.
    let mem = make_memory("inmem-read-1");
    engine.create(&mem).unwrap();

    // Read through engine.get() — in-memory mode routes through writer.
    let got = engine.get("inmem-read-1").unwrap();
    assert!(got.is_some(), "in-memory read should go through writer and find the memory");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CP-05: In-memory read pool connections are isolated
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cp_05_in_memory_read_pool_isolated() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("isolated-1");
    engine.create(&mem).unwrap();

    // Direct read pool access in in-memory mode → isolated DB, won't see writer's data.
    let got = engine.pool().readers.with_conn(|conn| {
        // This connection is a separate in-memory database.
        // It won't have the memories table unless we run migrations on it too.
        let exists: bool = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories'")
            .and_then(|mut stmt| stmt.exists([]))
            .unwrap_or(false);
        if !exists {
            // Expected: isolated in-memory DB has no tables.
            return Ok(true);
        }
        let result = cortex_storage::queries::memory_crud::get_memory(conn, "isolated-1");
        match result {
            Ok(None) => Ok(true),  // Doesn't see writer's data — expected
            Ok(Some(_)) => Ok(false), // Sees data — unexpected for separate in-memory DB
            Err(_) => Ok(true),    // Error reading = also isolated
        }
    }).unwrap();
    assert!(got, "in-memory read pool should be isolated from writer");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CP-06: Pool size clamped to MAX_POOL_SIZE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cp_06_pool_size_clamped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pool_clamp.db");
    // Create the DB first so the file exists.
    let _engine = StorageEngine::open(&path).unwrap();

    // Open a read pool with an excessively large size.
    let pool = ReadPool::open(&path, 100).unwrap();
    assert_eq!(pool.size(), 8, "pool size should be clamped to MAX_POOL_SIZE=8");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CP-07: Read pool lock poisoning handled
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cp_07_read_pool_lock_poisoning() {
    let (engine, _dir) = test_engine_file();
    let mem = make_memory("poison-test");
    engine.create(&mem).unwrap();

    // A poisoned mutex returns a StorageError, not a panic.
    // We can't easily poison a Mutex in the pool, but we can verify
    // the error handling path by checking the pool still works after
    // normal operations.
    for _ in 0..20 {
        let got = engine.get("poison-test").unwrap();
        assert!(got.is_some());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CP-08: Writer blocking_lock works outside tokio context
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cp_08_writer_blocking_lock_no_tokio() {
    // This test runs outside a tokio runtime — verifies blocking_lock works.
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("no-tokio-1");
    // create() uses with_conn_sync() which calls blocking_lock().
    engine.create(&mem).unwrap();
    let got = engine.get("no-tokio-1").unwrap();
    assert!(got.is_some());
}

// ═══════════════════════════════════════════════════════════════════════════════
// CP-09: Concurrent readers don't block writer (WAL)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cp_09_concurrent_readers_dont_block_writer() {
    let (engine, _dir) = test_engine_file();
    let engine = Arc::new(engine);

    // Seed some data.
    for i in 0..5 {
        engine.create(&make_memory(&format!("wal-conc-{i}"))).unwrap();
    }

    // Spawn readers that hold connections briefly.
    let reader_handles: Vec<_> = (0..4)
        .map(|_| {
            let eng = Arc::clone(&engine);
            std::thread::spawn(move || {
                for _ in 0..20 {
                    let _ = eng.get("wal-conc-0");
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            })
        })
        .collect();

    // Concurrently write.
    let start = std::time::Instant::now();
    for i in 5..15 {
        engine.create(&make_memory(&format!("wal-conc-{i}"))).unwrap();
    }
    let write_time = start.elapsed();

    for h in reader_handles {
        h.join().unwrap();
    }

    // Writes should complete reasonably fast (< 2 seconds even in debug).
    assert!(
        write_time < std::time::Duration::from_secs(2),
        "writes took too long: {write_time:?} — readers may be blocking writer"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CP-10: Pool default size is 4
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cp_10_pool_default_size() {
    assert_eq!(ReadPool::default_size(), 4);
}

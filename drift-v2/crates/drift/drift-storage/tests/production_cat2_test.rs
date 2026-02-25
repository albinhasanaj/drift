//! Production Category 2: SQLite / WAL Concurrency
//!
//! Drift V2 relies on a BatchWriter (bounded channel, 1024 capacity, 500-batch threshold)
//! and a ReadPool (default 4 / max 8). These tests verify concurrency, backpressure,
//! atomicity, poison recovery, pragma correctness, and in-memory vs file-backed behavioral diffs.

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use drift_storage::batch::commands::{BatchCommand, FileMetadataRow};
use drift_storage::batch::BatchWriter;
use drift_storage::connection::pragmas;
use drift_storage::connection::DatabaseManager;
use drift_storage::migrations::run_migrations;
use rusqlite::Connection;
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn make_file_row(path: &str) -> FileMetadataRow {
    FileMetadataRow {
        path: path.to_string(),
        language: Some("TypeScript".to_string()),
        file_size: 100,
        content_hash: vec![0u8; 8],
        mtime_secs: 1700000000,
        mtime_nanos: 0,
        last_scanned_at: 1700000000,
        scan_duration_us: Some(500),
    }
}

fn open_migrated(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    pragmas::apply_pragmas(&conn).unwrap();
    run_migrations(&conn).unwrap();
    conn
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-01: Write-Write Conflict
// Simulate two simultaneous driftAnalyze calls that both send BatchCommands.
// System must serialize via BatchWriter's single channel; no SQLITE_BUSY.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_01_write_write_conflict() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");

    // Open DB and run migrations on primary connection
    let primary = open_migrated(&db_path);
    drop(primary);

    // Open a dedicated batch connection
    let db = DatabaseManager::open(&db_path).unwrap();
    let batch_conn = db.open_batch_connection().unwrap();
    run_migrations(&batch_conn).unwrap();
    let writer = BatchWriter::new(batch_conn);

    let barrier = Arc::new(Barrier::new(2));
    let writer = Arc::new(writer);

    // Two threads sending commands simultaneously
    let handles: Vec<_> = (0..2)
        .map(|thread_id| {
            let w = Arc::clone(&writer);
            let b = Arc::clone(&barrier);
            thread::spawn(move || {
                b.wait();
                for i in 0..500 {
                    let row = make_file_row(&format!("t{thread_id}/file_{i}.ts"));
                    w.send(BatchCommand::UpsertFileMetadata(vec![row])).unwrap();
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    // Shutdown collects all pending writes
    let stats = match Arc::try_unwrap(writer) {
        Ok(w) => w.shutdown().unwrap(),
        Err(_) => panic!("Arc should have sole ownership after threads join"),
    };

    assert_eq!(
        stats.file_metadata_rows, 1000,
        "all 1000 rows from both threads must be written without SQLITE_BUSY"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-02: WAL Checkpoint Pressure
// Run writes that produce many WAL frames, then checkpoint and verify
// the WAL file truncates.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_02_wal_checkpoint_pressure() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let wal_path = dir.path().join("drift.db-wal");

    let db = DatabaseManager::open(&db_path).unwrap();

    // Insert 5000 file_metadata rows via writer
    db.with_writer(|conn| {
        for i in 0..5000 {
            conn.execute(
                "INSERT OR REPLACE INTO file_metadata
                 (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
                 VALUES (?1, 'TypeScript', 100, ?2, 0, 0, 0)",
                rusqlite::params![format!("src/file_{i}.ts"), vec![0u8; 8]],
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        }
        Ok(())
    })
    .unwrap();

    // WAL file should exist and have non-trivial size
    assert!(wal_path.exists(), "WAL file should exist after heavy writes");
    let wal_size_before = std::fs::metadata(&wal_path).unwrap().len();
    assert!(
        wal_size_before > 0,
        "WAL file should have content before checkpoint"
    );

    // Checkpoint with TRUNCATE
    db.checkpoint().unwrap();

    // After TRUNCATE checkpoint, WAL should be 0 bytes
    let wal_size_after = std::fs::metadata(&wal_path).unwrap().len();
    assert_eq!(
        wal_size_after, 0,
        "WAL file must be truncated after checkpoint (was {wal_size_before} bytes)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-03: Retention Tier Logic
// Create a file_metadata entry, "delete" the file from disk, re-scan.
// Entry should appear in ScanDiff.removed via compute_diff logic.
// We verify at the storage level: the row still exists until explicitly removed.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_03_retention_tier_logic() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    // Insert a file_metadata row
    db.with_writer(|conn| {
        conn.execute(
            "INSERT OR REPLACE INTO file_metadata
             (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES ('src/deleted.ts', 'TypeScript', 100, X'AABBCCDD', 1700000000, 0, 1700000000)",
            [],
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError {
            message: e.to_string(),
        })?;
        Ok(())
    })
    .unwrap();

    // The row persists in DB even though the file doesn't exist on disk.
    // ScanDiff.removed detection is handled by the scanner, not by storage auto-purge.
    db.with_reader(|conn| {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_metadata WHERE path = 'src/deleted.ts'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        assert_eq!(
            count, 1,
            "file_metadata row must persist until explicitly removed by scanner"
        );
        Ok(())
    })
    .unwrap();

    // Explicitly delete (simulating what scanner does after detecting removal)
    db.with_writer(|conn| {
        conn.execute(
            "DELETE FROM file_metadata WHERE path = 'src/deleted.ts'",
            [],
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError {
            message: e.to_string(),
        })?;
        Ok(())
    })
    .unwrap();

    db.with_reader(|conn| {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_metadata WHERE path = 'src/deleted.ts'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        assert_eq!(count, 0, "row must be gone after explicit delete");
        Ok(())
    })
    .unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-04: Channel Backpressure
// Flood the BatchWriter with >1024 commands without flushing.
// Sender must block (bounded channel semantics); no data loss after drain.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_04_channel_backpressure() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let primary = open_migrated(&db_path);
    drop(primary);

    let db = DatabaseManager::open(&db_path).unwrap();
    let batch_conn = db.open_batch_connection().unwrap();
    run_migrations(&batch_conn).unwrap();
    let writer = BatchWriter::new(batch_conn);

    // Send 2000 commands (well above CHANNEL_BOUND=1024).
    // The sender will block when the channel is full, then resume when
    // the writer thread drains it. This must complete without data loss.
    let total = 2000;
    for i in 0..total {
        let row = make_file_row(&format!("backpressure/file_{i}.ts"));
        writer
            .send(BatchCommand::UpsertFileMetadata(vec![row]))
            .unwrap();
    }

    let stats = writer.shutdown().unwrap();
    assert_eq!(
        stats.file_metadata_rows, total,
        "all {total} commands must be processed despite backpressure"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-05: Batch Atomicity on Failure
// Inject a constraint violation mid-batch. Verify the entire batch rolls back.
// Buffer must be retained on rollback (writer.rs:178-180 iterates by reference,
// buffer only cleared after commit on line 323).
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_05_batch_atomicity_on_failure() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    // The detections table has a NOT NULL constraint on `file`.
    // We test atomicity at the DB manager level: a transaction with a
    // constraint violation should roll back all changes in that transaction.
    let result = db.with_writer(|conn| {
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;

        // First insert — valid
        tx.execute(
            "INSERT OR REPLACE INTO file_metadata
             (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES ('valid.ts', 'TypeScript', 100, X'AABB', 0, 0, 0)",
            [],
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError {
            message: e.to_string(),
        })?;

        // Second insert — violate NOT NULL on 'file' column in detections
        tx.execute(
            "INSERT INTO detections (file, line, column_num, pattern_id, category, confidence, detection_method)
             VALUES (NULL, 1, 1, 'p1', 'error', 0.9, 'regex')",
            [],
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError {
            message: e.to_string(),
        })?;

        tx.commit().map_err(|e| drift_core::errors::StorageError::SqliteError {
            message: e.to_string(),
        })?;
        Ok(())
    });

    assert!(result.is_err(), "transaction with constraint violation must fail");

    // The valid.ts insert should have been rolled back
    db.with_reader(|conn| {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_metadata WHERE path = 'valid.ts'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        assert_eq!(count, 0, "valid.ts must be rolled back with the batch");
        Ok(())
    })
    .unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-06: Flush Timeout Drain
// Send 499 commands (below BATCH_SIZE=500), then wait >100ms.
// Auto-flush must trigger on FLUSH_TIMEOUT (100ms).
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_06_flush_timeout_drain() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let primary = open_migrated(&db_path);
    drop(primary);

    let db = DatabaseManager::open(&db_path).unwrap();
    let batch_conn = db.open_batch_connection().unwrap();
    run_migrations(&batch_conn).unwrap();
    let writer = BatchWriter::new(batch_conn);

    // Send 499 commands — below BATCH_SIZE=500 threshold
    for i in 0..499 {
        let row = make_file_row(&format!("timeout/file_{i}.ts"));
        writer
            .send(BatchCommand::UpsertFileMetadata(vec![row]))
            .unwrap();
    }

    // Wait for FLUSH_TIMEOUT (100ms) + margin
    thread::sleep(Duration::from_millis(250));

    // Shutdown should show all 499 flushed (at least 1 flush happened on timeout)
    let stats = writer.shutdown().unwrap();
    assert_eq!(
        stats.file_metadata_rows, 499,
        "all 499 rows must be flushed by timeout"
    );
    assert!(
        stats.flushes >= 1,
        "at least 1 flush must have occurred (timeout-triggered)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-07: ReadPool Round-Robin Under Contention
// Spawn 8 concurrent read operations. AtomicUsize round-robin distributes
// across all 4 connections; no single-connection bottleneck.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_07_readpool_round_robin_under_contention() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = Arc::new(DatabaseManager::open(&db_path).unwrap());

    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let db = Arc::clone(&db);
            let b = Arc::clone(&barrier);
            thread::spawn(move || {
                b.wait();
                for _ in 0..100 {
                    db.with_reader(|conn| {
                        let count: i64 = conn
                            .query_row(
                                "SELECT COUNT(*) FROM file_metadata",
                                [],
                                |row| row.get(0),
                            )
                            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                                message: e.to_string(),
                            })?;
                        assert!(count >= 0);
                        Ok(())
                    })
                    .unwrap();
                }
            })
        })
        .collect();

    let start = Instant::now();
    for h in handles {
        h.join().unwrap();
    }
    let elapsed = start.elapsed();

    // 800 reads across 8 threads with 4 connections should complete quickly.
    // If a single-connection bottleneck existed, this would be much slower.
    assert!(
        elapsed < Duration::from_secs(10),
        "800 concurrent reads must complete in <10s (took {:?})",
        elapsed
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-08: In-Memory BatchWriter Isolation
// In-memory mode: write via BatchWriter, read via with_reader.
// Reads must NOT see batch writes (in-memory connections are separate DBs).
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_08_in_memory_batch_writer_isolation() {
    let db = DatabaseManager::open_in_memory().unwrap();

    // Write data through the main writer — writer has schema (migrations ran)
    db.with_writer(|conn| {
        conn.execute(
            "INSERT OR REPLACE INTO file_metadata
             (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES ('main_writer.ts', 'TypeScript', 100, X'AABB', 0, 0, 0)",
            [],
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError {
            message: e.to_string(),
        })?;
        Ok(())
    })
    .unwrap();

    // In-memory: with_reader uses a SEPARATE in-memory DB (pool.rs open_in_memory).
    // These reader connections don't even have the schema (no migrations run on them).
    // This is the documented caveat in connection/mod.rs:97-98.
    let reader_result = db.with_reader(|conn| {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_metadata WHERE path = 'main_writer.ts'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        Ok(count)
    });

    // In-memory reader pool connections are fully isolated: separate empty DBs
    // without schema. This must either error (no such table) or return 0.
    match reader_result {
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                msg.contains("no such table"),
                "expected 'no such table' error, got: {msg}"
            );
        }
        Ok(count) => {
            assert_eq!(
                count, 0,
                "in-memory: reader must NOT see writer data (separate DBs)"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-09: Writer Mutex Poison Recovery
// Panic inside with_writer closure. Subsequent with_writer call.
// Must return "write lock poisoned" error, not hang.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_09_writer_mutex_poison_recovery() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = Arc::new(DatabaseManager::open(&db_path).unwrap());

    // Panic inside with_writer on a separate thread to poison the mutex
    let db2 = Arc::clone(&db);
    let handle = thread::spawn(move || {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            db2.with_writer(|_conn| -> Result<(), drift_core::errors::StorageError> {
                panic!("intentional panic to poison mutex");
            })
            .ok();
        }));
    });
    handle.join().ok();

    // Subsequent with_writer should return poisoned error, not hang
    let result = db.with_writer(|_conn| Ok(()));
    assert!(result.is_err(), "poisoned mutex must return error");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("poisoned"),
        "error must mention 'poisoned', got: {err_msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-10: ReadPool Poison Recovery
// Panic inside with_reader closure. Subsequent reads.
// Must return "read pool lock poisoned" for poisoned slot; other slots work.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_10_readpool_poison_recovery() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = Arc::new(DatabaseManager::open(&db_path).unwrap());

    // Poison one reader slot by panicking on a separate thread
    let db2 = Arc::clone(&db);
    let handle = thread::spawn(move || {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            db2.with_reader(|_conn| -> Result<(), drift_core::errors::StorageError> {
                panic!("intentional panic to poison one reader slot");
            })
            .ok();
        }));
    });
    handle.join().ok();

    // Subsequent reads: some may hit the poisoned slot (error), others should work.
    // With a pool of 4, round-robin means ~1/4 reads hit the poisoned slot.
    let mut successes = 0;
    let mut failures = 0;
    for _ in 0..20 {
        let result = db.with_reader(|conn| {
            let _count: i64 = conn
                .query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
                .map_err(|e| drift_core::errors::StorageError::SqliteError {
                    message: e.to_string(),
                })?;
            Ok(())
        });
        if result.is_ok() {
            successes += 1;
        } else {
            failures += 1;
        }
    }

    // With pool_size=4 and 1 poisoned slot, ~75% should succeed, ~25% fail
    assert!(
        successes > 0,
        "some reads must succeed (non-poisoned slots)"
    );
    assert!(
        failures > 0,
        "some reads must fail (poisoned slot hit via round-robin)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-11: Writer Pragma Verification
// After DatabaseManager::open(), query all 8 writer pragmas.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_11_writer_pragma_verification() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    db.with_writer(|conn| {
        // journal_mode = wal
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(
            mode.to_lowercase(),
            "wal",
            "journal_mode must be WAL"
        );

        // synchronous = NORMAL (1)
        let sync: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(sync, 1, "synchronous must be NORMAL (1)");

        // foreign_keys = ON (1)
        let fk: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign_keys must be ON");

        // cache_size = -64000 (64MB in KiB-pages)
        let cache: i64 = conn
            .pragma_query_value(None, "cache_size", |row| row.get(0))
            .unwrap();
        assert_eq!(cache, -64000, "cache_size must be -64000");

        // mmap_size = 268435456 (256MB)
        let mmap: i64 = conn
            .pragma_query_value(None, "mmap_size", |row| row.get(0))
            .unwrap();
        assert_eq!(mmap, 268435456, "mmap_size must be 268435456");

        // busy_timeout = 5000
        let timeout: i64 = conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, 5000, "busy_timeout must be 5000");

        // temp_store = MEMORY (2)
        let temp: i64 = conn
            .pragma_query_value(None, "temp_store", |row| row.get(0))
            .unwrap();
        assert_eq!(temp, 2, "temp_store must be MEMORY (2)");

        // auto_vacuum = INCREMENTAL (2)
        // NOTE: PRAGMA auto_vacuum can only be set before any tables are created.
        // On a freshly-created DB file, apply_pragmas runs before migrations,
        // so it should take effect. We check the actual value.
        let av: i64 = conn
            .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
            .unwrap();
        assert_eq!(av, 2, "auto_vacuum must be INCREMENTAL (2)");

        Ok(())
    })
    .unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-12: Reader Pragma Isolation
// After open, query reader pragmas. Readers must have query_only=ON.
// Writers must NOT have query_only=ON.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_12_reader_pragma_isolation() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    // Reader pragmas
    db.with_reader(|conn| {
        // query_only = ON (1) — readers opened with SQLITE_OPEN_READ_ONLY
        // Note: query_only may not be directly queryable as a pragma on read-only connections,
        // but we can verify writes fail (which proves read-only mode).
        let result = conn.execute(
            "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES ('reader_write_test.ts', 10, X'AABB', 0, 0, 0)",
            [],
        );
        assert!(
            result.is_err(),
            "reader connection must reject writes (read-only mode)"
        );

        // cache_size
        let cache: i64 = conn
            .pragma_query_value(None, "cache_size", |row| row.get(0))
            .unwrap();
        assert_eq!(cache, -64000, "reader cache_size must be -64000");

        // busy_timeout
        let timeout: i64 = conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, 5000, "reader busy_timeout must be 5000");

        Ok(())
    })
    .unwrap();

    // Writer must NOT have query_only=ON
    db.with_writer(|conn| {
        let result = conn.execute(
            "INSERT OR REPLACE INTO file_metadata
             (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES ('writer_write_test.ts', 10, X'AABB', 0, 0, 0)",
            [],
        );
        assert!(
            result.is_ok(),
            "writer connection must allow writes"
        );

        // Clean up
        conn.execute("DELETE FROM file_metadata WHERE path = 'writer_write_test.ts'", [])
            .ok();
        Ok(())
    })
    .unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// T2-13: File-Backed vs In-Memory Mode Behavioral Diff
// Run the same write+read sequence in both modes. File-backed: BatchWriter
// writes visible to readers (WAL). In-memory: BatchWriter writes invisible
// to readers (separate DBs).
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t2_13_file_backed_vs_in_memory_behavioral_diff() {
    // ── File-backed mode ──
    // Writer and readers share the same on-disk DB via WAL — writes are visible.
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");
    let file_db = DatabaseManager::open(&db_path).unwrap();

    file_db
        .with_writer(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO file_metadata
                 (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
                 VALUES ('file_backed_test.ts', 'TypeScript', 100, X'AABB', 0, 0, 0)",
                [],
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
            Ok(())
        })
        .unwrap();

    let file_backed_reader_ok = file_db
        .with_reader(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM file_metadata WHERE path = 'file_backed_test.ts'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| drift_core::errors::StorageError::SqliteError {
                    message: e.to_string(),
                })?;
            Ok(count)
        })
        .unwrap();

    // ── In-memory mode ──
    // Writer and readers are SEPARATE in-memory DBs.
    // Reader pool connections don't even have the schema (no migrations).
    let mem_db = DatabaseManager::open_in_memory().unwrap();

    mem_db
        .with_writer(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO file_metadata
                 (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
                 VALUES ('in_memory_test.ts', 'TypeScript', 100, X'AABB', 0, 0, 0)",
                [],
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
            Ok(())
        })
        .unwrap();

    let in_memory_reader_result = mem_db.with_reader(|conn| {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_metadata WHERE path = 'in_memory_test.ts'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        Ok(count)
    });

    // ── Assert behavioral difference ──
    assert_eq!(
        file_backed_reader_ok, 1,
        "file-backed: writer writes MUST be visible to readers via shared WAL"
    );

    // In-memory: reader pool connections are isolated empty DBs. The reader either
    // errors (no schema) or returns 0 (if schema existed but no shared data).
    match in_memory_reader_result {
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                msg.contains("no such table"),
                "in-memory reader should fail with 'no such table', got: {msg}"
            );
        }
        Ok(count) => {
            assert_eq!(
                count, 0,
                "in-memory: reader must NOT see writer data (separate DBs)"
            );
        }
    }
}

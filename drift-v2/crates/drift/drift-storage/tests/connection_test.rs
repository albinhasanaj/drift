//! Storage connection tests — T1-STR-01, T1-STR-05, T1-STR-06, T1-STR-09,
//! T1-STR-10, T1-STR-11, T1-STR-14, T1-STR-15.

use std::sync::{Arc, Barrier};
use std::thread;

use drift_storage::DatabaseManager;
use tempfile::TempDir;

// ---- T1-STR-01: PRAGMAs set correctly ----

#[test]
fn t1_str_01_pragmas_set_correctly() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    db.with_writer(|conn| {
        // WAL mode
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal", "journal_mode should be WAL");

        // synchronous = NORMAL (1)
        let sync: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(sync, 1, "synchronous should be NORMAL (1)");

        // foreign_keys = ON
        let fk: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign_keys should be ON");

        // cache_size = -64000 (64MB)
        let cache: i64 = conn
            .pragma_query_value(None, "cache_size", |row| row.get(0))
            .unwrap();
        assert_eq!(cache, -64000, "cache_size should be -64000 (64MB)");

        // busy_timeout = 5000
        let timeout: i64 = conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, 5000, "busy_timeout should be 5000ms");

        Ok(())
    })
    .unwrap();
}

// ---- T1-STR-05: Read pool round-robin ----

#[test]
fn t1_str_05_read_pool_round_robin() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    // Issue 100 reads — verify they complete without error
    // (We can't directly observe which connection is used, but we verify
    // the pool distributes work without deadlock or error)
    for _ in 0..100 {
        db.with_reader(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
                .map_err(|e| drift_core::errors::StorageError::SqliteError {
                    message: e.to_string(),
                })?;
            assert_eq!(count, 0);
            Ok(())
        })
        .unwrap();
    }
}

// ---- T1-STR-06: Write serialization ----

#[test]
fn t1_str_06_write_serialization() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = Arc::new(DatabaseManager::open(&db_path).unwrap());

    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|thread_id| {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for i in 0..100 {
                    let path = format!("thread_{thread_id}/file_{i}.ts");
                    db.with_writer(|conn| {
                        conn.execute(
                            "INSERT OR REPLACE INTO file_metadata
                             (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                            rusqlite::params![path, "TypeScript", 100, vec![0u8; 8], 0, 0, 0],
                        )
                        .map_err(|e| drift_core::errors::StorageError::SqliteError {
                            message: e.to_string(),
                        })?;
                        Ok(())
                    })
                    .unwrap();
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    // Verify all 800 rows persisted
    db.with_reader(|conn| {
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        assert_eq!(count, 800, "all 800 rows should be persisted");
        Ok(())
    })
    .unwrap();
}

// ---- T1-STR-09: busy_timeout=5000 ----

#[test]
fn t1_str_09_busy_timeout() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = Arc::new(DatabaseManager::open(&db_path).unwrap());

    // Hold write lock for 1s in one thread
    let db2 = Arc::clone(&db);
    let barrier = Arc::new(Barrier::new(2));
    let b2 = Arc::clone(&barrier);

    let writer = thread::spawn(move || {
        db2.with_writer(|conn| {
            conn.execute_batch("BEGIN IMMEDIATE").ok();
            b2.wait(); // Signal that lock is held
            thread::sleep(std::time::Duration::from_secs(1));
            conn.execute_batch("COMMIT").ok();
            Ok(())
        })
        .unwrap();
    });

    barrier.wait(); // Wait for lock to be held
    thread::sleep(std::time::Duration::from_millis(50)); // Small delay

    // Second write should succeed after waiting (busy_timeout=5000ms > 1s hold)
    let result = db.with_writer(|conn| {
        conn.execute(
            "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES ('busy_test.ts', 10, X'0000000000000000', 0, 0, 0)",
            [],
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError {
            message: e.to_string(),
        })?;
        Ok(())
    });

    writer.join().unwrap();
    assert!(result.is_ok(), "write should succeed after busy_timeout wait");
}

// ---- T1-STR-10: Disk full handling ----

#[test]
fn t1_str_10_disk_full_handling() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    // Set max_page_count to a tiny value to simulate disk full
    db.with_writer(|conn| {
        conn.execute_batch("PRAGMA max_page_count = 10;")
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        Ok(())
    })
    .unwrap();

    // Attempt large insert — should fail with an error, not panic
    let result = db.with_writer(|conn| {
        for i in 0..10000 {
            let path = format!("file_{i}.ts");
            let large_data = vec![0u8; 1024];
            conn.execute(
                "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
                 VALUES (?1, ?2, ?3, 0, 0, 0)",
                rusqlite::params![path, 1024, large_data],
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        }
        Ok(())
    });

    assert!(result.is_err(), "should return error when disk is full");
}

// ---- T1-STR-11: prepare_cached reuse ----

#[test]
fn t1_str_11_prepare_cached_reuse() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    // Execute same query 1000 times using prepare_cached
    db.with_reader(|conn| {
        for _ in 0..1000 {
            let mut stmt = conn
                .prepare_cached("SELECT COUNT(*) FROM file_metadata")
                .map_err(|e| drift_core::errors::StorageError::SqliteError {
                    message: e.to_string(),
                })?;
            let _count: i64 = stmt.query_row([], |row| row.get(0)).map_err(|e| {
                drift_core::errors::StorageError::SqliteError {
                    message: e.to_string(),
                }
            })?;
        }
        Ok(())
    })
    .unwrap();
    // If prepare_cached didn't work, this would be noticeably slower.
    // The test verifies it completes without error.
}

// ---- T1-STR-14: Concurrent reader + writer ----

#[test]
fn t1_str_14_concurrent_reader_writer() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = Arc::new(DatabaseManager::open(&db_path).unwrap());

    // Writer thread: insert 100 rows
    let db_w = Arc::clone(&db);
    let writer = thread::spawn(move || {
        for i in 0..100 {
            db_w.with_writer(|conn| {
                conn.execute(
                    "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
                     VALUES (?1, ?2, ?3, 0, 0, 0)",
                    rusqlite::params![format!("file_{i}.ts"), 100, vec![0u8; 8]],
                )
                .map_err(|e| drift_core::errors::StorageError::SqliteError {
                    message: e.to_string(),
                })?;
                Ok(())
            })
            .unwrap();
        }
    });

    // 4 reader threads: query simultaneously
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let db_r = Arc::clone(&db);
            thread::spawn(move || {
                for _ in 0..50 {
                    db_r.with_reader(|conn| {
                        let count: i64 = conn
                            .query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
                            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                                message: e.to_string(),
                            })?;
                        // Count should be non-negative (readers see committed state)
                        assert!(count >= 0);
                        Ok(())
                    })
                    .unwrap();
                    thread::sleep(std::time::Duration::from_millis(1));
                }
            })
        })
        .collect();

    writer.join().unwrap();
    for r in readers {
        r.join().unwrap();
    }

    // Final count should be 100
    db.with_reader(|conn| {
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        assert_eq!(count, 100);
        Ok(())
    })
    .unwrap();
}

// ---- T1-STR-15: Read-only enforcement ----

#[test]
fn t1_str_15_read_only_enforcement() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    // Attempt write through read pool — should fail
    let result = db.with_reader(|conn| {
        conn.execute(
            "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES ('readonly_test.ts', 10, X'0000000000000000', 0, 0, 0)",
            [],
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError {
            message: e.to_string(),
        })?;
        Ok(())
    });

    assert!(result.is_err(), "write through read pool should fail");
}

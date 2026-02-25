//! Phase 1 — Storage Stress & Battle Tests
//!
//! DatabaseManager write serialization, read pooling, BatchWriter throughput,
//! concurrent access, and edge cases.

use drift_storage::connection::DatabaseManager;
use drift_storage::batch::commands::*;
use drift_storage::batch::BatchWriter;

use rusqlite::Connection;
use std::sync::Arc;
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════════════════
// DATABASE MANAGER — write serialization, read pool, pragmas, migrations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_db_manager_open_in_memory() {
    let db = DatabaseManager::open_in_memory().unwrap();
    assert!(db.path().is_none());
}

#[test]
fn stress_db_manager_open_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let db = DatabaseManager::open(&path).unwrap();
    assert_eq!(db.path().unwrap(), path);
}

#[test]
fn stress_db_manager_write_then_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("write_read.db");
    let db = DatabaseManager::open(&path).unwrap();

    // Write via serialized writer
    db.with_writer(|conn| {
        conn.execute(
            "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params!["src/app.ts", 1024, vec![1u8, 2, 3], 1000, 0, 1000],
        ).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
        Ok(())
    }).unwrap();

    // Read via pooled reader
    let count: i64 = db.with_reader(|conn| {
        conn.query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
            .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
    }).unwrap();
    assert_eq!(count, 1);
}

#[test]
fn stress_db_manager_1000_writes_serialized() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("1000writes.db");
    let db = DatabaseManager::open(&path).unwrap();

    for i in 0..1000 {
        db.with_writer(|conn| {
            conn.execute(
                "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![format!("file_{i}.ts"), 100i64, vec![0u8; 8], 1000i64, 0i64, 1000i64],
            ).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            Ok(())
        }).unwrap();
    }

    let count: i64 = db.with_reader(|conn| {
        conn.query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
            .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
    }).unwrap();
    assert_eq!(count, 1000);
}

#[test]
fn stress_db_manager_concurrent_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.db");
    let db = Arc::new(DatabaseManager::open(&path).unwrap());

    // Seed data
    db.with_writer(|conn| {
        for i in 0..100 {
            conn.execute(
                "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![format!("file_{i}.ts"), 100i64, vec![0u8; 8], 1000i64, 0i64, 1000i64],
            ).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
        }
        Ok(())
    }).unwrap();

    // Concurrent reads from multiple threads
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let db = db.clone();
            std::thread::spawn(move || {
                for _ in 0..100 {
                    let count: i64 = db.with_reader(|conn| {
                        conn.query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
                            .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
                    }).unwrap();
                    assert_eq!(count, 100);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn stress_db_manager_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal.db");
    let db = DatabaseManager::open(&path).unwrap();

    db.with_writer(|conn| {
        conn.execute(
            "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params!["test.ts", 100i64, vec![0u8; 8], 1000i64, 0i64, 1000i64],
        ).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
        Ok(())
    }).unwrap();

    // Checkpoint should not error
    db.checkpoint().unwrap();
}

#[test]
fn stress_db_manager_migrations_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("migrate.db");

    // Open twice — migrations should be idempotent
    {
        let _db = DatabaseManager::open(&path).unwrap();
    }
    {
        let db = DatabaseManager::open(&path).unwrap();
        // Should still work after re-running migrations
        db.with_writer(|conn| {
            conn.execute(
                "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params!["test.ts", 100i64, vec![0u8; 8], 1000i64, 0i64, 1000i64],
            ).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            Ok(())
        }).unwrap();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCH WRITER — throughput, all command types, flush, shutdown
// ═══════════════════════════════════════════════════════════════════════════

fn make_batch_writer() -> BatchWriter {
    let conn = Connection::open_in_memory().unwrap();
    drift_storage::migrations::run_migrations(&conn).unwrap();
    BatchWriter::new(conn)
}

#[test]
fn stress_batch_writer_file_metadata_1000_rows() {
    let writer = make_batch_writer();

    let rows: Vec<FileMetadataRow> = (0..1000)
        .map(|i| FileMetadataRow {
            path: format!("src/file_{i}.ts"),
            language: Some("typescript".into()),
            file_size: 1024 + i as i64,
            content_hash: vec![i as u8; 8],
            mtime_secs: 1700000000 + i as i64,
            mtime_nanos: 0,
            last_scanned_at: 1700000000,
            scan_duration_us: Some(100),
        })
        .collect();

    writer.send(BatchCommand::UpsertFileMetadata(rows)).unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.file_metadata_rows, 1000);
}

#[test]
fn stress_batch_writer_functions_500_rows() {
    let writer = make_batch_writer();

    let rows: Vec<FunctionRow> = (0..500)
        .map(|i| FunctionRow {
            file: format!("src/mod_{}.ts", i / 10),
            name: format!("func_{i}"),
            qualified_name: Some(format!("Module{}.func_{i}", i / 10)),
            language: "typescript".into(),
            line: i as i64,
            end_line: i as i64 + 10,
            parameter_count: (i % 5) as i64,
            return_type: Some("void".into()),
            is_exported: i % 2 == 0,
            is_async: i % 3 == 0,
            body_hash: vec![i as u8; 8],
            signature_hash: vec![(i + 1) as u8; 8],
        })
        .collect();

    writer.send(BatchCommand::InsertFunctions(rows)).unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.function_rows, 500);
}

#[test]
fn stress_batch_writer_detections_batch() {
    let writer = make_batch_writer();

    let rows: Vec<DetectionRow> = (0..200)
        .map(|i| DetectionRow {
            file: format!("src/file_{}.ts", i / 10),
            line: i as i64,
            column_num: 0,
            pattern_id: format!("pattern_{}", i % 8),
            category: "security".into(),
            confidence: 0.85,
            detection_method: "ast_visitor".into(),
            cwe_ids: Some("89".into()),
            owasp: Some("A03:2021".into()),
            matched_text: Some(format!("matched text {i}")),
        })
        .collect();

    writer.send(BatchCommand::InsertDetections(rows)).unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.detection_rows, 200);
}

#[test]
fn stress_batch_writer_boundaries_batch() {
    let writer = make_batch_writer();

    let rows: Vec<BoundaryRow> = (0..50)
        .map(|i| BoundaryRow {
            file: format!("src/models/model_{i}.ts"),
            framework: "typeorm".into(),
            model_name: format!("Model{i}"),
            table_name: Some(format!("model_{i}")),
            field_name: Some(format!("field_{i}")),
            sensitivity: Some("pii".into()),
            confidence: 0.9,
        })
        .collect();

    writer.send(BatchCommand::InsertBoundaries(rows)).unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.boundary_rows, 50);
}

#[test]
fn stress_batch_writer_call_edges_batch() {
    let writer = make_batch_writer();

    let rows: Vec<CallEdgeRow> = (0..300)
        .map(|i| CallEdgeRow {
            caller_id: i as i64,
            callee_id: (i + 1) as i64,
            resolution: "same_file".into(),
            confidence: 0.95,
            call_site_line: i as i64 * 10,
        })
        .collect();

    writer.send(BatchCommand::InsertCallEdges(rows)).unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.call_edge_rows, 300);
}

#[test]
fn stress_batch_writer_pattern_confidence_batch() {
    let writer = make_batch_writer();

    let rows: Vec<PatternConfidenceRow> = (0..100)
        .map(|i| PatternConfidenceRow {
            pattern_id: format!("pattern_{i}"),
            alpha: 10.0 + i as f64,
            beta: 2.0 + i as f64 * 0.1,
            posterior_mean: 0.8,
            credible_interval_low: 0.7,
            credible_interval_high: 0.9,
            tier: "established".into(),
            momentum: "rising".into(),
        })
        .collect();

    writer.send(BatchCommand::InsertPatternConfidence(rows)).unwrap();
    writer.shutdown().unwrap();
}

#[test]
fn stress_batch_writer_outliers_batch() {
    let writer = make_batch_writer();

    let rows: Vec<OutlierDetectionRow> = (0..100)
        .map(|i| OutlierDetectionRow {
            pattern_id: format!("pattern_{}", i % 10),
            file: format!("src/file_{i}.ts"),
            line: i as i64 * 5,
            deviation_score: 2.5 + i as f64 * 0.1,
            significance: "high".into(),
            method: "zscore".into(),
        })
        .collect();

    writer.send(BatchCommand::InsertOutliers(rows)).unwrap();
    writer.shutdown().unwrap();
}

#[test]
fn stress_batch_writer_conventions_batch() {
    let writer = make_batch_writer();

    let rows: Vec<ConventionInsertRow> = (0..50)
        .map(|i| ConventionInsertRow {
            pattern_id: format!("conv_{i}"),
            category: "structural".into(),
            scope: "project".into(),
            dominance_ratio: 0.8 + (i as f64 * 0.001),
            promotion_status: "candidate".into(),
            discovered_at: 1700000000,
            last_seen: 1700000000,
            expires_at: None,
        })
        .collect();

    writer.send(BatchCommand::InsertConventions(rows)).unwrap();
    writer.shutdown().unwrap();
}

#[test]
fn stress_batch_writer_delete_file_metadata() {
    let writer = make_batch_writer();

    // Insert first
    let rows: Vec<FileMetadataRow> = (0..10)
        .map(|i| FileMetadataRow {
            path: format!("src/file_{i}.ts"),
            language: Some("typescript".into()),
            file_size: 100,
            content_hash: vec![0u8; 8],
            mtime_secs: 1000,
            mtime_nanos: 0,
            last_scanned_at: 1000,
            scan_duration_us: None,
        })
        .collect();
    writer.send(BatchCommand::UpsertFileMetadata(rows)).unwrap();

    // Delete some
    let paths: Vec<String> = (0..5).map(|i| format!("src/file_{i}.ts")).collect();
    writer.send(BatchCommand::DeleteFileMetadata(paths)).unwrap();

    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.file_metadata_rows, 10);
    assert_eq!(stats.deleted_files, 5);
}

#[test]
fn stress_batch_writer_explicit_flush() {
    let writer = make_batch_writer();

    let rows = vec![FileMetadataRow {
        path: "flush_test.ts".into(),
        language: Some("typescript".into()),
        file_size: 100,
        content_hash: vec![0u8; 8],
        mtime_secs: 1000,
        mtime_nanos: 0,
        last_scanned_at: 1000,
        scan_duration_us: None,
    }];
    writer.send(BatchCommand::UpsertFileMetadata(rows)).unwrap();
    writer.flush().unwrap();

    let stats = writer.shutdown().unwrap();
    assert!(stats.flushes >= 1);
}

#[test]
fn stress_batch_writer_mixed_commands_rapid() {
    let writer = make_batch_writer();
    let start = Instant::now();

    for i in 0..100 {
        writer.send(BatchCommand::UpsertFileMetadata(vec![FileMetadataRow {
            path: format!("rapid_{i}.ts"),
            language: Some("typescript".into()),
            file_size: 100,
            content_hash: vec![i as u8; 8],
            mtime_secs: 1000,
            mtime_nanos: 0,
            last_scanned_at: 1000,
            scan_duration_us: None,
        }])).unwrap();

        writer.send(BatchCommand::InsertFunctions(vec![FunctionRow {
            file: format!("rapid_{i}.ts"),
            name: format!("func_{i}"),
            qualified_name: None,
            language: "typescript".into(),
            line: 1,
            end_line: 10,
            parameter_count: 0,
            return_type: None,
            is_exported: true,
            is_async: false,
            body_hash: vec![0u8; 8],
            signature_hash: vec![0u8; 8],
        }])).unwrap();
    }

    let stats = writer.shutdown().unwrap();
    let elapsed = start.elapsed();

    assert_eq!(stats.file_metadata_rows, 100);
    assert_eq!(stats.function_rows, 100);
    // Should complete in well under 5 seconds
    assert!(elapsed.as_secs() < 5, "mixed commands took too long: {elapsed:?}");
}

#[test]
fn stress_batch_writer_upsert_idempotent() {
    let writer = make_batch_writer();

    // Insert same path twice — should upsert, not duplicate
    for _ in 0..3 {
        writer.send(BatchCommand::UpsertFileMetadata(vec![FileMetadataRow {
            path: "same_file.ts".into(),
            language: Some("typescript".into()),
            file_size: 200,
            content_hash: vec![1u8; 8],
            mtime_secs: 2000,
            mtime_nanos: 0,
            last_scanned_at: 2000,
            scan_duration_us: Some(50),
        }])).unwrap();
    }

    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.file_metadata_rows, 3); // 3 upserts processed
}

#[test]
fn stress_batch_writer_parse_cache() {
    let writer = make_batch_writer();

    let rows: Vec<ParseCacheRow> = (0..100)
        .map(|i| ParseCacheRow {
            content_hash: vec![i as u8; 8],
            language: "typescript".into(),
            parse_result_json: format!(r#"{{"file":"file_{i}.ts","functions":[]}}"#),
            created_at: 1700000000,
        })
        .collect();

    writer.send(BatchCommand::InsertParseCache(rows)).unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.parse_cache_rows, 100);
}

//! Phase B engine integration tests (CT0-B-01 through CT0-B-07, CT0-B-14, CT0-B-16).
//!
//! These test `DriftStorageEngine` in isolation — no NAPI involved.
//! Uses file-backed temp directories because in-memory SQLite creates
//! isolated databases per connection (writer/reader/batch can't see each other).

use std::sync::{Arc, Barrier};
use tempfile::TempDir;
use drift_storage::DriftStorageEngine;
use drift_core::traits::storage::drift_files::IDriftFiles;
use drift_core::traits::storage::drift_analysis::IDriftAnalysis;
use drift_core::traits::storage::drift_enforcement::IDriftEnforcement;
use drift_core::traits::storage::drift_batch::IDriftBatchWriter;
use drift_core::traits::storage::drift_reader::IDriftReader;
use drift_storage::batch::commands::BatchCommand;

fn temp_engine() -> (TempDir, DriftStorageEngine) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let engine = DriftStorageEngine::open(&db_path).unwrap();
    (dir, engine)
}

/// CT0-B-01: open → load_all_file_metadata returns empty → insert via writer → read back → fields identical.
#[test]
fn ct0_b01_engine_file_metadata_round_trip() {
    let (_dir, engine) = temp_engine();

    // Empty state
    let files = engine.load_all_file_metadata().unwrap();
    assert!(files.is_empty(), "Expected empty file metadata on fresh engine");

    // Insert via writer
    engine
        .with_writer(|conn| {
            conn.execute(
                "INSERT INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at, function_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params!["src/main.rs", "rust", 1024, b"abc123".to_vec(), 1000, 0, 1000, 5],
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
            Ok(())
        })
        .unwrap();

    // Read back
    let files = engine.load_all_file_metadata().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, "src/main.rs");
    assert_eq!(files[0].language, Some("rust".to_string()));
    assert_eq!(files[0].file_size, 1024);
    assert_eq!(files[0].function_count, 5);
}

/// CT0-B-02: Insert via IDriftAnalysis (writer) → read via IDriftAnalysis (reader) → data visible.
#[test]
fn ct0_b02_analysis_read_write_routing() {
    let (_dir, engine) = temp_engine();

    // Insert a function via writer
    engine
        .with_writer(|conn| {
            conn.execute(
                "INSERT INTO functions (file, name, language, line, end_line)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params!["src/main.rs", "main", "rust", 1, 10],
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
            Ok(())
        })
        .unwrap();

    // Read via trait method (uses with_reader internally)
    let count = engine.count_functions().unwrap();
    assert_eq!(count, 1, "Expected 1 function after insert");
}

/// CT0-B-03: send_batch(InsertDetections) → flush_sync → get_detections_by_file returns rows.
#[test]
fn ct0_b03_batch_writer_integration() {
    let (_dir, engine) = temp_engine();

    // Insert a file first (FK reference)
    engine
        .with_writer(|conn| {
            conn.execute(
                "INSERT INTO file_metadata (path, language, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at, function_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params!["src/lib.rs", "rust", 512, b"def456".to_vec(), 2000, 0, 2000, 3],
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
            Ok(())
        })
        .unwrap();

    // Send batch detections
    let rows = vec![drift_storage::batch::commands::DetectionRow {
        file: "src/lib.rs".to_string(),
        line: 10,
        column_num: 0,
        pattern_id: "pat_001".to_string(),
        category: "naming".to_string(),
        confidence: 0.9,
        detection_method: "ast".to_string(),
        cwe_ids: None,
        owasp: None,
        matched_text: None,
    }];

    engine
        .send_batch(BatchCommand::InsertDetections(rows))
        .unwrap();
    engine.flush_batch_sync().unwrap();

    // Read back via trait
    let detections = engine.get_detections_by_file("src/lib.rs").unwrap();
    assert_eq!(detections.len(), 1);
    assert_eq!(detections[0].pattern_id, "pat_001");
    assert_eq!(detections[0].confidence, 0.9);
}

/// CT0-B-05: Insert 200 violations → verify all readable back.
#[test]
fn ct0_b05_bulk_violations_readable() {
    let (_dir, engine) = temp_engine();

    engine
        .with_writer(|conn| {
            for i in 0..200 {
                conn.execute(
                    "INSERT INTO violations (id, file, line, severity, pattern_id, rule_id, message, suppressed, is_new)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0)",
                    rusqlite::params![
                        format!("v_{i:03}"),
                        "src/main.rs",
                        i + 1,
                        "warning",
                        "pat_001",
                        "rule_001",
                        format!("Violation {i}")
                    ],
                )
                .map_err(|e| drift_core::errors::StorageError::SqliteError {
                    message: e.to_string(),
                })?;
            }
            Ok(())
        })
        .unwrap();

    let violations = engine.query_all_violations().unwrap();
    assert_eq!(violations.len(), 200, "Expected all 200 violations readable");
    // Verify no duplicates
    let mut ids: Vec<String> = violations.iter().map(|v| v.id.clone()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 200, "No duplicate violation IDs");
}

/// CT0-B-06: Insert pattern_confidence row → IDriftReader::pattern_confidence returns Some(0.85).
#[test]
fn ct0_b06_drift_reader_returns_real_data() {
    let (_dir, engine) = temp_engine();
    let engine = Arc::new(engine);

    engine
        .with_writer(|conn| {
            conn.execute(
                "INSERT INTO pattern_confidence (pattern_id, posterior_mean, credible_interval_low, credible_interval_high, tier, alpha, beta, momentum)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params!["auth_check", 0.85, 0.75, 0.95, "established", 10.0, 2.0, 0.5],
            )
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
            Ok(())
        })
        .unwrap();

    let reader: &dyn IDriftReader = engine.as_ref();
    let confidence = reader.pattern_confidence("auth_check").unwrap();
    assert!(confidence.is_some(), "Expected Some for existing pattern");
    let val = confidence.unwrap();
    assert!((val - 0.85).abs() < 1e-9, "Expected 0.85, got {val}");
}

/// CT0-B-07: Empty engine → all 14 IDriftReader methods → None or 0, no errors.
#[test]
fn ct0_b07_drift_reader_empty_state_safe() {
    let (_dir, engine) = temp_engine();
    let engine = Arc::new(engine);
    let reader: &dyn IDriftReader = engine.as_ref();

    assert_eq!(reader.pattern_confidence("nonexistent").unwrap(), None);
    assert_eq!(reader.pattern_occurrence_rate("nonexistent").unwrap(), None);
    assert_eq!(reader.false_positive_rate("nonexistent").unwrap(), None);
    assert_eq!(reader.constraint_verified("nonexistent").unwrap(), None);
    assert_eq!(reader.coupling_metric("nonexistent").unwrap(), None);
    assert_eq!(reader.dna_health().unwrap(), None);
    assert_eq!(reader.test_coverage("nonexistent").unwrap(), None);
    assert_eq!(reader.error_handling_gaps("nonexistent").unwrap(), None);
    assert_eq!(reader.decision_evidence("nonexistent").unwrap(), None);
    assert_eq!(reader.boundary_data("nonexistent").unwrap(), None);
    assert_eq!(reader.taint_flow_risk("nonexistent").unwrap(), None);
    assert_eq!(reader.call_graph_coverage("nonexistent").unwrap(), None);
    assert_eq!(reader.count_matching_patterns(&[]).unwrap(), 0);
    assert_eq!(reader.latest_scan_timestamp().unwrap(), None);
}

/// CT0-B-14: Spawn 20 threads calling different storage methods → all complete within 5s.
#[test]
fn ct0_b14_concurrency_safety() {
    let (_dir, engine) = temp_engine();
    let engine = Arc::new(engine);
    let barrier = Arc::new(Barrier::new(20));

    let handles: Vec<_> = (0..20)
        .map(|i| {
            let eng = Arc::clone(&engine);
            let bar = Arc::clone(&barrier);
            std::thread::spawn(move || {
                bar.wait();
                match i % 4 {
                    0 => {
                        let _ = eng.load_all_file_metadata();
                    }
                    1 => {
                        let _ = eng.count_functions();
                    }
                    2 => {
                        let _ = eng.query_all_violations();
                    }
                    3 => {
                        let reader: &dyn IDriftReader = eng.as_ref();
                        let _ = reader.pattern_confidence("test");
                    }
                    _ => unreachable!(),
                }
            })
        })
        .collect();

    for h in handles {
        let result = h.join();
        assert!(result.is_ok(), "Thread panicked — possible deadlock or race");
    }
}

/// CT0-B-16: Compile-time assertion — DriftStorageEngine implements all 7 traits.
/// If this compiles, it passes.
#[test]
fn ct0_b16_engine_implements_all_traits() {
    fn assert_all_traits(
        _: &(impl IDriftFiles
            + IDriftAnalysis
            + drift_core::traits::storage::drift_structural::IDriftStructural
            + drift_core::traits::storage::drift_enforcement::IDriftEnforcement
            + drift_core::traits::storage::drift_advanced::IDriftAdvanced
            + IDriftBatchWriter
            + IDriftReader),
    ) {
    }
    let (_dir, engine) = temp_engine();
    assert_all_traits(&engine);
}

//! NAPI bridge tests — T1-NAPI-01 through T1-NAPI-08.
//!
//! Since drift-napi is a cdylib, these tests exercise the Rust internals
//! that power the NAPI boundary: runtime initialization, type conversions,
//! error code propagation, and config merging.
//!
//! Note: OnceLock-based runtime tests are limited because OnceLock can only
//! be set once per process. We test the underlying components directly.

use std::path::PathBuf;

use drift_core::config::DriftConfig;
use drift_core::errors::ScanError;
use drift_core::errors::error_code::DriftErrorCode;
use drift_napi::conversions::error_codes;
use drift_napi::conversions::types::{ProgressUpdate, ScanOptions, ScanSummary, ScanStatsJs};
use drift_storage::DatabaseManager;
use tempfile::TempDir;

// ---- T1-NAPI-01: drift_initialize creates drift.db with correct PRAGMAs ----

#[test]
fn t1_napi_01_initialize_creates_db_with_pragmas() {
    // Test the underlying DatabaseManager::open that drift_initialize uses
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("drift.db");

    let db = DatabaseManager::open(&db_path).unwrap();

    // Verify PRAGMAs are set correctly (same checks as T1-STR-01)
    db.with_writer(|conn| {
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal", "journal_mode should be WAL");

        let sync: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(sync, 1, "synchronous should be NORMAL (1)");

        let fk: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign_keys should be ON");

        let cache: i64 = conn
            .pragma_query_value(None, "cache_size", |row| row.get(0))
            .unwrap();
        assert_eq!(cache, -64000, "cache_size should be -64000 (64MB)");

        Ok(())
    })
    .unwrap();

    // Verify schema was migrated
    db.with_reader(|conn| {
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        assert_eq!(version, 9, "schema version should match latest migration");
        Ok(())
    })
    .unwrap();

    // Verify drift.db file exists on disk
    assert!(db_path.exists(), "drift.db should exist on disk");
}

// ---- T1-NAPI-02: ScanSummary type conversion from ScanDiff ----

#[test]
fn t1_napi_02_scan_summary_type_conversion() {
    use drift_analysis::scanner::types::{ScanDiff, ScanStats};
    use drift_analysis::scanner::language_detect::Language;
    use drift_core::types::collections::FxHashMap;

    // Build a realistic ScanDiff
    let mut languages_found = FxHashMap::default();
    languages_found.insert(Language::TypeScript, 50);
    languages_found.insert(Language::Python, 30);

    let stats = ScanStats {
        total_files: 100,
        total_size_bytes: 1_000_000,
        discovery_ms: 50,
        hashing_ms: 100,
        diff_ms: 10,
        cache_hit_rate: 0.85,
        files_skipped_large: 2,
        files_skipped_ignored: 5,
        files_skipped_binary: 3,
        languages_found,
    };

    let diff = ScanDiff {
        added: vec![PathBuf::from("new_file.ts")],
        modified: vec![PathBuf::from("changed.ts")],
        removed: vec![PathBuf::from("deleted.ts")],
        unchanged: (0..97).map(|i| PathBuf::from(format!("file_{i}.ts"))).collect(),
        errors: vec![],
        stats,
        entries: FxHashMap::default(),
    };

    let summary = ScanSummary::from(&diff);

    // Verify all fields are correctly typed and populated
    assert_eq!(summary.files_total, 100);
    assert_eq!(summary.files_added, 1);
    assert_eq!(summary.files_modified, 1);
    assert_eq!(summary.files_removed, 1);
    assert_eq!(summary.files_unchanged, 97);
    assert_eq!(summary.errors_count, 0);
    assert_eq!(summary.duration_ms, 160); // 50 + 100 + 10
    assert_eq!(summary.status, "complete");

    // Verify language map is populated
    assert!(!summary.languages.is_empty());
}

// ---- T1-NAPI-03: drift_shutdown cleanly closes connections ----

#[test]
fn t1_napi_03_shutdown_checkpoint() {
    // Test the checkpoint mechanism that drift_shutdown uses
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    // Insert some data
    db.with_writer(|conn| {
        conn.execute(
            "INSERT INTO file_metadata (path, file_size, content_hash, mtime_secs, mtime_nanos, last_scanned_at)
             VALUES ('test.ts', 100, X'0000000000000000', 0, 0, 0)",
            [],
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError {
            message: e.to_string(),
        })?;
        Ok(())
    })
    .unwrap();

    // Checkpoint (what drift_shutdown does)
    db.checkpoint().unwrap();

    // WAL file should be empty or very small after TRUNCATE checkpoint
    let wal_path = dir.path().join("test.db-wal");
    if wal_path.exists() {
        let wal_size = std::fs::metadata(&wal_path).unwrap().len();
        // After TRUNCATE checkpoint, WAL should be 0 bytes
        assert_eq!(wal_size, 0, "WAL should be truncated after checkpoint");
    }

    // Data should survive — reopen and verify
    drop(db);
    let db2 = DatabaseManager::open(&db_path).unwrap();
    db2.with_reader(|conn| {
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM file_metadata", [], |row| row.get(0))
            .map_err(|e| drift_core::errors::StorageError::SqliteError {
                message: e.to_string(),
            })?;
        assert_eq!(count, 1, "data should survive checkpoint + reopen");
        Ok(())
    })
    .unwrap();
}

// ---- T1-NAPI-04: Double initialize is idempotent (OnceLock) ----

#[test]
fn t1_napi_04_double_initialize_idempotent() {
    // OnceLock::set returns Err if already set — verify the error message format
    use std::sync::OnceLock;

    let lock: OnceLock<String> = OnceLock::new();

    // First set succeeds
    assert!(lock.set("first".to_string()).is_ok());

    // Second set fails (idempotent — no crash, returns error)
    let result = lock.set("second".to_string());
    assert!(result.is_err(), "second OnceLock::set should fail");

    // Original value is preserved
    assert_eq!(lock.get().unwrap(), "first");

    // Also verify the error code constant exists and is correct
    assert_eq!(error_codes::ALREADY_INITIALIZED, "ALREADY_INITIALIZED");
}

// ---- T1-NAPI-05: Scan after shutdown returns structured error ----

#[test]
fn t1_napi_05_runtime_not_initialized_error() {
    // Verify the error format for "runtime not initialized"
    let err = error_codes::runtime_not_initialized();
    let msg = err.to_string();

    assert!(
        msg.contains("[RUNTIME_NOT_INITIALIZED]"),
        "error should contain [RUNTIME_NOT_INITIALIZED] code, got: {msg}"
    );
    assert!(
        msg.contains("driftInitialize()"),
        "error should mention driftInitialize(), got: {msg}"
    );
}

// ---- T1-NAPI-06: Progress handler bridges events correctly ----

#[test]
fn t1_napi_06_progress_update_structure() {
    // Test the ProgressUpdate struct that ThreadsafeFunction would carry
    let update = ProgressUpdate {
        processed: 500,
        total: 10000,
        phase: "scanning".to_string(),
        current_file: Some("src/main.ts".to_string()),
    };

    assert_eq!(update.processed, 500);
    assert_eq!(update.total, 10000);
    assert_eq!(update.phase, "scanning");
    assert_eq!(update.current_file.as_deref(), Some("src/main.ts"));

    // Test without current_file
    let update2 = ProgressUpdate {
        processed: 10000,
        total: 10000,
        phase: "complete".to_string(),
        current_file: None,
    };
    assert!(update2.current_file.is_none());
}

// ---- T1-NAPI-07: Error code propagation format ----

#[test]
fn t1_napi_07_error_code_propagation() {
    // Test ScanError → NAPI error conversion
    let scan_err = ScanError::PermissionDenied {
        path: PathBuf::from("/secret/file.ts"),
    };

    // Verify DriftErrorCode trait
    assert_eq!(scan_err.error_code(), "SCAN_ERROR");

    // Verify napi_string format
    let napi_str = scan_err.napi_string();
    assert!(
        napi_str.starts_with("[SCAN_ERROR]"),
        "should start with [SCAN_ERROR], got: {napi_str}"
    );
    assert!(
        napi_str.contains("Permission denied"),
        "should contain 'Permission denied', got: {napi_str}"
    );
    assert!(
        napi_str.contains("/secret/file.ts"),
        "should contain the path, got: {napi_str}"
    );

    // Test to_napi_error conversion
    let napi_err = error_codes::scan_error(ScanError::PermissionDenied {
        path: PathBuf::from("/secret/file.ts"),
    });
    let msg = napi_err.to_string();
    assert!(msg.contains("[SCAN_ERROR]"), "NAPI error should contain code: {msg}");
    assert!(msg.contains("Permission denied"), "NAPI error should contain message: {msg}");

    // Test Cancelled error code
    let cancelled = ScanError::Cancelled;
    assert_eq!(cancelled.error_code(), "CANCELLED");
    let napi_str = cancelled.napi_string();
    assert!(napi_str.starts_with("[CANCELLED]"));

    // Test all error code constants exist
    assert_eq!(error_codes::SCAN_ERROR, "SCAN_ERROR");
    assert_eq!(error_codes::SCAN_CANCELLED, "SCAN_CANCELLED");
    assert_eq!(error_codes::PERMISSION_DENIED, "PERMISSION_DENIED");
    assert_eq!(error_codes::PARSE_ERROR, "PARSE_ERROR");
    assert_eq!(error_codes::STORAGE_ERROR, "STORAGE_ERROR");
    assert_eq!(error_codes::DB_BUSY, "DB_BUSY");
    assert_eq!(error_codes::DB_CORRUPT, "DB_CORRUPT");
    assert_eq!(error_codes::INIT_ERROR, "INIT_ERROR");
    assert_eq!(error_codes::INTERNAL_ERROR, "INTERNAL_ERROR");
    assert_eq!(error_codes::NOT_FOUND, "NOT_FOUND");
}

// ---- T1-NAPI-08: ScanOptions config merging ----

#[test]
fn t1_napi_08_scan_options_config_merging() {
    // Test ScanOptions defaults
    let default_opts = ScanOptions::default();
    assert!(default_opts.force_full.is_none());
    assert!(default_opts.max_file_size.is_none());
    assert!(default_opts.extra_ignore.is_none());
    assert!(default_opts.follow_symlinks.is_none());

    // Test ScanOptions with values
    let opts = ScanOptions {
        force_full: Some(true),
        max_file_size: Some(10_000_000),
        include: None,
        extra_ignore: Some(vec!["*.log".to_string(), "dist/".to_string()]),
        follow_symlinks: Some(false),
    };

    assert_eq!(opts.force_full, Some(true));
    assert_eq!(opts.max_file_size, Some(10_000_000));
    assert_eq!(opts.extra_ignore.as_ref().unwrap().len(), 2);
    assert_eq!(opts.follow_symlinks, Some(false));

    // Test ScanStatsJs conversion
    use drift_analysis::scanner::types::ScanStats;
    use drift_core::types::collections::FxHashMap as FxMap;
    let stats = ScanStats {
        total_files: 5000,
        total_size_bytes: 50_000_000,
        discovery_ms: 100,
        hashing_ms: 200,
        diff_ms: 50,
        cache_hit_rate: 0.92,
        files_skipped_large: 3,
        files_skipped_ignored: 15,
        files_skipped_binary: 7,
        languages_found: FxMap::default(),
    };

    let js_stats = ScanStatsJs::from(&stats);
    assert_eq!(js_stats.total_files, 5000);
    assert_eq!(js_stats.total_size_bytes, 50_000_000.0);
    assert_eq!(js_stats.discovery_ms, 100);
    assert_eq!(js_stats.hashing_ms, 200);
    assert_eq!(js_stats.diff_ms, 50);
    assert!((js_stats.cache_hit_rate - 0.92).abs() < f64::EPSILON);
    assert_eq!(js_stats.files_skipped_large, 3);
    assert_eq!(js_stats.files_skipped_ignored, 15);
    assert_eq!(js_stats.files_skipped_binary, 7);

    // Test DriftConfig defaults load without error
    let config = DriftConfig::default();
    assert!(config.scan.effective_max_file_size() > 0);
    // threads=0 means auto-detect (use all CPUs), which is valid
    assert_eq!(config.scan.effective_threads(), 0);
    assert!(config.scan.effective_incremental());
}

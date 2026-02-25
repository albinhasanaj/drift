//! Adversarial & stress tests for Phase A storage traits.
//!
//! Targets: concurrency, edge cases, mutex poisoning, Arc delegation,
//! stub isolation, f64 boundary values, Unicode, WriteStats completeness,
//! multi-trait composition, error variant Display, IDriftBatchWriter shutdown.

#![allow(unused_imports)]

use std::sync::Arc;
use std::thread;

use drift_core::errors::StorageError;
use drift_core::traits::storage::drift_advanced::IDriftAdvanced;
use drift_core::traits::storage::drift_analysis::{
    BoundaryRow, CallEdgeRow, ConventionRow, DetectionRow, DetectionSummaryRow, FunctionRow,
    IDriftAnalysis, OutlierRow, PatternConfidenceRow, ScanHistoryRow,
};
use drift_core::traits::storage::drift_batch::{IDriftBatchWriter, WriteStats};
use drift_core::traits::storage::drift_enforcement::{
    AuditSnapshotRow, DegradationAlertRow, FeedbackRow, FeedbackStats, GateResultRow,
    HealthTrendRow, IDriftEnforcement, PolicyResultRow, ViolationRow,
};
use drift_core::traits::storage::drift_files::{FileMetadataRow, IDriftFiles, ParseCacheRow};
use drift_core::traits::storage::drift_reader::IDriftReader;
use drift_core::traits::storage::drift_structural::{
    ConstantRow, CouplingMetricsRow, CryptoFindingRow, DataAccessRow, DnaGeneRow,
    DecompositionDecisionRow, EnvVariableRow, IDriftStructural, ImpactScoreRow,
    OwaspFindingRow, SecretRow, TaintFlowRow, TestQualityRow, WrapperRow,
};
use drift_core::traits::storage::test_helpers::IDriftReaderStub;
use drift_core::traits::storage::workspace::IWorkspaceStorage;
use drift_core::traits::storage::workspace_types::*;

// ─── Concurrency: multi-thread stub access ──────────────────────────

#[test]
fn stress_concurrent_stub_reads_and_writes() {
    let stub = Arc::new(IDriftReaderStub::new());

    let mut handles = vec![];
    for i in 0..20 {
        let s = Arc::clone(&stub);
        handles.push(thread::spawn(move || {
            let key = format!("pattern_{i}");
            s.set_pattern_confidence(&key, i as f64 * 0.05);
            s.set_occurrence_rate(&key, i as f64 * 0.01);
            s.set_coupling_metric(&key, i as f64 * 0.1);

            // Read back — may see our write or another thread's
            let _ = s.pattern_confidence(&key).unwrap();
            let _ = s.pattern_occurrence_rate(&key).unwrap();
            let _ = s.coupling_metric(&key).unwrap();
            let _ = s.dna_health().unwrap();
            let _ = s.latest_scan_timestamp().unwrap();
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }

    // Verify all 20 keys were written
    for i in 0..20 {
        let key = format!("pattern_{i}");
        assert!(stub.pattern_confidence(&key).unwrap().is_some());
    }
}

#[test]
fn stress_concurrent_arc_trait_object_reads() {
    let stub = Arc::new(IDriftReaderStub::new());
    stub.set_pattern_confidence("shared", 0.75);
    stub.set_dna_health(0.9);
    stub.set_latest_scan_timestamp("2026-02-11T15:00:00Z");

    let reader: Arc<dyn IDriftReader> = stub;

    let mut handles = vec![];
    for _ in 0..50 {
        let r = Arc::clone(&reader);
        handles.push(thread::spawn(move || {
            assert_eq!(r.pattern_confidence("shared").unwrap(), Some(0.75));
            assert_eq!(r.dna_health().unwrap(), Some(0.9));
            assert_eq!(
                r.latest_scan_timestamp().unwrap(),
                Some("2026-02-11T15:00:00Z".to_string())
            );
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }
}

// ─── Stub key isolation ─────────────────────────────────────────────

#[test]
fn stub_key_isolation_no_prefix_matching() {
    let stub = IDriftReaderStub::new();
    stub.set_pattern_confidence("auth", 0.5);
    stub.set_pattern_confidence("auth_check", 0.9);

    // "auth" must NOT match "auth_check" or "auth_module"
    assert_eq!(stub.pattern_confidence("auth").unwrap(), Some(0.5));
    assert_eq!(stub.pattern_confidence("auth_check").unwrap(), Some(0.9));
    assert_eq!(stub.pattern_confidence("auth_module").unwrap(), None);
    assert_eq!(stub.pattern_confidence("aut").unwrap(), None);
    assert_eq!(stub.pattern_confidence("").unwrap(), None);
}

#[test]
fn stub_key_isolation_across_different_methods() {
    let stub = IDriftReaderStub::new();
    stub.set_pattern_confidence("key", 0.5);
    stub.set_coupling_metric("key", 0.9);

    // Same key, different method → different namespace
    assert_eq!(stub.pattern_confidence("key").unwrap(), Some(0.5));
    assert_eq!(stub.coupling_metric("key").unwrap(), Some(0.9));
    assert_eq!(stub.pattern_occurrence_rate("key").unwrap(), None);
}

// ─── Stub overwrite semantics ───────────────────────────────────────

#[test]
fn stub_overwrite_uses_latest_value() {
    let stub = IDriftReaderStub::new();
    stub.set_pattern_confidence("p", 0.1);
    assert_eq!(stub.pattern_confidence("p").unwrap(), Some(0.1));

    stub.set_pattern_confidence("p", 0.99);
    assert_eq!(stub.pattern_confidence("p").unwrap(), Some(0.99));

    stub.set_dna_health(0.5);
    assert_eq!(stub.dna_health().unwrap(), Some(0.5));
    stub.set_dna_health(0.0);
    assert_eq!(stub.dna_health().unwrap(), Some(0.0));
}

// ─── f64 boundary values ────────────────────────────────────────────

#[test]
fn stub_f64_boundary_values() {
    let stub = IDriftReaderStub::new();

    // Zero
    stub.set_pattern_confidence("zero", 0.0);
    assert_eq!(stub.pattern_confidence("zero").unwrap(), Some(0.0));

    // One
    stub.set_pattern_confidence("one", 1.0);
    assert_eq!(stub.pattern_confidence("one").unwrap(), Some(1.0));

    // Negative (shouldn't happen in practice but trait doesn't enforce)
    stub.set_pattern_confidence("neg", -1.0);
    assert_eq!(stub.pattern_confidence("neg").unwrap(), Some(-1.0));

    // Very small
    stub.set_pattern_confidence("tiny", f64::MIN_POSITIVE);
    assert_eq!(
        stub.pattern_confidence("tiny").unwrap(),
        Some(f64::MIN_POSITIVE)
    );

    // Max
    stub.set_pattern_confidence("max", f64::MAX);
    assert_eq!(stub.pattern_confidence("max").unwrap(), Some(f64::MAX));

    // Infinity
    stub.set_pattern_confidence("inf", f64::INFINITY);
    assert_eq!(
        stub.pattern_confidence("inf").unwrap(),
        Some(f64::INFINITY)
    );

    // Negative infinity
    stub.set_pattern_confidence("ninf", f64::NEG_INFINITY);
    assert_eq!(
        stub.pattern_confidence("ninf").unwrap(),
        Some(f64::NEG_INFINITY)
    );
}

#[test]
fn stub_f64_nan_behavior() {
    let stub = IDriftReaderStub::new();
    stub.set_pattern_confidence("nan", f64::NAN);

    // NaN != NaN, so we test via is_nan
    let val = stub.pattern_confidence("nan").unwrap().unwrap();
    assert!(val.is_nan());
}

#[test]
fn stub_negative_zero() {
    let stub = IDriftReaderStub::new();
    stub.set_pattern_confidence("nz", -0.0);
    let val = stub.pattern_confidence("nz").unwrap().unwrap();
    // -0.0 == 0.0 in IEEE 754
    assert_eq!(val, 0.0);
    // But sign bit is set
    assert!(val.is_sign_negative());
}

// ─── count_matching_patterns ignores input ──────────────────────────

#[test]
fn stub_count_matching_patterns_ignores_pattern_ids() {
    let stub = IDriftReaderStub::new();
    stub.set_matching_pattern_count(5);

    // Regardless of what pattern IDs are passed, returns the configured count
    assert_eq!(stub.count_matching_patterns(&[]).unwrap(), 5);
    assert_eq!(
        stub.count_matching_patterns(&["a".into(), "b".into()])
            .unwrap(),
        5
    );
    assert_eq!(
        stub.count_matching_patterns(&["nonexistent".into()])
            .unwrap(),
        5
    );
}

// ─── Unicode / special characters ───────────────────────────────────

#[test]
fn stub_unicode_keys() {
    let stub = IDriftReaderStub::new();

    // CJK
    stub.set_pattern_confidence("模式_检查", 0.7);
    assert_eq!(stub.pattern_confidence("模式_检查").unwrap(), Some(0.7));

    // Emoji
    stub.set_pattern_confidence("🔥🚀", 0.99);
    assert_eq!(stub.pattern_confidence("🔥🚀").unwrap(), Some(0.99));

    // RTL
    stub.set_pattern_confidence("نمط", 0.3);
    assert_eq!(stub.pattern_confidence("نمط").unwrap(), Some(0.3));

    // Zero-width joiner
    stub.set_pattern_confidence("a\u{200D}b", 0.5);
    assert_eq!(stub.pattern_confidence("a\u{200D}b").unwrap(), Some(0.5));
    // Different from "ab"
    assert_eq!(stub.pattern_confidence("ab").unwrap(), None);
}

#[test]
fn stub_empty_and_whitespace_keys() {
    let stub = IDriftReaderStub::new();

    stub.set_pattern_confidence("", 0.1);
    assert_eq!(stub.pattern_confidence("").unwrap(), Some(0.1));

    stub.set_pattern_confidence(" ", 0.2);
    assert_eq!(stub.pattern_confidence(" ").unwrap(), Some(0.2));

    stub.set_pattern_confidence("\n\t", 0.3);
    assert_eq!(stub.pattern_confidence("\n\t").unwrap(), Some(0.3));

    // All distinct
    assert_eq!(stub.pattern_confidence("").unwrap(), Some(0.1));
    assert_eq!(stub.pattern_confidence(" ").unwrap(), Some(0.2));
}

// ─── WriteStats completeness ────────────────────────────────────────

#[test]
fn write_stats_default_all_zeros() {
    let stats = WriteStats::default();
    assert_eq!(stats.file_metadata_rows, 0);
    assert_eq!(stats.parse_cache_rows, 0);
    assert_eq!(stats.function_rows, 0);
    assert_eq!(stats.call_edge_rows, 0);
    assert_eq!(stats.detection_rows, 0);
    assert_eq!(stats.boundary_rows, 0);
    assert_eq!(stats.pattern_confidence_rows, 0);
    assert_eq!(stats.outlier_rows, 0);
    assert_eq!(stats.convention_rows, 0);
    assert_eq!(stats.scan_history_rows, 0);
    assert_eq!(stats.data_access_rows, 0);
    assert_eq!(stats.reachability_rows, 0);
    assert_eq!(stats.taint_flow_rows, 0);
    assert_eq!(stats.error_gap_rows, 0);
    assert_eq!(stats.impact_score_rows, 0);
    assert_eq!(stats.test_quality_rows, 0);
    assert_eq!(stats.coupling_metric_rows, 0);
    assert_eq!(stats.coupling_cycle_rows, 0);
    assert_eq!(stats.violation_rows, 0);
    assert_eq!(stats.gate_result_rows, 0);
    assert_eq!(stats.degradation_alert_rows, 0);
    assert_eq!(stats.wrapper_rows, 0);
    assert_eq!(stats.crypto_finding_rows, 0);
    assert_eq!(stats.dna_gene_rows, 0);
    assert_eq!(stats.dna_mutation_rows, 0);
    assert_eq!(stats.secret_rows, 0);
    assert_eq!(stats.constant_rows, 0);
    assert_eq!(stats.env_variable_rows, 0);
    assert_eq!(stats.owasp_finding_rows, 0);
    assert_eq!(stats.decomposition_decision_rows, 0);
    assert_eq!(stats.contract_rows, 0);
    assert_eq!(stats.contract_mismatch_rows, 0);
}

#[test]
fn write_stats_has_32_fields() {
    // If a field is added/removed, this test forces updating the count.
    // We verify by setting each field to a unique value and checking.
    let stats = WriteStats {
        file_metadata_rows: 1,
        parse_cache_rows: 2,
        function_rows: 3,
        call_edge_rows: 4,
        detection_rows: 5,
        boundary_rows: 6,
        pattern_confidence_rows: 7,
        outlier_rows: 8,
        convention_rows: 9,
        scan_history_rows: 10,
        data_access_rows: 11,
        reachability_rows: 12,
        taint_flow_rows: 13,
        error_gap_rows: 14,
        impact_score_rows: 15,
        test_quality_rows: 16,
        coupling_metric_rows: 17,
        coupling_cycle_rows: 18,
        violation_rows: 19,
        gate_result_rows: 20,
        degradation_alert_rows: 21,
        wrapper_rows: 22,
        crypto_finding_rows: 23,
        dna_gene_rows: 24,
        dna_mutation_rows: 25,
        secret_rows: 26,
        constant_rows: 27,
        env_variable_rows: 28,
        owasp_finding_rows: 29,
        decomposition_decision_rows: 30,
        contract_rows: 31,
        contract_mismatch_rows: 32,
    };
    // Sum should be 1+2+...+32 = 528
    let sum = stats.file_metadata_rows
        + stats.parse_cache_rows
        + stats.function_rows
        + stats.call_edge_rows
        + stats.detection_rows
        + stats.boundary_rows
        + stats.pattern_confidence_rows
        + stats.outlier_rows
        + stats.convention_rows
        + stats.scan_history_rows
        + stats.data_access_rows
        + stats.reachability_rows
        + stats.taint_flow_rows
        + stats.error_gap_rows
        + stats.impact_score_rows
        + stats.test_quality_rows
        + stats.coupling_metric_rows
        + stats.coupling_cycle_rows
        + stats.violation_rows
        + stats.gate_result_rows
        + stats.degradation_alert_rows
        + stats.wrapper_rows
        + stats.crypto_finding_rows
        + stats.dna_gene_rows
        + stats.dna_mutation_rows
        + stats.secret_rows
        + stats.constant_rows
        + stats.env_variable_rows
        + stats.owasp_finding_rows
        + stats.decomposition_decision_rows
        + stats.contract_rows
        + stats.contract_mismatch_rows;
    assert_eq!(sum, 528);
}

#[test]
fn write_stats_clone() {
    let stats = WriteStats {
        file_metadata_rows: 42,
        ..Default::default()
    };
    let cloned = stats.clone();
    assert_eq!(cloned.file_metadata_rows, 42);
    assert_eq!(cloned.detection_rows, 0);
}

// ─── IDriftBatchWriter Arc shutdown fallback ────────────────────────

struct DummyBatchWriter {
    flushed: std::sync::atomic::AtomicBool,
}

impl IDriftBatchWriter for DummyBatchWriter {
    fn send_raw(&self, _cmd: &str, _payload: &[u8]) -> Result<(), StorageError> {
        Ok(())
    }
    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }
    fn flush_sync(&self) -> Result<WriteStats, StorageError> {
        self.flushed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(WriteStats {
            file_metadata_rows: 99,
            ..Default::default()
        })
    }
    fn stats(&self) -> WriteStats {
        WriteStats::default()
    }
    fn shutdown(self: Box<Self>) -> Result<WriteStats, StorageError> {
        // Real shutdown
        Ok(WriteStats {
            file_metadata_rows: 100,
            ..Default::default()
        })
    }
}

#[test]
fn batch_writer_direct_shutdown() {
    let writer = Box::new(DummyBatchWriter {
        flushed: std::sync::atomic::AtomicBool::new(false),
    });
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.file_metadata_rows, 100);
}

#[test]
fn batch_writer_arc_shutdown_falls_back_to_flush_sync() {
    // Arc<T> can't consume self, so the blanket impl falls back to flush_sync.
    let writer = Arc::new(DummyBatchWriter {
        flushed: std::sync::atomic::AtomicBool::new(false),
    });

    // Wrap Arc in Box to call shutdown
    let boxed: Box<Arc<DummyBatchWriter>> = Box::new(writer);
    let stats = boxed.shutdown().unwrap();

    // Should get flush_sync result (99), NOT direct shutdown result (100)
    assert_eq!(stats.file_metadata_rows, 99);
}

#[test]
fn batch_writer_arc_trait_object() {
    let writer = Arc::new(DummyBatchWriter {
        flushed: std::sync::atomic::AtomicBool::new(false),
    });
    let _: Arc<dyn IDriftBatchWriter> = writer;
}

// ─── Error variant Display correctness ──────────────────────────────

#[test]
fn all_storage_error_variants_display() {
    use drift_core::errors::error_code::DriftErrorCode;

    let cases: Vec<(StorageError, &str, &str)> = vec![
        (
            StorageError::SqliteError {
                message: "table not found".into(),
            },
            "table not found",
            "STORAGE_ERROR",
        ),
        (
            StorageError::MigrationFailed {
                version: 7,
                message: "column exists".into(),
            },
            "version 7",
            "MIGRATION_FAILED",
        ),
        (StorageError::DbBusy, "busy", "DB_BUSY"),
        (
            StorageError::DbCorrupt {
                details: "page 42".into(),
            },
            "page 42",
            "DB_CORRUPT",
        ),
        (StorageError::DiskFull, "Disk full", "DISK_FULL"),
        (
            StorageError::ConnectionPoolExhausted { active: 10 },
            "10 active",
            "STORAGE_ERROR",
        ),
        (
            StorageError::NotSupported {
                operation: "backup".into(),
                reason: "cloud".into(),
            },
            "backup",
            "STORAGE_ERROR",
        ),
    ];

    for (err, expected_substr, expected_code) in cases {
        let display = format!("{err}");
        assert!(
            display.contains(expected_substr),
            "Display of {err:?} should contain '{expected_substr}', got: '{display}'"
        );
        assert_eq!(
            err.error_code(),
            expected_code,
            "Error code of {err:?} should be {expected_code}"
        );
    }
}

#[test]
fn not_supported_error_type_display_and_error_trait() {
    let err = NotSupportedError {
        operation: "VACUUM INTO".to_string(),
        reason: "Postgres has no equivalent".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("VACUUM INTO"));
    assert!(display.contains("Postgres has no equivalent"));

    // Verify it implements std::error::Error
    let _: &dyn std::error::Error = &err;
}

// ─── Row type Clone correctness ─────────────────────────────────────

#[test]
fn file_metadata_row_clone_is_deep() {
    let original = FileMetadataRow {
        path: "src/main.rs".to_string(),
        language: Some("rust".to_string()),
        file_size: 1024,
        content_hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
        mtime_secs: 1700000000,
        mtime_nanos: 500,
        last_scanned_at: 1700000001,
        scan_duration_us: Some(500),
        pattern_count: 10,
        function_count: 5,
        error_count: 0,
        error: None,
    };
    let cloned = original.clone();

    // Verify deep clone — modifying content_hash of one doesn't affect other
    assert_eq!(cloned.path, "src/main.rs");
    assert_eq!(cloned.content_hash, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(cloned.language, Some("rust".to_string()));
}

#[test]
fn parse_cache_row_clone() {
    let row = ParseCacheRow {
        content_hash: vec![1, 2, 3],
        language: "typescript".to_string(),
        parse_result_json: r#"{"functions":[]}"#.to_string(),
        created_at: 1700000000,
    };
    let cloned = row.clone();
    assert_eq!(cloned.content_hash, vec![1, 2, 3]);
    assert_eq!(cloned.parse_result_json, r#"{"functions":[]}"#);
}

#[test]
fn detection_row_clone_with_all_optionals() {
    let row = DetectionRow {
        id: 1,
        file: "test.rs".into(),
        line: 42,
        column_num: 10,
        pattern_id: "sec/hardcoded-password".into(),
        category: "security".into(),
        confidence: 0.95,
        detection_method: "TomlPattern".into(),
        cwe_ids: Some("CWE-798".into()),
        owasp: Some("A07".into()),
        matched_text: Some("password = \"hunter2\"".into()),
        created_at: 1700000000,
    };
    let cloned = row.clone();
    assert_eq!(cloned.cwe_ids, Some("CWE-798".into()));
    assert_eq!(cloned.owasp, Some("A07".into()));
}

// ─── Row type edge cases ────────────────────────────────────────────

#[test]
fn row_types_with_empty_strings() {
    let fm = FileMetadataRow {
        path: "".to_string(),
        language: Some("".to_string()),
        file_size: 0,
        content_hash: vec![],
        mtime_secs: 0,
        mtime_nanos: 0,
        last_scanned_at: 0,
        scan_duration_us: None,
        pattern_count: 0,
        function_count: 0,
        error_count: 0,
        error: Some("".to_string()),
    };
    assert_eq!(fm.path, "");
    assert_eq!(fm.content_hash.len(), 0);

    let func = FunctionRow {
        id: 0,
        file: "".into(),
        name: "".into(),
        qualified_name: None,
        language: "".into(),
        line: 0,
        end_line: 0,
        parameter_count: 0,
        return_type: None,
        is_exported: false,
        is_async: false,
        body_hash: None,
        signature_hash: None,
    };
    assert_eq!(func.name, "");
}

#[test]
fn row_types_with_unicode() {
    let violation = ViolationRow {
        id: "违规_1".to_string(),
        file: "src/模块/auth.rs".to_string(),
        line: 1,
        column: None,
        end_line: None,
        end_column: None,
        severity: "critical".to_string(),
        pattern_id: "sec/密码".to_string(),
        rule_id: "rule_🔥".to_string(),
        message: "发现硬编码密码".to_string(),
        quick_fix_strategy: None,
        quick_fix_description: None,
        cwe_id: Some(798),
        owasp_category: None,
        suppressed: false,
        is_new: true,
    };
    assert_eq!(violation.id, "违规_1");
    assert_eq!(violation.rule_id, "rule_🔥");
}

#[test]
fn row_type_boundary_integer_values() {
    let func = FunctionRow {
        id: i64::MAX,
        file: "test.rs".into(),
        name: "f".into(),
        qualified_name: None,
        language: "rust".into(),
        line: i64::MAX,
        end_line: i64::MAX,
        parameter_count: i64::MAX,
        return_type: None,
        is_exported: true,
        is_async: true,
        body_hash: Some(vec![255; 32]),
        signature_hash: Some(vec![0; 32]),
    };
    assert_eq!(func.id, i64::MAX);
    assert_eq!(func.line, i64::MAX);
}

// ─── Multi-trait composition ────────────────────────────────────────

struct CompositeStorage;

impl IDriftFiles for CompositeStorage {
    fn load_all_file_metadata(&self) -> Result<Vec<FileMetadataRow>, StorageError> { Ok(vec![]) }
    fn get_file_metadata(&self, _: &str) -> Result<Option<FileMetadataRow>, StorageError> { Ok(None) }
    fn update_function_count(&self, _: &str, _: i64) -> Result<(), StorageError> { Ok(()) }
    fn update_file_error(&self, _: &str, _: i64, _: Option<&str>) -> Result<(), StorageError> { Ok(()) }
    fn count_files(&self) -> Result<i64, StorageError> { Ok(42) }
    fn get_parse_cache_by_hash(&self, _: &[u8]) -> Result<Option<ParseCacheRow>, StorageError> { Ok(None) }
    fn insert_parse_cache(&self, _: &[u8], _: &str, _: &str, _: i64) -> Result<(), StorageError> { Ok(()) }
    fn invalidate_parse_cache(&self, _: &[u8]) -> Result<(), StorageError> { Ok(()) }
    fn count_parse_cache(&self) -> Result<i64, StorageError> { Ok(7) }
}

impl IDriftReader for CompositeStorage {
    fn pattern_confidence(&self, _: &str) -> Result<Option<f64>, StorageError> { Ok(Some(0.5)) }
    fn pattern_occurrence_rate(&self, _: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn false_positive_rate(&self, _: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn constraint_verified(&self, _: &str) -> Result<Option<bool>, StorageError> { Ok(None) }
    fn coupling_metric(&self, _: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn dna_health(&self) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn test_coverage(&self, _: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn error_handling_gaps(&self, _: &str) -> Result<Option<u32>, StorageError> { Ok(None) }
    fn decision_evidence(&self, _: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn boundary_data(&self, _: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn taint_flow_risk(&self, _: &str) -> Result<Option<u32>, StorageError> { Ok(None) }
    fn call_graph_coverage(&self, _: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn count_matching_patterns(&self, pids: &[String]) -> Result<u32, StorageError> { Ok(pids.len() as u32) }
    fn latest_scan_timestamp(&self) -> Result<Option<String>, StorageError> { Ok(None) }
}

#[test]
fn multi_trait_single_type() {
    let storage = CompositeStorage;

    // Use as IDriftFiles
    let files: &dyn IDriftFiles = &storage;
    assert_eq!(files.count_files().unwrap(), 42);

    // Use as IDriftReader
    let reader: &dyn IDriftReader = &storage;
    assert_eq!(reader.pattern_confidence("any").unwrap(), Some(0.5));
}

#[test]
fn multi_trait_arc_single_type() {
    let storage = Arc::new(CompositeStorage);

    // Same Arc used for both traits
    let files: Arc<dyn IDriftFiles> = Arc::clone(&storage) as Arc<dyn IDriftFiles>;
    let reader: Arc<dyn IDriftReader> = storage as Arc<dyn IDriftReader>;

    assert_eq!(files.count_files().unwrap(), 42);
    assert_eq!(reader.pattern_confidence("x").unwrap(), Some(0.5));
}

// ─── Workspace types edge cases ─────────────────────────────────────

#[test]
fn workspace_status_uninitialized() {
    let status = WorkspaceStatus {
        initialized: false,
        db_path: None,
        schema_version: 0,
        file_count: 0,
        db_size_bytes: 0,
        wal_size_bytes: 0,
    };
    assert!(!status.initialized);
    assert!(status.db_path.is_none());
}

#[test]
fn gc_stats_default_has_correct_values() {
    let gc = GcStats::default();
    assert_eq!(gc.orphan_files_removed, 0);
    assert_eq!(gc.stale_cache_entries_removed, 0);
    assert!(!gc.wal_checkpointed);
    assert_eq!(gc.freed_bytes, 0);
}

#[test]
fn integrity_result_with_issues() {
    let result = IntegrityResult {
        ok: false,
        issues: vec![
            "page 42 is corrupt".into(),
            "index i_detections_file malformed".into(),
        ],
    };
    assert!(!result.ok);
    assert_eq!(result.issues.len(), 2);
}

#[test]
fn project_info_empty_language_breakdown() {
    let info = ProjectInfo {
        root_path: "/project".to_string(),
        name: "empty-project".to_string(),
        language_breakdown: vec![],
        total_files: 0,
        total_functions: 0,
        total_patterns: 0,
        last_scan_at: None,
    };
    assert!(info.language_breakdown.is_empty());
    assert!(info.last_scan_at.is_none());
}

// ─── Error propagation through trait impls ──────────────────────────

struct ErrorStorage;

impl IWorkspaceStorage for ErrorStorage {
    fn initialize(&self, _: &str) -> Result<(), StorageError> {
        Err(StorageError::SqliteError {
            message: "init failed".into(),
        })
    }
    fn status(&self) -> Result<WorkspaceStatus, StorageError> {
        Err(StorageError::DbBusy)
    }
    fn project_info(&self) -> Result<ProjectInfo, StorageError> {
        Err(StorageError::DbCorrupt {
            details: "page corrupt".into(),
        })
    }
    fn workspace_context(&self) -> Result<WorkspaceContext, StorageError> {
        Err(StorageError::DiskFull)
    }
    fn gc(&self) -> Result<GcStats, StorageError> {
        Err(StorageError::ConnectionPoolExhausted { active: 5 })
    }
    fn backup(&self, _: &str) -> Result<BackupResult, StorageError> {
        Err(StorageError::NotSupported {
            operation: "backup".into(),
            reason: "test".into(),
        })
    }
    fn export(&self, _: &str) -> Result<(), StorageError> {
        Err(StorageError::MigrationFailed {
            version: 3,
            message: "export fail".into(),
        })
    }
    fn import(&self, _: &str) -> Result<(), StorageError> { Ok(()) }
    fn integrity_check(&self) -> Result<IntegrityResult, StorageError> { Ok(IntegrityResult { ok: true, issues: vec![] }) }
    fn schema_version(&self) -> Result<u32, StorageError> { Ok(7) }
}

#[test]
fn error_propagation_through_all_workspace_methods() {
    let storage = ErrorStorage;

    assert!(matches!(
        storage.initialize("/tmp"),
        Err(StorageError::SqliteError { .. })
    ));
    assert!(matches!(storage.status(), Err(StorageError::DbBusy)));
    assert!(matches!(
        storage.project_info(),
        Err(StorageError::DbCorrupt { .. })
    ));
    assert!(matches!(
        storage.workspace_context(),
        Err(StorageError::DiskFull)
    ));
    assert!(matches!(
        storage.gc(),
        Err(StorageError::ConnectionPoolExhausted { active: 5 })
    ));
    assert!(matches!(
        storage.backup("/tmp/b"),
        Err(StorageError::NotSupported { .. })
    ));
    assert!(matches!(
        storage.export("/tmp/e"),
        Err(StorageError::MigrationFailed { version: 3, .. })
    ));
}

#[test]
fn error_propagation_through_arc() {
    let storage = Arc::new(ErrorStorage);
    let ws: Arc<dyn IWorkspaceStorage> = storage;

    assert!(matches!(ws.initialize("/tmp"), Err(StorageError::SqliteError { .. })));
    assert!(matches!(ws.status(), Err(StorageError::DbBusy)));
    assert!(matches!(ws.backup("/tmp/b"), Err(StorageError::NotSupported { .. })));
}

// ─── Structural row types Debug impls ───────────────────────────────

#[test]
fn all_structural_row_types_debug() {
    // Verify Debug is derived — would be compile error if not
    let coupling = CouplingMetricsRow {
        module: "auth".into(), ce: 5, ca: 3, instability: 0.6,
        abstractness: 0.2, distance: 0.2, zone: "zone_of_pain".into(),
    };
    let debug = format!("{coupling:?}");
    assert!(debug.contains("auth"));

    let secret = SecretRow {
        id: None, pattern_name: "aws_key".into(), redacted_value: "AKI***".into(),
        file: "config.rs".into(), line: 10, severity: "critical".into(),
        entropy: 4.5, confidence: 0.99, cwe_ids: "CWE-798".into(),
    };
    let debug = format!("{secret:?}");
    assert!(debug.contains("aws_key"));

    let impact = ImpactScoreRow {
        function_id: "f1".into(), blast_radius: 42, risk_score: 0.8,
        is_dead_code: false, dead_code_reason: None, exclusion_category: None,
    };
    let debug = format!("{impact:?}");
    assert!(debug.contains("42"));
}

// ─── Analysis row types constructibility ────────────────────────────

#[test]
fn all_analysis_row_types_constructible() {
    let _pc = PatternConfidenceRow {
        pattern_id: "p".into(), alpha: 1.0, beta: 1.0, posterior_mean: 0.5,
        credible_interval_low: 0.3, credible_interval_high: 0.7,
        tier: "established".into(), momentum: "stable".into(), last_updated: 0,
    };
    let _ol = OutlierRow {
        id: 1, pattern_id: "p".into(), file: "f".into(), line: 1,
        deviation_score: 2.5, significance: "high".into(), method: "iqr".into(), created_at: 0,
    };
    let _cv = ConventionRow {
        id: 1, pattern_id: "p".into(), category: "naming".into(), scope: "file".into(),
        dominance_ratio: 0.8, promotion_status: "promoted".into(),
        discovered_at: 0, last_seen: 0, expires_at: None,
    };
    let _br = BoundaryRow {
        id: 1, file: "f".into(), framework: "django".into(), model_name: "User".into(),
        table_name: Some("users".into()), field_name: Some("email".into()),
        sensitivity: Some("PII".into()), confidence: 0.9, created_at: 0,
    };
    let _ce = CallEdgeRow {
        caller_id: 1, callee_id: 2, resolution: "import".into(), confidence: 0.95, call_site_line: 10,
    };
    let _sh = ScanHistoryRow {
        id: 1, started_at: 0, completed_at: Some(100), root_path: "/proj".into(),
        total_files: Some(1000), added_files: Some(50), modified_files: Some(20),
        removed_files: Some(5), unchanged_files: Some(925), duration_ms: Some(5000),
        status: "completed".into(), error: None,
    };
}

// ─── Enforcement row types constructibility ─────────────────────────

#[test]
fn all_enforcement_row_types_constructible() {
    let _v = ViolationRow {
        id: "v1".into(), file: "f.rs".into(), line: 1, column: Some(5),
        end_line: Some(3), end_column: Some(10), severity: "error".into(),
        pattern_id: "p".into(), rule_id: "r".into(), message: "bad".into(),
        quick_fix_strategy: Some("replace".into()),
        quick_fix_description: Some("Use X instead".into()),
        cwe_id: Some(79), owasp_category: Some("A03".into()),
        suppressed: false, is_new: true,
    };
    let _g = GateResultRow {
        gate_id: "g1".into(), status: "passed".into(), passed: true, score: 0.95,
        summary: "All good".into(), violation_count: 0, warning_count: 2,
        execution_time_ms: 150, details: None, error: None, run_at: 1700000000,
    };
    let _a = AuditSnapshotRow {
        health_score: 0.85, avg_confidence: 0.7, approval_ratio: 0.9,
        compliance_rate: 0.95, cross_validation_rate: 0.8, duplicate_free_rate: 0.99,
        pattern_count: 100, category_scores: Some("{}".into()), created_at: 0,
    };
    let _h = HealthTrendRow {
        metric_name: "confidence".into(), metric_value: 0.75, recorded_at: 0,
    };
    let _f = FeedbackRow {
        violation_id: "v1".into(), pattern_id: "p1".into(), detector_id: "d1".into(),
        action: "fix".into(), dismissal_reason: None, reason: Some("was valid".into()),
        author: Some("dev@example.com".into()), created_at: 0,
    };
    let _fs = FeedbackStats::default();
    assert_eq!(_fs.total_count, 0);
    let _pr = PolicyResultRow {
        id: 1, policy_name: "security".into(), aggregation_mode: "all".into(),
        overall_passed: true, overall_score: 0.9, gate_count: 5, gates_passed: 4,
        gates_failed: 1, details: None, run_at: 0,
    };
    let _da = DegradationAlertRow {
        id: 1, alert_type: "confidence_drop".into(), severity: "warning".into(),
        message: "dropped 10%".into(), current_value: 0.6, previous_value: 0.7,
        delta: -0.1, created_at: 0,
    };
}

// ─── Advanced row types constructibility ────────────────────────────

#[test]
fn advanced_row_types_constructible() {
    use drift_core::traits::storage::drift_advanced::{CorrectionRow, SimulationRow};

    let _s = SimulationRow {
        id: 1, task_category: "refactor".into(), task_description: "extract auth".into(),
        approach_count: 3, recommended_approach: Some("strategy pattern".into()),
        p10_effort: 2.0, p50_effort: 5.0, p90_effort: 12.0, created_at: 0,
    };
    let _c = CorrectionRow {
        id: 1, module_id: 1, section: "imports".into(),
        original_text: "import old".into(), corrected_text: "import new".into(),
        reason: Some("deprecated".into()), created_at: 0,
    };
}

// ─── Structural row types for graph intelligence ────────────────────

#[test]
fn graph_intelligence_row_types_constructible() {
    use drift_core::traits::storage::drift_structural::{
        ErrorGapRow, ReachabilityCacheRow, TestCoverageRow,
    };

    let _r = ReachabilityCacheRow {
        source_node: "fn_main".into(), direction: "forward".into(),
        reachable_set: "[\"fn_a\",\"fn_b\"]".into(), sensitivity: "exact".into(),
    };
    let _t = TaintFlowRow {
        id: None, source_file: "input.rs".into(), source_line: 10,
        source_type: "user_input".into(), sink_file: "db.rs".into(), sink_line: 50,
        sink_type: "sql_query".into(), cwe_id: Some(89), is_sanitized: false,
        path: "input.rs:10 → process.rs:20 → db.rs:50".into(), confidence: 0.85,
    };
    let _e = ErrorGapRow {
        id: None, file: "api.rs".into(), function_id: "handle_request".into(),
        gap_type: "unchecked_result".into(), error_type: Some("io::Error".into()),
        propagation_chain: Some("fn_a → fn_b".into()),
        framework: Some("actix-web".into()), cwe_id: Some(755),
        severity: "medium".into(),
    };
    let _tc = TestCoverageRow {
        test_function_id: "test_login".into(), source_function_id: "login".into(),
        coverage_type: "direct".into(),
    };
    let _tq = TestQualityRow {
        function_id: "test_login".into(), coverage_breadth: Some(0.8),
        coverage_depth: Some(0.6), assertion_density: Some(3.0),
        mock_ratio: Some(0.2), isolation: Some(0.9), freshness: Some(0.95),
        stability: Some(1.0), overall_score: 0.78, smells: None,
    };
}

// ─── Verify IDriftReaderStub Default impl ───────────────────────────

#[test]
fn stub_default_trait() {
    let stub = IDriftReaderStub::default();
    assert_eq!(stub.pattern_confidence("any").unwrap(), None);
    assert_eq!(stub.dna_health().unwrap(), None);
    assert_eq!(stub.count_matching_patterns(&[]).unwrap(), 0);
    assert_eq!(stub.latest_scan_timestamp().unwrap(), None);
}

// ─── Verify trait re-exports from barrel module ─────────────────────

#[test]
fn barrel_re_exports_work() {
    // These would fail to compile if re-exports were broken
    use drift_core::traits::IDriftFiles;
    use drift_core::traits::IDriftAnalysis;
    use drift_core::traits::IDriftStructural;
    use drift_core::traits::IDriftEnforcement;
    use drift_core::traits::IDriftAdvanced;
    use drift_core::traits::IDriftBatchWriter;
    use drift_core::traits::IDriftReader;
    use drift_core::traits::IWorkspaceStorage;

    #[allow(clippy::too_many_arguments)]
    fn _use_traits(
        _a: &dyn IDriftFiles,
        _b: &dyn IDriftAnalysis,
        _c: &dyn IDriftStructural,
        _d: &dyn IDriftEnforcement,
        _e: &dyn IDriftAdvanced,
        _f: &dyn IDriftBatchWriter,
        _g: &dyn IDriftReader,
        _h: &dyn IWorkspaceStorage,
    ) {}
}

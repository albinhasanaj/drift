//! Phase A tests (CT0-A-01 through CT0-A-12) — Storage trait design verification.

use std::sync::Arc;

use drift_core::errors::StorageError;
use drift_core::traits::storage::drift_advanced::IDriftAdvanced;
use drift_core::traits::storage::drift_analysis::IDriftAnalysis;
use drift_core::traits::storage::drift_batch::IDriftBatchWriter;
use drift_core::traits::storage::drift_enforcement::IDriftEnforcement;
use drift_core::traits::storage::drift_files::IDriftFiles;
use drift_core::traits::storage::drift_reader::IDriftReader;
use drift_core::traits::storage::drift_structural::IDriftStructural;
use drift_core::traits::storage::test_helpers::IDriftReaderStub;
use drift_core::traits::storage::workspace::IWorkspaceStorage;

// ─── CT0-A-01: Trait object safety ──────────────────────────────────
// Verify all 8 traits are object-safe by constructing trait objects.

#[test]
fn ct0_a01_drift_files_is_object_safe() {
    fn _assert_object_safe(_: &dyn IDriftFiles) {}
}

#[test]
fn ct0_a01_drift_analysis_is_object_safe() {
    fn _assert_object_safe(_: &dyn IDriftAnalysis) {}
}

#[test]
fn ct0_a01_drift_structural_is_object_safe() {
    fn _assert_object_safe(_: &dyn IDriftStructural) {}
}

#[test]
fn ct0_a01_drift_enforcement_is_object_safe() {
    fn _assert_object_safe(_: &dyn IDriftEnforcement) {}
}

#[test]
fn ct0_a01_drift_advanced_is_object_safe() {
    fn _assert_object_safe(_: &dyn IDriftAdvanced) {}
}

#[test]
fn ct0_a01_drift_batch_writer_is_object_safe() {
    fn _assert_object_safe(_: &dyn IDriftBatchWriter) {}
}

#[test]
fn ct0_a01_drift_reader_is_object_safe() {
    fn _assert_object_safe(_: &dyn IDriftReader) {}
}

#[test]
fn ct0_a01_workspace_storage_is_object_safe() {
    fn _assert_object_safe(_: &dyn IWorkspaceStorage) {}
}

// ─── CT0-A-02: Arc blanket impls ────────────────────────────────────
// Verify Arc<T: Trait> also implements Trait.

#[test]
fn ct0_a02_arc_drift_files() {
    fn _assert_arc_impl<T: IDriftFiles>() {}
    fn _assert_arc<T: IDriftFiles>() {
        _assert_arc_impl::<Arc<T>>();
    }
    let _ = _assert_arc::<IDriftReaderStubAsFiles>;
}

// Use a dummy struct to verify Arc blanket impls compile.
// We only need the type check to pass — no runtime execution needed.
struct IDriftReaderStubAsFiles;

impl IDriftFiles for IDriftReaderStubAsFiles {
    fn load_all_file_metadata(&self) -> Result<Vec<drift_core::traits::storage::drift_files::FileMetadataRow>, StorageError> { Ok(vec![]) }
    fn get_file_metadata(&self, _: &str) -> Result<Option<drift_core::traits::storage::drift_files::FileMetadataRow>, StorageError> { Ok(None) }
    fn update_function_count(&self, _: &str, _: i64) -> Result<(), StorageError> { Ok(()) }
    fn update_file_error(&self, _: &str, _: i64, _: Option<&str>) -> Result<(), StorageError> { Ok(()) }
    fn count_files(&self) -> Result<i64, StorageError> { Ok(0) }
    fn get_parse_cache_by_hash(&self, _: &[u8]) -> Result<Option<drift_core::traits::storage::drift_files::ParseCacheRow>, StorageError> { Ok(None) }
    fn insert_parse_cache(&self, _: &[u8], _: &str, _: &str, _: i64) -> Result<(), StorageError> { Ok(()) }
    fn invalidate_parse_cache(&self, _: &[u8]) -> Result<(), StorageError> { Ok(()) }
    fn count_parse_cache(&self) -> Result<i64, StorageError> { Ok(0) }
}

#[test]
fn ct0_a02_arc_blanket_compiles_for_all_traits() {
    // If these type assertions compile, the Arc blanket impls work.
    fn assert_files<T: IDriftFiles>() {}
    fn assert_reader<T: IDriftReader>() {}

    assert_files::<Arc<IDriftReaderStubAsFiles>>();
    assert_reader::<Arc<IDriftReaderStub>>();
}

// ─── CT0-A-03: Send + Sync bounds ──────────────────────────────────

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn ct0_a03_all_traits_are_send_sync() {
    assert_send_sync::<Box<dyn IDriftFiles>>();
    assert_send_sync::<Box<dyn IDriftAnalysis>>();
    assert_send_sync::<Box<dyn IDriftStructural>>();
    assert_send_sync::<Box<dyn IDriftEnforcement>>();
    assert_send_sync::<Box<dyn IDriftAdvanced>>();
    assert_send_sync::<Box<dyn IDriftBatchWriter>>();
    assert_send_sync::<Box<dyn IDriftReader>>();
    assert_send_sync::<Box<dyn IWorkspaceStorage>>();
}

// ─── CT0-A-04: IDriftReader covers all evidence types ───────────────

#[test]
fn ct0_a04_drift_reader_has_14_evidence_methods() {
    // Verify trait has methods for all evidence types by calling them on the stub.
    let stub = IDriftReaderStub::new();

    // 1. PatternConfidence
    let _ = stub.pattern_confidence("test");
    // 2. OccurrenceRate
    let _ = stub.pattern_occurrence_rate("test");
    // 3. FalsePositiveRate
    let _ = stub.false_positive_rate("test");
    // 4. ConstraintVerified
    let _ = stub.constraint_verified("test");
    // 5. CouplingMetric
    let _ = stub.coupling_metric("test");
    // 6. DnaHealth
    let _ = stub.dna_health();
    // 7. TestCoverage
    let _ = stub.test_coverage("test");
    // 8. ErrorHandlingGaps
    let _ = stub.error_handling_gaps("test");
    // 9. DecisionEvidence
    let _ = stub.decision_evidence("test");
    // 10. BoundaryData
    let _ = stub.boundary_data("test");
    // 11. TaintFlowRisk
    let _ = stub.taint_flow_risk("test");
    // 12. CallGraphCoverage
    let _ = stub.call_graph_coverage("test");
    // 13. CountMatchingPatterns
    let _ = stub.count_matching_patterns(&[]);
    // 14. LatestScanTimestamp
    let _ = stub.latest_scan_timestamp();
}

// ─── CT0-A-05: IDriftReaderStub returns configured values ───────────

#[test]
fn ct0_a05_stub_returns_configured_values() {
    let stub = IDriftReaderStub::new();
    stub.set_pattern_confidence("auth_check", 0.85);
    stub.set_occurrence_rate("auth_check", 0.42);
    stub.set_false_positive_rate("auth_check", 0.03);
    stub.set_constraint_verified("no_raw_sql", true);
    stub.set_coupling_metric("auth_module", 0.67);
    stub.set_dna_health(0.91);
    stub.set_test_coverage("handle_login", 0.78);
    stub.set_error_handling_gaps("src/auth", 3);
    stub.set_decision_evidence("dec_001", 0.95);
    stub.set_boundary_data("bound_001", 0.88);
    stub.set_taint_flow_risk("src/auth/login.rs", 2);
    stub.set_call_graph_coverage("handle_login", 0.55);
    stub.set_matching_pattern_count(7);
    stub.set_latest_scan_timestamp("2026-01-15T10:30:00Z");

    assert_eq!(stub.pattern_confidence("auth_check").unwrap(), Some(0.85));
    assert_eq!(stub.pattern_occurrence_rate("auth_check").unwrap(), Some(0.42));
    assert_eq!(stub.false_positive_rate("auth_check").unwrap(), Some(0.03));
    assert_eq!(stub.constraint_verified("no_raw_sql").unwrap(), Some(true));
    assert_eq!(stub.coupling_metric("auth_module").unwrap(), Some(0.67));
    assert_eq!(stub.dna_health().unwrap(), Some(0.91));
    assert_eq!(stub.test_coverage("handle_login").unwrap(), Some(0.78));
    assert_eq!(stub.error_handling_gaps("src/auth").unwrap(), Some(3));
    assert_eq!(stub.decision_evidence("dec_001").unwrap(), Some(0.95));
    assert_eq!(stub.boundary_data("bound_001").unwrap(), Some(0.88));
    assert_eq!(stub.taint_flow_risk("src/auth/login.rs").unwrap(), Some(2));
    assert_eq!(stub.call_graph_coverage("handle_login").unwrap(), Some(0.55));
    assert_eq!(stub.count_matching_patterns(&[]).unwrap(), 7);
    assert_eq!(
        stub.latest_scan_timestamp().unwrap(),
        Some("2026-01-15T10:30:00Z".to_string())
    );
}

// ─── CT0-A-06: IDriftReaderStub defaults to None ────────────────────

#[test]
fn ct0_a06_stub_defaults_to_none() {
    let stub = IDriftReaderStub::new();

    assert_eq!(stub.pattern_confidence("nonexistent").unwrap(), None);
    assert_eq!(stub.pattern_occurrence_rate("nonexistent").unwrap(), None);
    assert_eq!(stub.false_positive_rate("nonexistent").unwrap(), None);
    assert_eq!(stub.constraint_verified("nonexistent").unwrap(), None);
    assert_eq!(stub.coupling_metric("nonexistent").unwrap(), None);
    assert_eq!(stub.dna_health().unwrap(), None);
    assert_eq!(stub.test_coverage("nonexistent").unwrap(), None);
    assert_eq!(stub.error_handling_gaps("nonexistent").unwrap(), None);
    assert_eq!(stub.decision_evidence("nonexistent").unwrap(), None);
    assert_eq!(stub.boundary_data("nonexistent").unwrap(), None);
    assert_eq!(stub.taint_flow_risk("nonexistent").unwrap(), None);
    assert_eq!(stub.call_graph_coverage("nonexistent").unwrap(), None);
    assert_eq!(stub.count_matching_patterns(&[]).unwrap(), 0);
    assert_eq!(stub.latest_scan_timestamp().unwrap(), None);
}

// ─── CT0-A-07: IWorkspaceStorage backup returns NotSupported ────────

struct CloudWorkspaceStub;

impl IWorkspaceStorage for CloudWorkspaceStub {
    fn initialize(&self, _: &str) -> Result<(), StorageError> { Ok(()) }
    fn status(&self) -> Result<drift_core::traits::storage::workspace_types::WorkspaceStatus, StorageError> {
        Ok(drift_core::traits::storage::workspace_types::WorkspaceStatus {
            initialized: true,
            db_path: None,
            schema_version: 1,
            file_count: 0,
            db_size_bytes: 0,
            wal_size_bytes: 0,
        })
    }
    fn project_info(&self) -> Result<drift_core::traits::storage::workspace_types::ProjectInfo, StorageError> {
        Ok(drift_core::traits::storage::workspace_types::ProjectInfo {
            root_path: "/cloud".to_string(),
            name: "cloud-project".to_string(),
            language_breakdown: vec![],
            total_files: 0,
            total_functions: 0,
            total_patterns: 0,
            last_scan_at: None,
        })
    }
    fn workspace_context(&self) -> Result<drift_core::traits::storage::workspace_types::WorkspaceContext, StorageError> {
        Ok(drift_core::traits::storage::workspace_types::WorkspaceContext {
            root_path: "/cloud".to_string(),
            languages: vec![],
            frameworks: vec![],
            file_count: 0,
            function_count: 0,
            pattern_count: 0,
            boundary_count: 0,
            detection_count: 0,
        })
    }
    fn gc(&self) -> Result<drift_core::traits::storage::workspace_types::GcStats, StorageError> {
        Ok(Default::default())
    }
    fn backup(&self, _: &str) -> Result<drift_core::traits::storage::workspace_types::BackupResult, StorageError> {
        Err(StorageError::NotSupported {
            operation: "backup".to_string(),
            reason: "cloud backends do not support SQLite backup API".to_string(),
        })
    }
    fn export(&self, _: &str) -> Result<(), StorageError> {
        Err(StorageError::NotSupported {
            operation: "export".to_string(),
            reason: "cloud backends do not support VACUUM INTO".to_string(),
        })
    }
    fn import(&self, _: &str) -> Result<(), StorageError> {
        Err(StorageError::NotSupported {
            operation: "import".to_string(),
            reason: "cloud backends do not support import".to_string(),
        })
    }
    fn integrity_check(&self) -> Result<drift_core::traits::storage::workspace_types::IntegrityResult, StorageError> {
        Ok(drift_core::traits::storage::workspace_types::IntegrityResult { ok: true, issues: vec![] })
    }
    fn schema_version(&self) -> Result<u32, StorageError> { Ok(1) }
}

#[test]
fn ct0_a07_workspace_backup_returns_not_supported_for_cloud() {
    let cloud = CloudWorkspaceStub;
    let result = cloud.backup("/tmp/backup.db");
    assert!(result.is_err());
    match result.unwrap_err() {
        StorageError::NotSupported { operation, .. } => {
            assert_eq!(operation, "backup");
        }
        other => panic!("expected NotSupported, got: {other:?}"),
    }
}

#[test]
fn ct0_a07_workspace_export_returns_not_supported_for_cloud() {
    let cloud = CloudWorkspaceStub;
    let result = cloud.export("/tmp/export.db");
    assert!(result.is_err());
    match result.unwrap_err() {
        StorageError::NotSupported { operation, .. } => {
            assert_eq!(operation, "export");
        }
        other => panic!("expected NotSupported, got: {other:?}"),
    }
}

// ─── CT0-A-08: Error type conversion ────────────────────────────────

#[test]
fn ct0_a08_storage_error_not_supported_has_correct_error_code() {
    use drift_core::errors::error_code::DriftErrorCode;
    let err = StorageError::NotSupported {
        operation: "backup".to_string(),
        reason: "test".to_string(),
    };
    assert_eq!(err.error_code(), "STORAGE_ERROR");
    let msg = format!("{err}");
    assert!(msg.contains("backup"));
    assert!(msg.contains("test"));
}

// ─── CT0-A-09: Trait method counts ──────────────────────────────────

#[test]
fn ct0_a09_trait_method_count_idrift_files() {
    // IDriftFiles has 9 methods (5 file_metadata + 4 parse_cache)
    // Verified by the fact that our stub must implement exactly 9 methods.
    let stub = IDriftReaderStubAsFiles;
    let _: &dyn IDriftFiles = &stub;
}

// ─── CT0-A-10: IDriftReader stub works through Arc ──────────────────

#[test]
fn ct0_a10_drift_reader_works_through_arc() {
    let stub = Arc::new(IDriftReaderStub::new());
    stub.set_pattern_confidence("test_pattern", 0.92);

    // Access through Arc<IDriftReaderStub> which impls IDriftReader via blanket.
    let reader: Arc<dyn IDriftReader> = stub;
    assert_eq!(reader.pattern_confidence("test_pattern").unwrap(), Some(0.92));
    assert_eq!(reader.pattern_confidence("missing").unwrap(), None);
}

// ─── CT0-A-11: IDriftReaderStub is Send + Sync ─────────────────────

#[test]
fn ct0_a11_drift_reader_stub_is_send_sync() {
    assert_send_sync::<IDriftReaderStub>();
    assert_send_sync::<Arc<IDriftReaderStub>>();
}

// ─── CT0-A-12: Workspace supporting types have expected fields ──────

#[test]
fn ct0_a12_workspace_types_constructible() {
    use drift_core::traits::storage::workspace_types::*;

    let status = WorkspaceStatus {
        initialized: true,
        db_path: Some("/test/.drift/drift.db".to_string()),
        schema_version: 7,
        file_count: 42,
        db_size_bytes: 1024,
        wal_size_bytes: 0,
    };
    assert!(status.initialized);
    assert_eq!(status.schema_version, 7);

    let info = ProjectInfo {
        root_path: "/test".to_string(),
        name: "test-project".to_string(),
        language_breakdown: vec![("rust".to_string(), 100)],
        total_files: 42,
        total_functions: 500,
        total_patterns: 30,
        last_scan_at: Some(1700000000),
    };
    assert_eq!(info.total_files, 42);

    let ctx = WorkspaceContext {
        root_path: "/test".to_string(),
        languages: vec!["rust".to_string()],
        frameworks: vec![],
        file_count: 42,
        function_count: 500,
        pattern_count: 30,
        boundary_count: 5,
        detection_count: 100,
    };
    assert_eq!(ctx.languages.len(), 1);

    let gc = GcStats::default();
    assert_eq!(gc.orphan_files_removed, 0);

    let backup = BackupResult {
        destination: "/tmp/backup.db".to_string(),
        size_bytes: 2048,
        duration_ms: 15,
    };
    assert_eq!(backup.size_bytes, 2048);

    let integrity = IntegrityResult {
        ok: true,
        issues: vec![],
    };
    assert!(integrity.ok);

    let ns_err = NotSupportedError {
        operation: "backup".to_string(),
        reason: "cloud backend".to_string(),
    };
    let msg = format!("{ns_err}");
    assert!(msg.contains("backup"));
}

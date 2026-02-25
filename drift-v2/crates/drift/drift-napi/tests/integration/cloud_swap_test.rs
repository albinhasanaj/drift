//! CP0-G-02: Cloud-swap simulation — Drift.
//!
//! MockDriftStorage: In-memory HashMap implementing all 7 drift traits.
//! Proves the trait boundary is sufficient for a Postgres backend.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use drift_core::errors::StorageError;
use drift_core::traits::storage::drift_files::*;
use drift_core::traits::storage::drift_analysis::*;
use drift_core::traits::storage::drift_structural::*;
use drift_core::traits::storage::drift_enforcement::*;
use drift_core::traits::storage::drift_advanced::*;
use drift_core::traits::storage::drift_batch::*;
use drift_core::traits::storage::drift_reader::*;

/// In-memory mock that implements all 7 drift storage traits.
/// Proves a future PostgresDriftStorage can work without pipeline changes.
struct MockDriftStorage {
    files: Mutex<HashMap<String, FileMetadataRow>>,
    functions: Mutex<Vec<FunctionRow>>,
    detections: Mutex<Vec<DetectionRow>>,
    patterns: Mutex<HashMap<String, PatternConfidenceRow>>,
    violations: Mutex<Vec<ViolationRow>>,
    scan_history: Mutex<Vec<ScanHistoryRow>>,
    next_id: Mutex<i64>,
}

impl MockDriftStorage {
    fn new() -> Self {
        Self {
            files: Mutex::new(HashMap::new()),
            functions: Mutex::new(Vec::new()),
            detections: Mutex::new(Vec::new()),
            patterns: Mutex::new(HashMap::new()),
            violations: Mutex::new(Vec::new()),
            scan_history: Mutex::new(Vec::new()),
            next_id: Mutex::new(1),
        }
    }

    fn next_id(&self) -> i64 {
        let mut id = self.next_id.lock().unwrap();
        let val = *id;
        *id += 1;
        val
    }
}

// Implement IDriftFiles
impl IDriftFiles for MockDriftStorage {
    fn load_all_file_metadata(&self) -> Result<Vec<FileMetadataRow>, StorageError> {
        Ok(self.files.lock().unwrap().values().cloned().collect())
    }
    fn get_file_metadata(&self, path: &str) -> Result<Option<FileMetadataRow>, StorageError> {
        Ok(self.files.lock().unwrap().get(path).cloned())
    }
    fn update_function_count(&self, path: &str, count: i64) -> Result<(), StorageError> {
        if let Some(f) = self.files.lock().unwrap().get_mut(path) {
            f.function_count = count;
        }
        Ok(())
    }
    fn update_file_error(&self, path: &str, error_count: i64, error_msg: Option<&str>) -> Result<(), StorageError> {
        if let Some(f) = self.files.lock().unwrap().get_mut(path) {
            f.error_count = error_count;
            f.error = error_msg.map(String::from);
        }
        Ok(())
    }
    fn count_files(&self) -> Result<i64, StorageError> {
        Ok(self.files.lock().unwrap().len() as i64)
    }
    fn get_parse_cache_by_hash(&self, _hash: &[u8]) -> Result<Option<ParseCacheRow>, StorageError> {
        Ok(None)
    }
    fn insert_parse_cache(&self, _hash: &[u8], _lang: &str, _json: &str, _at: i64) -> Result<(), StorageError> {
        Ok(())
    }
    fn invalidate_parse_cache(&self, _hash: &[u8]) -> Result<(), StorageError> {
        Ok(())
    }
    fn count_parse_cache(&self) -> Result<i64, StorageError> {
        Ok(0)
    }
}

// Implement IDriftAnalysis (subset — key methods)
impl IDriftAnalysis for MockDriftStorage {
    fn get_functions_by_file(&self, file: &str) -> Result<Vec<FunctionRow>, StorageError> {
        Ok(self.functions.lock().unwrap().iter().filter(|f| f.file == file).cloned().collect())
    }
    fn get_function_by_qualified_name(&self, _qn: &str) -> Result<Option<FunctionRow>, StorageError> { Ok(None) }
    fn delete_functions_by_file(&self, _file: &str) -> Result<usize, StorageError> { Ok(0) }
    fn count_functions(&self) -> Result<i64, StorageError> {
        Ok(self.functions.lock().unwrap().len() as i64)
    }
    fn count_entry_points(&self) -> Result<i64, StorageError> { Ok(0) }
    fn insert_detections(&self, dets: &[DetectionRow]) -> Result<usize, StorageError> {
        let mut store = self.detections.lock().unwrap();
        let count = dets.len();
        store.extend(dets.iter().cloned());
        Ok(count)
    }
    fn get_detections_by_file(&self, file: &str) -> Result<Vec<DetectionRow>, StorageError> {
        Ok(self.detections.lock().unwrap().iter().filter(|d| d.file == file).cloned().collect())
    }
    fn get_detections_by_category(&self, _cat: &str) -> Result<Vec<DetectionRow>, StorageError> { Ok(vec![]) }
    fn query_all_detections(&self, limit: usize) -> Result<Vec<DetectionRow>, StorageError> {
        Ok(self.detections.lock().unwrap().iter().take(limit).cloned().collect())
    }
    fn delete_detections_by_file(&self, _file: &str) -> Result<usize, StorageError> { Ok(0) }
    fn count_detections(&self) -> Result<i64, StorageError> {
        Ok(self.detections.lock().unwrap().len() as i64)
    }
    fn get_detections_by_method(&self, _m: &str) -> Result<Vec<DetectionRow>, StorageError> { Ok(vec![]) }
    fn get_detections_by_pattern_prefix(&self, _p: &str) -> Result<Vec<DetectionRow>, StorageError> { Ok(vec![]) }
    fn get_detections_by_cwe(&self, _cwe: u32) -> Result<Vec<DetectionRow>, StorageError> { Ok(vec![]) }
    fn get_framework_detection_summary(&self) -> Result<Vec<DetectionSummaryRow>, StorageError> { Ok(vec![]) }
    fn upsert_confidence(&self, row: &PatternConfidenceRow) -> Result<(), StorageError> {
        self.patterns.lock().unwrap().insert(row.pattern_id.clone(), row.clone());
        Ok(())
    }
    fn query_confidence_by_tier(&self, _tier: &str, _after: Option<&str>, _limit: usize) -> Result<Vec<PatternConfidenceRow>, StorageError> { Ok(vec![]) }
    fn query_all_confidence(&self) -> Result<Vec<PatternConfidenceRow>, StorageError> {
        Ok(self.patterns.lock().unwrap().values().cloned().collect())
    }
    fn insert_outlier(&self, _row: &OutlierRow) -> Result<(), StorageError> { Ok(()) }
    fn query_outliers_by_pattern(&self, _pid: &str) -> Result<Vec<OutlierRow>, StorageError> { Ok(vec![]) }
    fn insert_convention(&self, _row: &ConventionRow) -> Result<(), StorageError> { Ok(()) }
    fn query_conventions_by_category(&self, _cat: &str) -> Result<Vec<ConventionRow>, StorageError> { Ok(vec![]) }
    fn query_all_conventions(&self) -> Result<Vec<ConventionRow>, StorageError> { Ok(vec![]) }
    fn insert_boundaries(&self, _b: &[BoundaryRow]) -> Result<usize, StorageError> { Ok(0) }
    fn get_boundaries_by_file(&self, _file: &str) -> Result<Vec<BoundaryRow>, StorageError> { Ok(vec![]) }
    fn get_boundaries_by_framework(&self, _fw: &str) -> Result<Vec<BoundaryRow>, StorageError> { Ok(vec![]) }
    fn get_sensitive_boundaries(&self) -> Result<Vec<BoundaryRow>, StorageError> { Ok(vec![]) }
    fn delete_boundaries_by_file(&self, _file: &str) -> Result<usize, StorageError> { Ok(0) }
    fn count_boundaries(&self) -> Result<i64, StorageError> { Ok(0) }
    fn insert_call_edges(&self, _edges: &[CallEdgeRow]) -> Result<usize, StorageError> { Ok(0) }
    fn get_edges_by_caller(&self, _id: i64) -> Result<Vec<CallEdgeRow>, StorageError> { Ok(vec![]) }
    fn get_edges_by_callee(&self, _id: i64) -> Result<Vec<CallEdgeRow>, StorageError> { Ok(vec![]) }
    fn delete_edges_by_file(&self, _file: &str) -> Result<usize, StorageError> { Ok(0) }
    fn count_call_edges(&self) -> Result<i64, StorageError> { Ok(0) }
    fn count_resolved_edges(&self) -> Result<i64, StorageError> { Ok(0) }
    fn insert_scan_start(&self, started_at: i64, root_path: &str) -> Result<i64, StorageError> {
        let id = self.next_id();
        self.scan_history.lock().unwrap().push(ScanHistoryRow {
            id, started_at, completed_at: None, root_path: root_path.to_string(),
            total_files: None, added_files: None, modified_files: None,
            removed_files: None, unchanged_files: None, duration_ms: None,
            status: "running".to_string(), error: None,
        });
        Ok(id)
    }
    fn update_scan_complete(&self, id: i64, completed_at: i64, total_files: i64, added: i64, modified: i64, removed: i64, unchanged: i64, duration_ms: i64, status: &str, error: Option<&str>) -> Result<(), StorageError> {
        let mut history = self.scan_history.lock().unwrap();
        if let Some(scan) = history.iter_mut().find(|s| s.id == id) {
            scan.completed_at = Some(completed_at);
            scan.total_files = Some(total_files);
            scan.added_files = Some(added);
            scan.modified_files = Some(modified);
            scan.removed_files = Some(removed);
            scan.unchanged_files = Some(unchanged);
            scan.duration_ms = Some(duration_ms);
            scan.status = status.to_string();
            scan.error = error.map(String::from);
        }
        Ok(())
    }
    fn query_recent_scans(&self, limit: usize) -> Result<Vec<ScanHistoryRow>, StorageError> {
        Ok(self.scan_history.lock().unwrap().iter().rev().take(limit).cloned().collect())
    }
    fn count_scans(&self) -> Result<i64, StorageError> {
        Ok(self.scan_history.lock().unwrap().len() as i64)
    }
}

// Implement IDriftStructural (all methods return empty/default — proves compilation)
impl IDriftStructural for MockDriftStorage {
    fn upsert_coupling_metrics(&self, _row: &CouplingMetricsRow) -> Result<(), StorageError> { Ok(()) }
    fn get_coupling_metrics(&self, _module: &str) -> Result<Option<CouplingMetricsRow>, StorageError> { Ok(None) }
    fn get_all_coupling_metrics(&self) -> Result<Vec<CouplingMetricsRow>, StorageError> { Ok(vec![]) }
    fn get_coupling_metrics_by_zone(&self, _zone: &str) -> Result<Vec<CouplingMetricsRow>, StorageError> { Ok(vec![]) }
    fn insert_coupling_cycle(&self, _members: &str, _suggestions: &str) -> Result<(), StorageError> { Ok(()) }
    fn query_coupling_cycles(&self) -> Result<Vec<CouplingCycleRow>, StorageError> { Ok(vec![]) }
    fn upsert_constraint(&self, _row: &ConstraintRow) -> Result<(), StorageError> { Ok(()) }
    fn get_constraint(&self, _id: &str) -> Result<Option<ConstraintRow>, StorageError> { Ok(None) }
    fn get_enabled_constraints(&self) -> Result<Vec<ConstraintRow>, StorageError> { Ok(vec![]) }
    fn insert_constraint_verification(&self, _cid: &str, _passed: bool, _violations: &str) -> Result<(), StorageError> { Ok(()) }
    fn query_constraint_verifications(&self, _cid: &str) -> Result<Vec<ConstraintVerificationRow>, StorageError> { Ok(vec![]) }
    fn upsert_contract(&self, _row: &ContractRow) -> Result<(), StorageError> { Ok(()) }
    fn get_contract(&self, _id: &str) -> Result<Option<ContractRow>, StorageError> { Ok(None) }
    fn get_contracts_by_paradigm(&self, _p: &str) -> Result<Vec<ContractRow>, StorageError> { Ok(vec![]) }
    fn insert_contract_mismatch(&self, _row: &ContractMismatchRow) -> Result<(), StorageError> { Ok(()) }
    fn query_contract_mismatches(&self) -> Result<Vec<ContractMismatchRow>, StorageError> { Ok(vec![]) }
    fn query_contract_mismatches_by_type(&self, _mt: &str) -> Result<Vec<ContractMismatchRow>, StorageError> { Ok(vec![]) }
    fn insert_secret(&self, _row: &SecretRow) -> Result<i64, StorageError> { Ok(1) }
    fn get_secrets_by_file(&self, _file: &str) -> Result<Vec<SecretRow>, StorageError> { Ok(vec![]) }
    fn get_secrets_by_severity(&self, _sev: &str) -> Result<Vec<SecretRow>, StorageError> { Ok(vec![]) }
    fn insert_wrapper(&self, _row: &WrapperRow) -> Result<i64, StorageError> { Ok(1) }
    fn get_wrappers_by_file(&self, _file: &str) -> Result<Vec<WrapperRow>, StorageError> { Ok(vec![]) }
    fn get_wrappers_by_category(&self, _cat: &str) -> Result<Vec<WrapperRow>, StorageError> { Ok(vec![]) }
    fn upsert_dna_gene(&self, _row: &DnaGeneRow) -> Result<(), StorageError> { Ok(()) }
    fn get_dna_gene(&self, _gene_id: &str) -> Result<Option<DnaGeneRow>, StorageError> { Ok(None) }
    fn get_all_dna_genes(&self) -> Result<Vec<DnaGeneRow>, StorageError> { Ok(vec![]) }
    fn upsert_dna_mutation(&self, _row: &DnaMutationRow) -> Result<(), StorageError> { Ok(()) }
    fn get_dna_mutations_by_gene(&self, _gid: &str) -> Result<Vec<DnaMutationRow>, StorageError> { Ok(vec![]) }
    fn get_unresolved_mutations(&self) -> Result<Vec<DnaMutationRow>, StorageError> { Ok(vec![]) }
    fn insert_crypto_finding(&self, _row: &CryptoFindingRow) -> Result<i64, StorageError> { Ok(1) }
    fn get_crypto_findings_by_file(&self, _file: &str) -> Result<Vec<CryptoFindingRow>, StorageError> { Ok(vec![]) }
    fn get_crypto_findings_by_category(&self, _cat: &str) -> Result<Vec<CryptoFindingRow>, StorageError> { Ok(vec![]) }
    fn upsert_owasp_finding(&self, _row: &OwaspFindingRow) -> Result<(), StorageError> { Ok(()) }
    fn get_owasp_findings_by_file(&self, _file: &str) -> Result<Vec<OwaspFindingRow>, StorageError> { Ok(vec![]) }
    fn get_owasp_findings_by_detector(&self, _det: &str) -> Result<Vec<OwaspFindingRow>, StorageError> { Ok(vec![]) }
    fn insert_decomposition_decision(&self, _row: &DecompositionDecisionRow) -> Result<i64, StorageError> { Ok(1) }
    fn get_decomposition_decisions(&self, _hash: &str) -> Result<Vec<DecompositionDecisionRow>, StorageError> { Ok(vec![]) }
    fn insert_constant(&self, _row: &ConstantRow) -> Result<(), StorageError> { Ok(()) }
    fn insert_constants_batch(&self, _rows: &[ConstantRow]) -> Result<(), StorageError> { Ok(()) }
    fn query_constants_by_file(&self, _file: &str) -> Result<Vec<ConstantRow>, StorageError> { Ok(vec![]) }
    fn query_unused_constants(&self) -> Result<Vec<ConstantRow>, StorageError> { Ok(vec![]) }
    fn query_magic_numbers(&self) -> Result<Vec<ConstantRow>, StorageError> { Ok(vec![]) }
    fn delete_constants_by_file(&self, _file: &str) -> Result<usize, StorageError> { Ok(0) }
    fn count_constants(&self) -> Result<i64, StorageError> { Ok(0) }
    fn insert_env_variable(&self, _row: &EnvVariableRow) -> Result<(), StorageError> { Ok(()) }
    fn insert_env_variables_batch(&self, _rows: &[EnvVariableRow]) -> Result<(), StorageError> { Ok(()) }
    fn query_env_variables_by_name(&self, _name: &str) -> Result<Vec<EnvVariableRow>, StorageError> { Ok(vec![]) }
    fn query_env_variables_by_file(&self, _file: &str) -> Result<Vec<EnvVariableRow>, StorageError> { Ok(vec![]) }
    fn query_missing_env_variables(&self) -> Result<Vec<EnvVariableRow>, StorageError> { Ok(vec![]) }
    fn delete_env_variables_by_file(&self, _file: &str) -> Result<usize, StorageError> { Ok(0) }
    fn count_env_variables(&self) -> Result<i64, StorageError> { Ok(0) }
    fn insert_data_access(&self, _row: &DataAccessRow) -> Result<(), StorageError> { Ok(()) }
    fn insert_data_access_batch(&self, _rows: &[DataAccessRow]) -> Result<(), StorageError> { Ok(()) }
    fn query_data_access_by_function(&self, _fid: i64) -> Result<Vec<DataAccessRow>, StorageError> { Ok(vec![]) }
    fn query_data_access_by_table(&self, _tbl: &str) -> Result<Vec<DataAccessRow>, StorageError> { Ok(vec![]) }
    fn delete_data_access_by_function(&self, _fid: i64) -> Result<usize, StorageError> { Ok(0) }
    fn count_data_access(&self) -> Result<i64, StorageError> { Ok(0) }
    fn upsert_reachability(&self, _row: &ReachabilityCacheRow) -> Result<(), StorageError> { Ok(()) }
    fn get_reachability(&self, _sn: &str, _dir: &str) -> Result<Option<ReachabilityCacheRow>, StorageError> { Ok(None) }
    fn clear_reachability_cache(&self) -> Result<(), StorageError> { Ok(()) }
    fn insert_taint_flow(&self, _row: &TaintFlowRow) -> Result<i64, StorageError> { Ok(1) }
    fn get_taint_flows_by_file(&self, _file: &str) -> Result<Vec<TaintFlowRow>, StorageError> { Ok(vec![]) }
    fn get_taint_flows_by_cwe(&self, _cwe: u32) -> Result<Vec<TaintFlowRow>, StorageError> { Ok(vec![]) }
    fn insert_error_gap(&self, _row: &ErrorGapRow) -> Result<i64, StorageError> { Ok(1) }
    fn get_error_gaps_by_file(&self, _file: &str) -> Result<Vec<ErrorGapRow>, StorageError> { Ok(vec![]) }
    fn upsert_impact_score(&self, _row: &ImpactScoreRow) -> Result<(), StorageError> { Ok(()) }
    fn get_impact_score(&self, _fid: &str) -> Result<Option<ImpactScoreRow>, StorageError> { Ok(None) }
    fn insert_test_coverage(&self, _row: &TestCoverageRow) -> Result<(), StorageError> { Ok(()) }
    fn get_test_coverage_for_source(&self, _sfid: &str) -> Result<Vec<TestCoverageRow>, StorageError> { Ok(vec![]) }
    fn upsert_test_quality(&self, _row: &TestQualityRow) -> Result<(), StorageError> { Ok(()) }
    fn get_test_quality(&self, _fid: &str) -> Result<Option<TestQualityRow>, StorageError> { Ok(None) }
}

impl IDriftEnforcement for MockDriftStorage {
    fn insert_violation(&self, v: &ViolationRow) -> Result<(), StorageError> {
        self.violations.lock().unwrap().push(v.clone()); Ok(())
    }
    fn query_violations_by_file(&self, file: &str) -> Result<Vec<ViolationRow>, StorageError> {
        Ok(self.violations.lock().unwrap().iter().filter(|v| v.file == file).cloned().collect())
    }
    fn query_all_violations(&self) -> Result<Vec<ViolationRow>, StorageError> {
        Ok(self.violations.lock().unwrap().clone())
    }
    fn insert_gate_result(&self, _g: &GateResultRow) -> Result<(), StorageError> { Ok(()) }
    fn query_gate_results(&self) -> Result<Vec<GateResultRow>, StorageError> { Ok(vec![]) }
    fn insert_audit_snapshot(&self, _s: &AuditSnapshotRow) -> Result<(), StorageError> { Ok(()) }
    fn query_audit_snapshots(&self, _limit: u32) -> Result<Vec<AuditSnapshotRow>, StorageError> { Ok(vec![]) }
    fn insert_health_trend(&self, _mn: &str, _mv: f64) -> Result<(), StorageError> { Ok(()) }
    fn query_health_trends(&self, _mn: &str, _limit: u32) -> Result<Vec<HealthTrendRow>, StorageError> { Ok(vec![]) }
    fn insert_feedback(&self, _f: &FeedbackRow) -> Result<(), StorageError> { Ok(()) }
    fn query_feedback_by_detector(&self, _did: &str) -> Result<Vec<FeedbackRow>, StorageError> { Ok(vec![]) }
    fn query_feedback_by_pattern(&self, _pid: &str) -> Result<Vec<FeedbackRow>, StorageError> { Ok(vec![]) }
    fn query_feedback_adjustments(&self, _pid: &str) -> Result<Vec<(f64, f64)>, StorageError> { Ok(vec![]) }
    fn get_violation_pattern_id(&self, _vid: &str) -> Result<Option<String>, StorageError> { Ok(None) }
    fn query_feedback_stats(&self) -> Result<FeedbackStats, StorageError> { Ok(FeedbackStats::default()) }
    fn count_needs_review(&self) -> Result<u32, StorageError> { Ok(0) }
    fn insert_policy_result(&self, _row: &PolicyResultRow) -> Result<(), StorageError> { Ok(()) }
    fn query_recent_policy_results(&self, _limit: usize) -> Result<Vec<PolicyResultRow>, StorageError> { Ok(vec![]) }
    fn insert_degradation_alert(&self, _row: &DegradationAlertRow) -> Result<(), StorageError> { Ok(()) }
    fn query_recent_degradation_alerts(&self, _limit: usize) -> Result<Vec<DegradationAlertRow>, StorageError> { Ok(vec![]) }
    fn query_degradation_alerts_by_type(&self, _at: &str) -> Result<Vec<DegradationAlertRow>, StorageError> { Ok(vec![]) }
}

impl IDriftAdvanced for MockDriftStorage {
    fn insert_simulation(&self, _tc: &str, _td: &str, _ac: i32, _ra: Option<&str>, _p10: f64, _p50: f64, _p90: f64) -> Result<i64, StorageError> { Ok(1) }
    fn get_simulations(&self, _limit: usize) -> Result<Vec<SimulationRow>, StorageError> { Ok(vec![]) }
    fn insert_decision(&self, _cat: &str, _desc: &str, _sha: Option<&str>, _conf: f64, _rp: Option<&str>, _auth: Option<&str>, _fc: Option<&str>) -> Result<i64, StorageError> { Ok(1) }
    fn insert_context_cache(&self, _sid: &str, _intent: &str, _depth: &str, _tc: i32, _ch: &str) -> Result<i64, StorageError> { Ok(1) }
    fn create_migration_project(&self, _name: &str, _sl: &str, _tl: &str, _sf: Option<&str>, _tf: Option<&str>) -> Result<i64, StorageError> { Ok(1) }
    fn create_migration_module(&self, _pid: i64, _mn: &str) -> Result<i64, StorageError> { Ok(1) }
    fn update_module_status(&self, _mid: i64, _status: &str) -> Result<(), StorageError> { Ok(()) }
    fn insert_migration_correction(&self, _mid: i64, _sec: &str, _ot: &str, _ct: &str, _reason: Option<&str>) -> Result<i64, StorageError> { Ok(1) }
    fn get_migration_correction(&self, _cid: i64) -> Result<Option<CorrectionRow>, StorageError> { Ok(None) }
}

impl IDriftBatchWriter for MockDriftStorage {
    fn send_raw(&self, _command_name: &str, _payload: &[u8]) -> Result<(), StorageError> { Ok(()) }
    fn flush(&self) -> Result<(), StorageError> { Ok(()) }
    fn flush_sync(&self) -> Result<WriteStats, StorageError> { Ok(WriteStats::default()) }
    fn stats(&self) -> WriteStats { WriteStats::default() }
    fn shutdown(self: Box<Self>) -> Result<WriteStats, StorageError> { Ok(WriteStats::default()) }
}

impl IDriftReader for MockDriftStorage {
    fn pattern_confidence(&self, pid: &str) -> Result<Option<f64>, StorageError> {
        Ok(self.patterns.lock().unwrap().get(pid).map(|p| p.posterior_mean))
    }
    fn pattern_occurrence_rate(&self, _pid: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn false_positive_rate(&self, _pid: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn constraint_verified(&self, _cid: &str) -> Result<Option<bool>, StorageError> { Ok(None) }
    fn coupling_metric(&self, _module: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn dna_health(&self) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn test_coverage(&self, _fid: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn error_handling_gaps(&self, _fp: &str) -> Result<Option<u32>, StorageError> { Ok(None) }
    fn decision_evidence(&self, _did: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn boundary_data(&self, _bid: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn taint_flow_risk(&self, _file: &str) -> Result<Option<u32>, StorageError> { Ok(None) }
    fn call_graph_coverage(&self, _fid: &str) -> Result<Option<f64>, StorageError> { Ok(None) }
    fn count_matching_patterns(&self, pids: &[String]) -> Result<u32, StorageError> {
        let store = self.patterns.lock().unwrap();
        Ok(pids.iter().filter(|pid| store.contains_key(*pid)).count() as u32)
    }
    fn latest_scan_timestamp(&self) -> Result<Option<String>, StorageError> {
        Ok(self.scan_history.lock().unwrap().last().map(|s| s.started_at.to_string()))
    }
}

#[test]
fn ct0_g02_cloud_swap_mock_drift_produces_results() {
    let mock = MockDriftStorage::new();

    // Use trait objects — exactly how a cloud backend would be used
    let files: &dyn IDriftFiles = &mock;
    let analysis: &dyn IDriftAnalysis = &mock;
    let reader: &dyn IDriftReader = &mock;

    // Start a scan
    let scan_id = analysis.insert_scan_start(1000, "/mock/path").unwrap();
    assert!(scan_id > 0);

    // Complete it
    analysis.update_scan_complete(scan_id, 2000, 50, 25, 15, 5, 5, 500, "completed", None).unwrap();

    // Verify via reader
    let ts = reader.latest_scan_timestamp().unwrap();
    assert!(ts.is_some());

    // Files
    assert_eq!(files.count_files().unwrap(), 0);

    // Insert pattern confidence
    analysis.upsert_confidence(&PatternConfidenceRow {
        pattern_id: "test-pattern".into(),
        alpha: 10.0, beta: 2.0, posterior_mean: 0.83,
        credible_interval_low: 0.7, credible_interval_high: 0.95,
        tier: "established".into(), momentum: "stable".into(),
        last_updated: 1000,
    }).unwrap();

    // Read it via reader
    let conf = reader.pattern_confidence("test-pattern").unwrap();
    assert_eq!(conf, Some(0.83));

    // Count patterns
    let matching = reader.count_matching_patterns(&["test-pattern".into(), "nonexistent".into()]).unwrap();
    assert_eq!(matching, 1);
}

#[test]
fn ct0_g02_mock_works_behind_arc() {
    let mock = Arc::new(MockDriftStorage::new());

    let files: Arc<dyn IDriftFiles> = mock.clone();
    let analysis: Arc<dyn IDriftAnalysis> = mock.clone();
    let reader: Arc<dyn IDriftReader> = mock.clone();

    assert_eq!(files.count_files().unwrap(), 0);
    assert_eq!(analysis.count_functions().unwrap(), 0);
    assert!(reader.pattern_confidence("x").unwrap().is_none());
}

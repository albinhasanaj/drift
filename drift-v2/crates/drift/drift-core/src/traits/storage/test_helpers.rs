//! `IDriftReaderStub` — in-memory test double for `IDriftReader`.
//!
//! Used by bridge tests to avoid creating real drift.db connections.

use crate::errors::StorageError;
use std::collections::HashMap;
use std::sync::Mutex;

use super::drift_reader::IDriftReader;

/// In-memory stub implementation of `IDriftReader`.
///
/// All methods return `Ok(None)` or `Ok(0)` by default. Use the `set_*`
/// methods to configure return values for specific inputs.
pub struct IDriftReaderStub {
    pattern_confidences: Mutex<HashMap<String, f64>>,
    occurrence_rates: Mutex<HashMap<String, f64>>,
    false_positive_rates: Mutex<HashMap<String, f64>>,
    constraint_verified: Mutex<HashMap<String, bool>>,
    coupling_metrics: Mutex<HashMap<String, f64>>,
    dna_health_value: Mutex<Option<f64>>,
    test_coverages: Mutex<HashMap<String, f64>>,
    error_gaps: Mutex<HashMap<String, u32>>,
    decision_evidences: Mutex<HashMap<String, f64>>,
    boundary_data: Mutex<HashMap<String, f64>>,
    taint_risks: Mutex<HashMap<String, u32>>,
    call_graph_coverages: Mutex<HashMap<String, f64>>,
    matching_pattern_count: Mutex<Option<u32>>,
    latest_scan: Mutex<Option<String>>,
}

impl IDriftReaderStub {
    /// Create a new stub with all methods returning defaults.
    pub fn new() -> Self {
        Self {
            pattern_confidences: Mutex::new(HashMap::new()),
            occurrence_rates: Mutex::new(HashMap::new()),
            false_positive_rates: Mutex::new(HashMap::new()),
            constraint_verified: Mutex::new(HashMap::new()),
            coupling_metrics: Mutex::new(HashMap::new()),
            dna_health_value: Mutex::new(None),
            test_coverages: Mutex::new(HashMap::new()),
            error_gaps: Mutex::new(HashMap::new()),
            decision_evidences: Mutex::new(HashMap::new()),
            boundary_data: Mutex::new(HashMap::new()),
            taint_risks: Mutex::new(HashMap::new()),
            call_graph_coverages: Mutex::new(HashMap::new()),
            matching_pattern_count: Mutex::new(None),
            latest_scan: Mutex::new(None),
        }
    }

    pub fn set_pattern_confidence(&self, pattern_id: &str, value: f64) {
        self.pattern_confidences.lock().unwrap().insert(pattern_id.to_string(), value);
    }

    pub fn set_occurrence_rate(&self, pattern_id: &str, value: f64) {
        self.occurrence_rates.lock().unwrap().insert(pattern_id.to_string(), value);
    }

    pub fn set_false_positive_rate(&self, pattern_id: &str, value: f64) {
        self.false_positive_rates.lock().unwrap().insert(pattern_id.to_string(), value);
    }

    pub fn set_constraint_verified(&self, constraint_id: &str, value: bool) {
        self.constraint_verified.lock().unwrap().insert(constraint_id.to_string(), value);
    }

    pub fn set_coupling_metric(&self, module: &str, value: f64) {
        self.coupling_metrics.lock().unwrap().insert(module.to_string(), value);
    }

    pub fn set_dna_health(&self, value: f64) {
        *self.dna_health_value.lock().unwrap() = Some(value);
    }

    pub fn set_test_coverage(&self, function_id: &str, value: f64) {
        self.test_coverages.lock().unwrap().insert(function_id.to_string(), value);
    }

    pub fn set_error_handling_gaps(&self, file_prefix: &str, count: u32) {
        self.error_gaps.lock().unwrap().insert(file_prefix.to_string(), count);
    }

    pub fn set_decision_evidence(&self, decision_id: &str, value: f64) {
        self.decision_evidences.lock().unwrap().insert(decision_id.to_string(), value);
    }

    pub fn set_boundary_data(&self, boundary_id: &str, value: f64) {
        self.boundary_data.lock().unwrap().insert(boundary_id.to_string(), value);
    }

    pub fn set_taint_flow_risk(&self, file: &str, count: u32) {
        self.taint_risks.lock().unwrap().insert(file.to_string(), count);
    }

    pub fn set_call_graph_coverage(&self, function_id: &str, value: f64) {
        self.call_graph_coverages.lock().unwrap().insert(function_id.to_string(), value);
    }

    pub fn set_matching_pattern_count(&self, count: u32) {
        *self.matching_pattern_count.lock().unwrap() = Some(count);
    }

    pub fn set_latest_scan_timestamp(&self, ts: &str) {
        *self.latest_scan.lock().unwrap() = Some(ts.to_string());
    }
}

impl Default for IDriftReaderStub {
    fn default() -> Self {
        Self::new()
    }
}

impl IDriftReader for IDriftReaderStub {
    fn pattern_confidence(&self, pid: &str) -> Result<Option<f64>, StorageError> {
        Ok(self.pattern_confidences.lock().unwrap().get(pid).copied())
    }
    fn pattern_occurrence_rate(&self, pid: &str) -> Result<Option<f64>, StorageError> {
        Ok(self.occurrence_rates.lock().unwrap().get(pid).copied())
    }
    fn false_positive_rate(&self, pid: &str) -> Result<Option<f64>, StorageError> {
        Ok(self.false_positive_rates.lock().unwrap().get(pid).copied())
    }
    fn constraint_verified(&self, cid: &str) -> Result<Option<bool>, StorageError> {
        Ok(self.constraint_verified.lock().unwrap().get(cid).copied())
    }
    fn coupling_metric(&self, module: &str) -> Result<Option<f64>, StorageError> {
        Ok(self.coupling_metrics.lock().unwrap().get(module).copied())
    }
    fn dna_health(&self) -> Result<Option<f64>, StorageError> {
        Ok(*self.dna_health_value.lock().unwrap())
    }
    fn test_coverage(&self, fid: &str) -> Result<Option<f64>, StorageError> {
        Ok(self.test_coverages.lock().unwrap().get(fid).copied())
    }
    fn error_handling_gaps(&self, fp: &str) -> Result<Option<u32>, StorageError> {
        Ok(self.error_gaps.lock().unwrap().get(fp).copied())
    }
    fn decision_evidence(&self, did: &str) -> Result<Option<f64>, StorageError> {
        Ok(self.decision_evidences.lock().unwrap().get(did).copied())
    }
    fn boundary_data(&self, bid: &str) -> Result<Option<f64>, StorageError> {
        Ok(self.boundary_data.lock().unwrap().get(bid).copied())
    }
    fn taint_flow_risk(&self, file: &str) -> Result<Option<u32>, StorageError> {
        Ok(self.taint_risks.lock().unwrap().get(file).copied())
    }
    fn call_graph_coverage(&self, fid: &str) -> Result<Option<f64>, StorageError> {
        Ok(self.call_graph_coverages.lock().unwrap().get(fid).copied())
    }
    fn count_matching_patterns(&self, _pids: &[String]) -> Result<u32, StorageError> {
        Ok(self.matching_pattern_count.lock().unwrap().unwrap_or(0))
    }
    fn latest_scan_timestamp(&self) -> Result<Option<String>, StorageError> {
        Ok(self.latest_scan.lock().unwrap().clone())
    }
}

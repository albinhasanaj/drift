//! `IDriftEnforcement` trait — violations, gate results, audit, health trends,
//! feedback, policy results, degradation alerts.
//!
//! Maps to `drift-storage/src/queries/enforcement.rs`.

use crate::errors::StorageError;
use std::sync::Arc;

// ─── Row Types ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ViolationRow {
    pub id: String,
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
    pub severity: String,
    pub pattern_id: String,
    pub rule_id: String,
    pub message: String,
    pub quick_fix_strategy: Option<String>,
    pub quick_fix_description: Option<String>,
    pub cwe_id: Option<u32>,
    pub owasp_category: Option<String>,
    pub suppressed: bool,
    pub is_new: bool,
}

#[derive(Debug, Clone)]
pub struct GateResultRow {
    pub gate_id: String,
    pub status: String,
    pub passed: bool,
    pub score: f64,
    pub summary: String,
    pub violation_count: u32,
    pub warning_count: u32,
    pub execution_time_ms: u64,
    pub details: Option<String>,
    pub error: Option<String>,
    pub run_at: u64,
}

#[derive(Debug, Clone)]
pub struct AuditSnapshotRow {
    pub health_score: f64,
    pub avg_confidence: f64,
    pub approval_ratio: f64,
    pub compliance_rate: f64,
    pub cross_validation_rate: f64,
    pub duplicate_free_rate: f64,
    pub pattern_count: u32,
    pub category_scores: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct HealthTrendRow {
    pub metric_name: String,
    pub metric_value: f64,
    pub recorded_at: u64,
}

#[derive(Debug, Clone)]
pub struct FeedbackRow {
    pub violation_id: String,
    pub pattern_id: String,
    pub detector_id: String,
    pub action: String,
    pub dismissal_reason: Option<String>,
    pub reason: Option<String>,
    pub author: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Default)]
pub struct FeedbackStats {
    pub total_count: u32,
    pub fix_count: u32,
    pub dismiss_count: u32,
    pub suppress_count: u32,
    pub escalate_count: u32,
}

#[derive(Debug, Clone)]
pub struct PolicyResultRow {
    pub id: i64,
    pub policy_name: String,
    pub aggregation_mode: String,
    pub overall_passed: bool,
    pub overall_score: f64,
    pub gate_count: i64,
    pub gates_passed: i64,
    pub gates_failed: i64,
    pub details: Option<String>,
    pub run_at: i64,
}

#[derive(Debug, Clone)]
pub struct DegradationAlertRow {
    pub id: i64,
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub current_value: f64,
    pub previous_value: f64,
    pub delta: f64,
    pub created_at: i64,
}

// ─── Trait ───────────────────────────────────────────────────────────

/// Enforcement storage operations.
///
/// Covers: violations, gate_results, audit_snapshots, health_trends,
/// feedback, policy_results, degradation_alerts.
pub trait IDriftEnforcement: Send + Sync {
    // ── violations ──

    fn insert_violation(&self, v: &ViolationRow) -> Result<(), StorageError>;
    fn query_violations_by_file(&self, file: &str) -> Result<Vec<ViolationRow>, StorageError>;
    fn query_all_violations(&self) -> Result<Vec<ViolationRow>, StorageError>;

    // ── gate_results ──

    fn insert_gate_result(&self, g: &GateResultRow) -> Result<(), StorageError>;
    fn query_gate_results(&self) -> Result<Vec<GateResultRow>, StorageError>;

    // ── audit_snapshots ──

    fn insert_audit_snapshot(&self, s: &AuditSnapshotRow) -> Result<(), StorageError>;
    fn query_audit_snapshots(&self, limit: u32) -> Result<Vec<AuditSnapshotRow>, StorageError>;

    // ── health_trends ──

    fn insert_health_trend(&self, metric_name: &str, metric_value: f64) -> Result<(), StorageError>;
    fn query_health_trends(&self, metric_name: &str, limit: u32) -> Result<Vec<HealthTrendRow>, StorageError>;

    // ── feedback ──

    fn insert_feedback(&self, f: &FeedbackRow) -> Result<(), StorageError>;
    fn query_feedback_by_detector(&self, detector_id: &str) -> Result<Vec<FeedbackRow>, StorageError>;
    fn query_feedback_by_pattern(&self, pattern_id: &str) -> Result<Vec<FeedbackRow>, StorageError>;
    fn query_feedback_adjustments(&self, pattern_id: &str) -> Result<Vec<(f64, f64)>, StorageError>;
    fn get_violation_pattern_id(&self, violation_id: &str) -> Result<Option<String>, StorageError>;
    fn query_feedback_stats(&self) -> Result<FeedbackStats, StorageError>;
    fn count_needs_review(&self) -> Result<u32, StorageError>;

    // ── policy_results ──

    fn insert_policy_result(&self, row: &PolicyResultRow) -> Result<(), StorageError>;
    fn query_recent_policy_results(&self, limit: usize) -> Result<Vec<PolicyResultRow>, StorageError>;

    // ── degradation_alerts ──

    fn insert_degradation_alert(&self, row: &DegradationAlertRow) -> Result<(), StorageError>;
    fn query_recent_degradation_alerts(&self, limit: usize) -> Result<Vec<DegradationAlertRow>, StorageError>;
    fn query_degradation_alerts_by_type(&self, alert_type: &str) -> Result<Vec<DegradationAlertRow>, StorageError>;
}

// ─── Arc blanket impl ───────────────────────────────────────────────

impl<T: IDriftEnforcement + ?Sized> IDriftEnforcement for Arc<T> {
    fn insert_violation(&self, v: &ViolationRow) -> Result<(), StorageError> { (**self).insert_violation(v) }
    fn query_violations_by_file(&self, f: &str) -> Result<Vec<ViolationRow>, StorageError> { (**self).query_violations_by_file(f) }
    fn query_all_violations(&self) -> Result<Vec<ViolationRow>, StorageError> { (**self).query_all_violations() }
    fn insert_gate_result(&self, g: &GateResultRow) -> Result<(), StorageError> { (**self).insert_gate_result(g) }
    fn query_gate_results(&self) -> Result<Vec<GateResultRow>, StorageError> { (**self).query_gate_results() }
    fn insert_audit_snapshot(&self, s: &AuditSnapshotRow) -> Result<(), StorageError> { (**self).insert_audit_snapshot(s) }
    fn query_audit_snapshots(&self, limit: u32) -> Result<Vec<AuditSnapshotRow>, StorageError> { (**self).query_audit_snapshots(limit) }
    fn insert_health_trend(&self, mn: &str, mv: f64) -> Result<(), StorageError> { (**self).insert_health_trend(mn, mv) }
    fn query_health_trends(&self, mn: &str, limit: u32) -> Result<Vec<HealthTrendRow>, StorageError> { (**self).query_health_trends(mn, limit) }
    fn insert_feedback(&self, f: &FeedbackRow) -> Result<(), StorageError> { (**self).insert_feedback(f) }
    fn query_feedback_by_detector(&self, did: &str) -> Result<Vec<FeedbackRow>, StorageError> { (**self).query_feedback_by_detector(did) }
    fn query_feedback_by_pattern(&self, pid: &str) -> Result<Vec<FeedbackRow>, StorageError> { (**self).query_feedback_by_pattern(pid) }
    fn query_feedback_adjustments(&self, pid: &str) -> Result<Vec<(f64, f64)>, StorageError> { (**self).query_feedback_adjustments(pid) }
    fn get_violation_pattern_id(&self, vid: &str) -> Result<Option<String>, StorageError> { (**self).get_violation_pattern_id(vid) }
    fn query_feedback_stats(&self) -> Result<FeedbackStats, StorageError> { (**self).query_feedback_stats() }
    fn count_needs_review(&self) -> Result<u32, StorageError> { (**self).count_needs_review() }
    fn insert_policy_result(&self, row: &PolicyResultRow) -> Result<(), StorageError> { (**self).insert_policy_result(row) }
    fn query_recent_policy_results(&self, limit: usize) -> Result<Vec<PolicyResultRow>, StorageError> { (**self).query_recent_policy_results(limit) }
    fn insert_degradation_alert(&self, row: &DegradationAlertRow) -> Result<(), StorageError> { (**self).insert_degradation_alert(row) }
    fn query_recent_degradation_alerts(&self, limit: usize) -> Result<Vec<DegradationAlertRow>, StorageError> { (**self).query_recent_degradation_alerts(limit) }
    fn query_degradation_alerts_by_type(&self, at: &str) -> Result<Vec<DegradationAlertRow>, StorageError> { (**self).query_degradation_alerts_by_type(at) }
}

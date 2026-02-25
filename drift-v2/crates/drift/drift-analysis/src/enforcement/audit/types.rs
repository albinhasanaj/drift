//! Audit system types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete result of an audit run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub health_score: f64,
    pub health_breakdown: HealthBreakdown,
    pub category_health: HashMap<String, CategoryHealth>,
    pub degradation_alerts: Vec<DegradationAlert>,
    pub trends: AuditTrends,
    pub prediction: Option<TrendPrediction>,
    pub anomalies: Vec<AuditAnomaly>,
    pub auto_approved: Vec<String>,
    pub needs_review: Vec<String>,
    pub likely_false_positives: Vec<String>,
    pub duplicate_groups: Vec<DuplicateGroup>,
}

/// Breakdown of the 5-factor health score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthBreakdown {
    /// Average pattern confidence [0.0, 1.0]. Weight: 0.30.
    pub avg_confidence: f64,
    /// Approved patterns / total patterns [0.0, 1.0]. Weight: 0.20.
    pub approval_ratio: f64,
    /// Locations / (locations + outliers) [0.0, 1.0]. Weight: 0.20.
    pub compliance_rate: f64,
    /// Cross-validation rate [0.0, 1.0]. Weight: 0.15.
    pub cross_validation_rate: f64,
    /// 1 - (patterns in duplicate groups / total) [0.0, 1.0]. Weight: 0.15.
    pub duplicate_free_rate: f64,
    /// The computed raw score before scaling.
    pub raw_score: f64,
}

/// Per-category health score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryHealth {
    pub category: String,
    pub score: f64,
    pub pattern_count: usize,
    pub avg_confidence: f64,
    pub compliance_rate: f64,
    pub trend: TrendDirection,
}

/// Degradation alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradationAlert {
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub current_value: f64,
    pub previous_value: f64,
    pub delta: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    HealthDrop,
    ConfidenceDrop,
    FalsePositiveIncrease,
    DuplicateIncrease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Warning,
    Critical,
}

/// Trend indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrends {
    pub health_trend: TrendDirection,
    pub confidence_trend: TrendDirection,
    pub pattern_growth: PatternGrowth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrendDirection {
    Improving,
    Stable,
    Declining,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternGrowth {
    Healthy,
    Rapid,
    Stagnant,
}

/// Trend prediction via linear regression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPrediction {
    pub predicted_score_7d: f64,
    pub predicted_score_30d: f64,
    pub slope: f64,
    pub confidence_interval: f64,
    pub direction: TrendDirection,
}

/// Anomaly detected in audit metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAnomaly {
    pub metric: String,
    pub z_score: f64,
    pub value: f64,
    pub mean: f64,
    pub std_dev: f64,
    pub message: String,
}

/// Duplicate pattern group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub pattern_ids: Vec<String>,
    pub similarity: f64,
    pub action: DuplicateAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateAction {
    /// Similarity > 0.95 — safe to auto-merge.
    AutoMerge,
    /// Similarity > 0.90 — recommend merge.
    Merge,
    /// Similarity 0.85-0.90 — needs human review.
    Review,
}

/// Snapshot of audit state for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSnapshot {
    pub health_score: f64,
    pub avg_confidence: f64,
    pub approval_ratio: f64,
    pub compliance_rate: f64,
    pub cross_validation_rate: f64,
    pub duplicate_free_rate: f64,
    pub pattern_count: usize,
    pub category_scores: HashMap<String, f64>,
    pub timestamp: u64,
    /// Root path of the scan that produced this snapshot.
    /// Used to prevent false degradation alerts when comparing scans with different scopes.
    #[serde(default)]
    pub root_path: Option<String>,
    /// Total files in the scan that produced this snapshot.
    #[serde(default)]
    pub total_files: Option<usize>,
}

/// Input data for audit processing.
#[derive(Debug, Clone, Default)]
pub struct AuditInput {
    pub patterns: Vec<PatternAuditData>,
    pub previous_snapshot: Option<AuditSnapshot>,
    pub history: Vec<AuditSnapshot>,
}

/// Pattern data for audit processing.
#[derive(Debug, Clone)]
pub struct PatternAuditData {
    pub id: String,
    pub name: String,
    pub category: String,
    pub status: PatternStatus,
    pub confidence: f64,
    pub location_count: usize,
    pub outlier_count: usize,
    pub in_call_graph: bool,
    pub constraint_issues: usize,
    pub has_error_issues: bool,
    /// Location strings (e.g. "file.ts:10") for Jaccard deduplication.
    /// When empty, falls back to count-ratio proxy.
    pub locations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternStatus {
    Discovered,
    Approved,
    Ignored,
}

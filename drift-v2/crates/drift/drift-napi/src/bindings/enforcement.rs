//! NAPI bindings for enforcement systems (Phase 6).
//!
//! Exposes drift_check(), drift_audit(), drift_violations(), drift_gates(),
//! drift_approve_pattern(), drift_pattern_status().

#[allow(unused_imports)]
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::{Deserialize, Serialize};

use crate::conversions::error_codes;
use crate::runtime;

// ─── Violation Types ─────────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsViolation {
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

// ─── Gate Result Types ───────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsGateResult {
    pub gate_id: String,
    pub status: String,
    pub passed: bool,
    pub score: f64,
    pub summary: String,
    pub violation_count: u32,
    pub warning_count: u32,
    pub execution_time_ms: u32,
    pub details: Option<String>,
    pub error: Option<String>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCheckResult {
    pub overall_passed: bool,
    pub total_violations: u32,
    pub gates: Vec<JsGateResult>,
    pub sarif: Option<String>,
}

// ─── Audit Types ─────────────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsHealthBreakdown {
    pub avg_confidence: f64,
    pub approval_ratio: f64,
    pub compliance_rate: f64,
    pub cross_validation_rate: f64,
    pub duplicate_free_rate: f64,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsAuditResult {
    pub health_score: f64,
    pub breakdown: JsHealthBreakdown,
    pub trend: String,
    pub degradation_alerts: Vec<String>,
    pub auto_approved_count: u32,
    pub needs_review_count: u32,
    pub data_completeness: f64,
}

// ─── NAPI Functions ──────────────────────────────────────────────────

/// Run quality gate checks on the project.
#[napi]
pub fn drift_check(_root: String) -> napi::Result<JsCheckResult> {
    let rt = runtime::get()?;

    let violations = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_all_violations(conn)
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    let gates = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_gate_results(conn)
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    let js_gates: Vec<JsGateResult> = gates.iter().map(|g| JsGateResult {
        gate_id: g.gate_id.clone(),
        status: g.status.clone(),
        passed: g.passed,
        score: g.score,
        summary: g.summary.clone(),
        violation_count: g.violation_count,
        warning_count: g.warning_count,
        execution_time_ms: g.execution_time_ms as u32,
        details: g.details.clone(),
        error: g.error.clone(),
    }).collect();

    // Fix 05: Exclude empty/skipped gates from overall_passed
    let active_gates: Vec<&JsGateResult> = js_gates.iter()
        .filter(|g| g.status != "skipped" && g.status != "no_data")
        .collect();
    let overall_passed = active_gates.is_empty() || active_gates.iter().all(|g| g.passed);

    // PH2-04: Generate SARIF inline
    let sarif = drift_analysis::enforcement::reporters::create_reporter("sarif")
        .and_then(|reporter| {
            let gate_results = storage_to_gate_results(&violations, &gates);
            reporter.generate(&gate_results).ok()
        });

    Ok(JsCheckResult {
        overall_passed,
        total_violations: violations.len() as u32,
        gates: js_gates,
        sarif,
    })
}

/// Run audit analysis on the project.
///
/// Wires the full upstream pipeline:
/// 1. Builds PatternAuditData from pattern_confidence + detections + outliers + pattern_status
/// 2. Runs AutoApprover::classify to get auto-approved / needs_review / likely_fp lists
/// 3. Persists auto-approved statuses into pattern_status table
/// 4. Computes health score from real pattern data
#[napi]
pub fn drift_audit(_root: String) -> napi::Result<JsAuditResult> {
    let rt = runtime::get()?;

    // Fix 06 Part A: Clear stale alerts older than 24h
    let _ = rt.storage.with_writer(|conn| {
        drift_storage::queries::enforcement::clear_recovered_alerts(conn)
    });

    let alerts = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_recent_degradation_alerts(conn, 50)
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    let alert_messages: Vec<String> = alerts.iter().map(|a| a.message.clone()).collect();

    // ─── Build PatternAuditData from upstream tables ─────────────────
    let audit_rows = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_patterns_for_audit(conn)
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    let pattern_audit_data: Vec<drift_analysis::enforcement::audit::PatternAuditData> = audit_rows
        .iter()
        .map(|r| drift_analysis::enforcement::audit::PatternAuditData {
            id: r.pattern_id.clone(),
            name: r.pattern_id.clone(),
            category: r.category.clone(),
            status: match r.status.as_str() {
                "approved" => drift_analysis::enforcement::audit::PatternStatus::Approved,
                "ignored" => drift_analysis::enforcement::audit::PatternStatus::Ignored,
                _ => drift_analysis::enforcement::audit::PatternStatus::Discovered,
            },
            confidence: r.confidence,
            location_count: r.location_count,
            outlier_count: r.outlier_count,
            in_call_graph: false,
            constraint_issues: 0,
            has_error_issues: r.has_error_issues,
            locations: Vec::new(),
        })
        .collect();

    // ─── Run AutoApprover classification ─────────────────────────────
    let approver = drift_analysis::enforcement::audit::AutoApprover::new();
    let (auto_approved_ids, needs_review_ids, _likely_fp_ids) =
        approver.classify(&pattern_audit_data);

    let auto_approved_count = auto_approved_ids.len() as u32;
    let needs_review_count = needs_review_ids.len() as u32;

    // ─── Persist auto-approved statuses ──────────────────────────────
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    for pid in &auto_approved_ids {
        let confidence = audit_rows.iter()
            .find(|r| &r.pattern_id == pid)
            .map(|r| r.confidence);

        let status_row = drift_storage::queries::enforcement::PatternStatusRow {
            pattern_id: pid.clone(),
            status: "approved".to_string(),
            approved_by: Some("auto".to_string()),
            approved_at: Some(now),
            confidence_at_approval: confidence,
            reason: Some("Auto-approved: meets stability criteria (confidence ≥ 0.90, outlier ratio ≤ 0.50, locations ≥ 3)".to_string()),
            updated_at: now,
        };
        let _ = rt.storage.with_writer(|conn| {
            drift_storage::queries::enforcement::upsert_pattern_status(conn, &status_row)
        });
    }

    // Ensure discovered patterns that weren't auto-approved have a status row
    for pid in &needs_review_ids {
        let _ = rt.storage.with_writer(|conn| {
            // Only insert if not already tracked (don't overwrite user decisions)
            let existing = drift_storage::queries::enforcement::query_pattern_status(conn, pid)?;
            if existing.is_none() {
                let status_row = drift_storage::queries::enforcement::PatternStatusRow {
                    pattern_id: pid.clone(),
                    status: "discovered".to_string(),
                    approved_by: None,
                    approved_at: None,
                    confidence_at_approval: None,
                    reason: None,
                    updated_at: now,
                };
                drift_storage::queries::enforcement::upsert_pattern_status(conn, &status_row)?;
            }
            Ok::<(), drift_core::errors::StorageError>(())
        });
    }

    // ─── Compute health metrics from real pattern data ───────────────
    let total_patterns = pattern_audit_data.len();

    let avg_confidence = if pattern_audit_data.is_empty() {
        0.0
    } else {
        pattern_audit_data.iter().map(|p| p.confidence).sum::<f64>() / total_patterns as f64
    };

    // Approval ratio from pattern_status (approved / total)
    let approved_count = pattern_audit_data.iter()
        .filter(|p| p.status == drift_analysis::enforcement::audit::PatternStatus::Approved)
        .count() + auto_approved_ids.len();
    let approval_ratio = if total_patterns > 0 {
        (approved_count as f64 / total_patterns as f64).min(1.0)
    } else {
        0.0
    };

    let trend = if alerts.is_empty() { "stable" } else { "degrading" };

    // Cross-validation rate from gate results
    let gates = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_gate_results(conn)
    }).unwrap_or_default();
    let active_gates: Vec<&drift_storage::queries::enforcement::GateResultRow> = gates.iter()
        .filter(|g| g.status != "skipped" && g.status != "no_data")
        .collect();
    let cross_validation_rate = if active_gates.is_empty() {
        1.0
    } else {
        active_gates.iter().filter(|g| g.passed).count() as f64 / active_gates.len() as f64
    };

    // Compliance rate from violations
    let violations = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_all_violations(conn)
    }).unwrap_or_default();
    let compliance_rate = if violations.is_empty() {
        1.0
    } else {
        violations.iter().filter(|v| v.suppressed).count() as f64 / violations.len() as f64
    };

    // Adaptive weighted health scoring — only include factors with data
    let mut factors: Vec<(f64, &str)> = Vec::new();

    if !pattern_audit_data.is_empty() {
        factors.push((avg_confidence, "avg_confidence"));
    }
    if total_patterns > 0 {
        factors.push((approval_ratio, "approval_ratio"));
    }
    factors.push((compliance_rate, "compliance_rate"));
    if !active_gates.is_empty() {
        factors.push((cross_validation_rate, "cross_validation_rate"));
    }
    factors.push((1.0, "duplicate_free_rate"));

    let max_factors = 5;
    let data_completeness = factors.len() as f64 / max_factors as f64;

    let health_score = if factors.is_empty() {
        50.0
    } else {
        let sum: f64 = factors.iter().map(|(v, _)| v).sum();
        (sum / factors.len() as f64 * 100.0).clamp(0.0, 100.0)
    };

    // Cap degradation penalty at 20 points max deduction
    let alert_penalty = (alerts.len() as f64 * 2.0).min(20.0);
    let health_score = if !alerts.is_empty() {
        (health_score - alert_penalty).max(0.0)
    } else {
        health_score
    };

    Ok(JsAuditResult {
        health_score,
        breakdown: JsHealthBreakdown {
            avg_confidence,
            approval_ratio,
            compliance_rate,
            cross_validation_rate,
            duplicate_free_rate: 1.0,
        },
        trend: trend.to_string(),
        degradation_alerts: alert_messages,
        auto_approved_count,
        needs_review_count,
        data_completeness,
    })
}

/// Query violations for the project.
#[napi]
pub fn drift_violations(_root: String) -> napi::Result<Vec<JsViolation>> {
    let rt = runtime::get()?;

    let rows = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_all_violations(conn)
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    Ok(rows.into_iter().map(|v| JsViolation {
        id: v.id,
        file: v.file,
        line: v.line,
        column: v.column,
        end_line: v.end_line,
        end_column: v.end_column,
        severity: v.severity,
        pattern_id: v.pattern_id,
        rule_id: v.rule_id,
        message: v.message,
        quick_fix_strategy: v.quick_fix_strategy,
        quick_fix_description: v.quick_fix_description,
        cwe_id: v.cwe_id,
        owasp_category: v.owasp_category,
        suppressed: v.suppressed,
        is_new: v.is_new,
    }).collect())
}

/// Generate a report in the specified format from stored violations and gate results.
///
/// Supported formats: "sarif", "json", "html", "junit", "sonarqube", "console", "github", "gitlab"
#[napi]
pub fn drift_report(format: String) -> napi::Result<String> {
    let rt = runtime::get()?;

    let violations = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_all_violations(conn)
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    let gates = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_gate_results(conn)
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    // Convert storage rows to enforcement gate results
    let gate_results = storage_to_gate_results(&violations, &gates);

    // Create reporter and generate output
    let reporter = drift_analysis::enforcement::reporters::create_reporter(&format)
        .ok_or_else(|| napi::Error::from_reason(format!(
            "[{}] Unknown report format: '{}'. Supported: sarif, json, html, junit, sonarqube, console, github, gitlab",
            error_codes::INVALID_ARGUMENT, format
        )))?;

    reporter.generate(&gate_results)
        .map_err(|e| napi::Error::from_reason(format!("[{}] Report generation failed: {e}", error_codes::INTERNAL_ERROR)))
}

/// Convert storage rows into enforcement GateResult structs for reporters.
fn storage_to_gate_results(
    violations: &[drift_storage::queries::enforcement::ViolationRow],
    gates: &[drift_storage::queries::enforcement::GateResultRow],
) -> Vec<drift_analysis::enforcement::gates::GateResult> {
    use drift_analysis::enforcement::gates::{GateId, GateResult, GateStatus};
    use drift_analysis::enforcement::rules::types::{Severity, Violation};

    let mut all_violations: Vec<Violation> = violations.iter().map(|v| {
        Violation {
            id: v.id.clone(),
            file: v.file.clone(),
            line: v.line,
            column: v.column,
            end_line: v.end_line,
            end_column: v.end_column,
            severity: match v.severity.as_str() {
                "critical" | "error" => Severity::Error,
                "high" | "warning" => Severity::Warning,
                "medium" | "info" => Severity::Info,
                _ => Severity::Hint,
            },
            pattern_id: v.pattern_id.clone(),
            rule_id: v.rule_id.clone(),
            message: v.message.clone(),
            cwe_id: v.cwe_id,
            owasp_category: v.owasp_category.clone(),
            suppressed: v.suppressed,
            is_new: v.is_new,
            quick_fix: v.quick_fix_strategy.as_ref().and_then(|s| {
                use drift_analysis::enforcement::rules::types::QuickFixStrategy;
                let strategy = match s.as_str() {
                    "add_import" => QuickFixStrategy::AddImport,
                    "rename" => QuickFixStrategy::Rename,
                    "extract_function" => QuickFixStrategy::ExtractFunction,
                    "wrap_in_try_catch" => QuickFixStrategy::WrapInTryCatch,
                    "add_type_annotation" => QuickFixStrategy::AddTypeAnnotation,
                    "add_test" => QuickFixStrategy::AddTest,
                    "add_documentation" => QuickFixStrategy::AddDocumentation,
                    "use_parameterized_query" => QuickFixStrategy::UseParameterizedQuery,
                    _ => return None,
                };
                Some(drift_analysis::enforcement::rules::types::QuickFix {
                    strategy,
                    description: v.quick_fix_description.clone().unwrap_or_default(),
                    replacement: None,
                })
            }),
        }
    }).collect();

    if gates.is_empty() {
        // No gate results stored — create a single synthetic gate
        return vec![GateResult {
            gate_id: GateId::PatternCompliance,
            status: if all_violations.iter().any(|v| matches!(v.severity, Severity::Error)) {
                GateStatus::Failed
            } else {
                GateStatus::Passed
            },
            passed: !all_violations.iter().any(|v| matches!(v.severity, Severity::Error) && !v.suppressed),
            score: 0.0,
            summary: format!("{} violations found", all_violations.len()),
            violations: all_violations,
            warnings: vec![],
            execution_time_ms: 0,
            details: serde_json::Value::Null,
            error: None,
        }];
    }

    let gate_count = gates.len();
    gates.iter().enumerate().map(|(idx, g)| {
        let gate_id = match g.gate_id.as_str() {
            "pattern-compliance" => GateId::PatternCompliance,
            "constraint-verification" => GateId::ConstraintVerification,
            "security-boundaries" => GateId::SecurityBoundaries,
            "test-coverage" => GateId::TestCoverage,
            "error-handling" => GateId::ErrorHandling,
            "regression" => GateId::Regression,
            _ => GateId::PatternCompliance,
        };
        let status = match g.status.as_str() {
            "passed" => GateStatus::Passed,
            "failed" => GateStatus::Failed,
            "skipped" => GateStatus::Skipped,
            _ => GateStatus::Failed,
        };
        let details = g.details.as_ref()
            .and_then(|d| serde_json::from_str(d).ok())
            .unwrap_or(serde_json::Value::Null);

        GateResult {
            gate_id,
            status,
            passed: g.passed,
            score: g.score,
            summary: g.summary.clone(),
            violations: if idx + 1 == gate_count {
                std::mem::take(&mut all_violations)
            } else {
                all_violations.clone()
            },
            warnings: vec![],
            execution_time_ms: g.execution_time_ms,
            details,
            error: g.error.clone(),
        }
    }).collect()
}

/// Query gate results for the project.
#[napi]
pub fn drift_gates(_root: String) -> napi::Result<Vec<JsGateResult>> {
    let rt = runtime::get()?;

    let rows = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_gate_results(conn)
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    Ok(rows.into_iter().map(|g| JsGateResult {
        gate_id: g.gate_id,
        status: g.status,
        passed: g.passed,
        score: g.score,
        summary: g.summary,
        violation_count: g.violation_count,
        warning_count: g.warning_count,
        execution_time_ms: g.execution_time_ms as u32,
        details: g.details,
        error: g.error,
    }).collect())
}

// ─── Pattern Status Types ───────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsPatternStatusEntry {
    pub pattern_id: String,
    pub status: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<f64>,
    pub confidence_at_approval: Option<f64>,
    pub reason: Option<String>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsPatternStatusResult {
    pub patterns: Vec<JsPatternStatusEntry>,
    pub total: u32,
    pub counts: JsPatternStatusCounts,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsPatternStatusCounts {
    pub discovered: u32,
    pub approved: u32,
    pub ignored: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsApprovePatternResult {
    pub success: bool,
    pub pattern_id: String,
    pub previous_status: String,
    pub new_status: String,
    pub message: String,
}

// ─── Pattern Approval NAPI ──────────────────────────────────────────

/// Approve or ignore a pattern by ID.
///
/// Sets the pattern_status to the given status ("approved" or "ignored").
/// User approvals always override auto-approvals.
#[napi]
pub fn drift_approve_pattern(
    pattern_id: String,
    status: String,
    reason: Option<String>,
) -> napi::Result<JsApprovePatternResult> {
    let rt = runtime::get()?;

    // Validate status
    let valid_statuses = ["approved", "ignored", "discovered"];
    if !valid_statuses.contains(&status.as_str()) {
        return Err(napi::Error::from_reason(format!(
            "[{}] Invalid status '{}'. Must be one of: approved, ignored, discovered",
            error_codes::INVALID_ARGUMENT, status
        )));
    }

    // Get current status
    let previous = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_pattern_status(conn, &pattern_id)
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    let previous_status = previous
        .as_ref()
        .map(|p| p.status.clone())
        .unwrap_or_else(|| "discovered".to_string());

    // Look up current confidence for the pattern
    let confidence = rt.storage.with_reader(|conn| {
        let scores = drift_storage::queries::patterns::query_all_confidence(conn)?;
        Ok(scores.iter().find(|s| s.pattern_id == pattern_id).map(|s| s.posterior_mean))
    }).map_err(|e: drift_core::errors::StorageError| {
        napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR))
    })?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let (approved_by, approved_at) = if status == "approved" {
        (Some("user".to_string()), Some(now))
    } else {
        (None, None)
    };

    let confidence_at_approval = if status == "approved" { confidence } else { None };

    let status_row = drift_storage::queries::enforcement::PatternStatusRow {
        pattern_id: pattern_id.clone(),
        status: status.clone(),
        approved_by,
        approved_at,
        confidence_at_approval,
        reason: reason.clone(),
        updated_at: now,
    };

    // User approval always wins — direct upsert (the SQL CASE only protects auto vs user)
    rt.storage.with_writer(|conn| {
        // For user approvals, we force-overwrite by using a direct update if row exists
        let existing = drift_storage::queries::enforcement::query_pattern_status(conn, &pattern_id)?;
        if existing.is_some() {
            conn.execute(
                "UPDATE pattern_status SET status = ?1, approved_by = ?2, approved_at = ?3, confidence_at_approval = ?4, reason = ?5, updated_at = ?6 WHERE pattern_id = ?7",
                rusqlite::params![status_row.status, status_row.approved_by, status_row.approved_at, status_row.confidence_at_approval, status_row.reason, status_row.updated_at, status_row.pattern_id],
            ).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
        } else {
            drift_storage::queries::enforcement::upsert_pattern_status(conn, &status_row)?;
        }
        Ok(())
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    Ok(JsApprovePatternResult {
        success: true,
        pattern_id: pattern_id.clone(),
        previous_status,
        new_status: status,
        message: format!(
            "Pattern {} status updated{}",
            pattern_id,
            reason.as_ref().map(|r| format!(": {r}")).unwrap_or_default()
        ),
    })
}

/// Query pattern statuses with optional status filter.
///
/// Returns pattern lifecycle data: discovered, approved (auto/user), or ignored.
#[napi]
pub fn drift_pattern_status(
    status_filter: Option<String>,
) -> napi::Result<JsPatternStatusResult> {
    let rt = runtime::get()?;

    let rows = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_all_pattern_statuses(
            conn,
            status_filter.as_deref(),
        )
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    let counts_raw = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::count_patterns_by_status(conn)
    }).map_err(|e| napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR)))?;

    let mut counts = JsPatternStatusCounts {
        discovered: 0,
        approved: 0,
        ignored: 0,
    };
    for (status, count) in &counts_raw {
        match status.as_str() {
            "discovered" => counts.discovered = *count,
            "approved" => counts.approved = *count,
            "ignored" => counts.ignored = *count,
            _ => {}
        }
    }

    let total = rows.len() as u32;

    let patterns: Vec<JsPatternStatusEntry> = rows.into_iter().map(|r| JsPatternStatusEntry {
        pattern_id: r.pattern_id,
        status: r.status,
        approved_by: r.approved_by,
        approved_at: r.approved_at.map(|t| t as f64),
        confidence_at_approval: r.confidence_at_approval,
        reason: r.reason,
    }).collect();

    Ok(JsPatternStatusResult {
        patterns,
        total,
        counts,
    })
}

//! V006 migration: Phase 6 tables for enforcement systems.
//!
//! Tables: violations, gate_results, audit_snapshots, health_trends, feedback

pub const MIGRATION_SQL: &str = r#"
-- Violations table
CREATE TABLE IF NOT EXISTS violations (
    id TEXT PRIMARY KEY,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column_num INTEGER,
    end_line INTEGER,
    end_column INTEGER,
    severity TEXT NOT NULL,
    pattern_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    message TEXT NOT NULL,
    quick_fix_strategy TEXT,
    quick_fix_description TEXT,
    cwe_id INTEGER,
    owasp_category TEXT,
    suppressed INTEGER NOT NULL DEFAULT 0,
    is_new INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_violations_file ON violations(file);
CREATE INDEX IF NOT EXISTS idx_violations_severity ON violations(severity);
CREATE INDEX IF NOT EXISTS idx_violations_pattern ON violations(pattern_id);
CREATE INDEX IF NOT EXISTS idx_violations_rule ON violations(rule_id);
CREATE INDEX IF NOT EXISTS idx_violations_cwe ON violations(cwe_id);

-- Gate results table
CREATE TABLE IF NOT EXISTS gate_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    gate_id TEXT NOT NULL,
    status TEXT NOT NULL,
    passed INTEGER NOT NULL,
    score REAL NOT NULL,
    summary TEXT NOT NULL,
    violation_count INTEGER NOT NULL DEFAULT 0,
    warning_count INTEGER NOT NULL DEFAULT 0,
    execution_time_ms INTEGER NOT NULL DEFAULT 0,
    details TEXT,
    error TEXT,
    run_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_gate_results_gate ON gate_results(gate_id);
CREATE INDEX IF NOT EXISTS idx_gate_results_run ON gate_results(run_at);
"#;

pub const MIGRATION_SQL_PART2: &str = r#"
-- Audit snapshots table
CREATE TABLE IF NOT EXISTS audit_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    health_score REAL NOT NULL,
    avg_confidence REAL NOT NULL,
    approval_ratio REAL NOT NULL,
    compliance_rate REAL NOT NULL,
    cross_validation_rate REAL NOT NULL,
    duplicate_free_rate REAL NOT NULL,
    pattern_count INTEGER NOT NULL DEFAULT 0,
    category_scores TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_snapshots_created ON audit_snapshots(created_at);

-- Health trends table
CREATE TABLE IF NOT EXISTS health_trends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    recorded_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_health_trends_metric ON health_trends(metric_name);
CREATE INDEX IF NOT EXISTS idx_health_trends_recorded ON health_trends(recorded_at);

-- Feedback table
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    violation_id TEXT NOT NULL,
    pattern_id TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    action TEXT NOT NULL,
    dismissal_reason TEXT,
    reason TEXT,
    author TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_feedback_violation ON feedback(violation_id);
CREATE INDEX IF NOT EXISTS idx_feedback_detector ON feedback(detector_id);
CREATE INDEX IF NOT EXISTS idx_feedback_pattern ON feedback(pattern_id);
CREATE INDEX IF NOT EXISTS idx_feedback_action ON feedback(action);

-- Policy results table
CREATE TABLE IF NOT EXISTS policy_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_name TEXT NOT NULL,
    aggregation_mode TEXT NOT NULL,
    overall_passed INTEGER NOT NULL,
    overall_score REAL NOT NULL,
    gate_count INTEGER NOT NULL,
    gates_passed INTEGER NOT NULL,
    gates_failed INTEGER NOT NULL,
    details TEXT,
    run_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- Degradation alerts table
CREATE TABLE IF NOT EXISTS degradation_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    current_value REAL NOT NULL,
    previous_value REAL NOT NULL,
    delta REAL NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
"#;

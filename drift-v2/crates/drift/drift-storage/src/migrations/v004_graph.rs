//! V004 migration: Phase 4 tables for graph intelligence systems.
//!
//! Tables: reachability_cache, taint_flows, error_gaps, impact_scores,
//!         test_coverage, test_quality.

pub const MIGRATION_SQL: &str = r#"
-- Reachability cache
CREATE TABLE IF NOT EXISTS reachability_cache (
    source_node TEXT NOT NULL,
    direction TEXT NOT NULL,
    reachable_set TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    computed_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (source_node, direction)
) STRICT;

-- Taint flows (source → sink paths)
CREATE TABLE IF NOT EXISTS taint_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT NOT NULL,
    source_line INTEGER NOT NULL,
    source_type TEXT NOT NULL,
    sink_file TEXT NOT NULL,
    sink_line INTEGER NOT NULL,
    sink_type TEXT NOT NULL,
    cwe_id INTEGER,
    is_sanitized INTEGER NOT NULL DEFAULT 0,
    path TEXT NOT NULL,
    confidence REAL NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_taint_flows_source ON taint_flows(source_file);
CREATE INDEX IF NOT EXISTS idx_taint_flows_sink ON taint_flows(sink_file);
CREATE INDEX IF NOT EXISTS idx_taint_flows_cwe ON taint_flows(cwe_id);

-- Error handling gaps
CREATE TABLE IF NOT EXISTS error_gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT NOT NULL,
    function_id TEXT NOT NULL,
    gap_type TEXT NOT NULL,
    error_type TEXT,
    propagation_chain TEXT,
    framework TEXT,
    cwe_id INTEGER,
    severity TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_error_gaps_file ON error_gaps(file);
CREATE INDEX IF NOT EXISTS idx_error_gaps_type ON error_gaps(gap_type);
CREATE INDEX IF NOT EXISTS idx_error_gaps_severity ON error_gaps(severity);

-- Impact scores per function
CREATE TABLE IF NOT EXISTS impact_scores (
    function_id TEXT PRIMARY KEY,
    blast_radius INTEGER NOT NULL,
    risk_score REAL NOT NULL,
    is_dead_code INTEGER NOT NULL DEFAULT 0,
    dead_code_reason TEXT,
    exclusion_category TEXT,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- Test coverage mapping
CREATE TABLE IF NOT EXISTS test_coverage (
    test_function_id TEXT NOT NULL,
    source_function_id TEXT NOT NULL,
    coverage_type TEXT NOT NULL,
    PRIMARY KEY (test_function_id, source_function_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_test_coverage_source ON test_coverage(source_function_id);

-- Test quality scores
CREATE TABLE IF NOT EXISTS test_quality (
    function_id TEXT PRIMARY KEY,
    coverage_breadth REAL,
    coverage_depth REAL,
    assertion_density REAL,
    mock_ratio REAL,
    isolation REAL,
    freshness REAL,
    stability REAL,
    overall_score REAL NOT NULL,
    smells TEXT,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;
"#;

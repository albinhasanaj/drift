//! V002: Phase 2 tables — call_edges, data_access, detections, boundaries.

pub const MIGRATION_SQL: &str = r#"
-- Call edges: directed edges in the call graph.
CREATE TABLE IF NOT EXISTS call_edges (
    caller_id INTEGER NOT NULL,
    callee_id INTEGER NOT NULL,
    resolution TEXT NOT NULL,
    confidence REAL NOT NULL,
    call_site_line INTEGER NOT NULL,
    PRIMARY KEY (caller_id, callee_id, call_site_line)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_call_edges_caller ON call_edges(caller_id);
CREATE INDEX IF NOT EXISTS idx_call_edges_callee ON call_edges(callee_id);
CREATE INDEX IF NOT EXISTS idx_call_edges_resolution ON call_edges(resolution);

-- Data access: function → table access patterns.
CREATE TABLE IF NOT EXISTS data_access (
    function_id INTEGER NOT NULL,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,
    framework TEXT,
    line INTEGER NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.8,
    PRIMARY KEY (function_id, table_name, operation, line)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_data_access_function ON data_access(function_id);
CREATE INDEX IF NOT EXISTS idx_data_access_table ON data_access(table_name);

-- Detections: pattern match results from the analysis engine.
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    column_num INTEGER NOT NULL,
    pattern_id TEXT NOT NULL,
    category TEXT NOT NULL,
    confidence REAL NOT NULL,
    detection_method TEXT NOT NULL,
    cwe_ids TEXT,
    owasp TEXT,
    matched_text TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_detections_file ON detections(file);
CREATE INDEX IF NOT EXISTS idx_detections_category ON detections(category);
CREATE INDEX IF NOT EXISTS idx_detections_pattern ON detections(pattern_id);
CREATE INDEX IF NOT EXISTS idx_detections_confidence ON detections(confidence);

-- Boundaries: ORM model/field boundary detection results.
CREATE TABLE IF NOT EXISTS boundaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT NOT NULL,
    framework TEXT NOT NULL,
    model_name TEXT NOT NULL,
    table_name TEXT,
    field_name TEXT,
    sensitivity TEXT,
    confidence REAL NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_boundaries_file ON boundaries(file);
CREATE INDEX IF NOT EXISTS idx_boundaries_framework ON boundaries(framework);
CREATE INDEX IF NOT EXISTS idx_boundaries_sensitivity ON boundaries(sensitivity)
    WHERE sensitivity IS NOT NULL;
"#;

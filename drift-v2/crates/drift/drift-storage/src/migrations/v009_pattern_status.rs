//! V009 migration: Pattern status tracking for auto-approve / user-approve workflow.
//!
//! Adds pattern_status table to track discovered → approved → ignored lifecycle.
//! Supports both auto-approval (confidence ≥ 0.90) and user approval flows.

pub const MIGRATION_SQL: &str = r#"
-- Pattern status lifecycle table
-- Tracks whether each pattern is discovered, approved (auto or user), or ignored.
CREATE TABLE IF NOT EXISTS pattern_status (
    pattern_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'discovered',
    approved_by TEXT,
    approved_at INTEGER,
    confidence_at_approval REAL,
    reason TEXT,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_pattern_status_status ON pattern_status(status);
CREATE INDEX IF NOT EXISTS idx_pattern_status_updated ON pattern_status(updated_at);
"#;

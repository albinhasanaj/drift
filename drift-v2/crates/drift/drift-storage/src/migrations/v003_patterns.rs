//! V003 migration: Phase 3 tables for pattern intelligence.
//!
//! Tables: pattern_confidence, outliers, conventions.

pub const MIGRATION_SQL: &str = r#"
-- Pattern confidence scores (Bayesian Beta distribution)
CREATE TABLE IF NOT EXISTS pattern_confidence (
    pattern_id TEXT PRIMARY KEY,
    alpha REAL NOT NULL,
    beta REAL NOT NULL,
    posterior_mean REAL NOT NULL,
    credible_interval_low REAL NOT NULL,
    credible_interval_high REAL NOT NULL,
    tier TEXT NOT NULL,
    momentum TEXT NOT NULL DEFAULT 'Stable',
    last_updated INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

-- Outlier detection results
CREATE TABLE IF NOT EXISTS outliers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    deviation_score REAL NOT NULL,
    significance TEXT NOT NULL,
    method TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_outliers_pattern ON outliers(pattern_id);
CREATE INDEX IF NOT EXISTS idx_outliers_file ON outliers(file);

-- Learned conventions
CREATE TABLE IF NOT EXISTS conventions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id TEXT NOT NULL,
    category TEXT NOT NULL,
    scope TEXT NOT NULL,
    dominance_ratio REAL NOT NULL,
    promotion_status TEXT NOT NULL DEFAULT 'discovered',
    discovered_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS idx_conventions_pattern ON conventions(pattern_id);
CREATE INDEX IF NOT EXISTS idx_conventions_category ON conventions(category);
CREATE INDEX IF NOT EXISTS idx_conventions_status ON conventions(promotion_status);
"#;

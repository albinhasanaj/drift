//! V007 migration: Phase 7 tables for advanced & capstone systems.
//!
//! Tables: simulations, decisions, context_cache, migration_projects,
//! migration_modules, migration_corrections

pub const MIGRATION_SQL: &str = r#"
-- Simulations table
CREATE TABLE IF NOT EXISTS simulations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_category TEXT NOT NULL,
    task_description TEXT NOT NULL,
    approach_count INTEGER NOT NULL,
    recommended_approach TEXT,
    p10_effort REAL NOT NULL,
    p50_effort REAL NOT NULL,
    p90_effort REAL NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_simulations_category ON simulations(task_category);
CREATE INDEX IF NOT EXISTS idx_simulations_created ON simulations(created_at);

-- Decisions table
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    commit_sha TEXT,
    confidence REAL NOT NULL,
    related_patterns TEXT,
    author TEXT,
    files_changed TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_decisions_category ON decisions(category);
CREATE INDEX IF NOT EXISTS idx_decisions_commit ON decisions(commit_sha);
CREATE INDEX IF NOT EXISTS idx_decisions_created ON decisions(created_at);

-- Context cache table
CREATE TABLE IF NOT EXISTS context_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    intent TEXT NOT NULL,
    depth TEXT NOT NULL,
    token_count INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_context_cache_session ON context_cache(session_id);
CREATE INDEX IF NOT EXISTS idx_context_cache_intent ON context_cache(intent);

-- Migration projects table
CREATE TABLE IF NOT EXISTS migration_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source_language TEXT NOT NULL,
    target_language TEXT NOT NULL,
    source_framework TEXT,
    target_framework TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_migration_projects_status ON migration_projects(status);

-- Migration modules table
CREATE TABLE IF NOT EXISTS migration_modules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES migration_projects(id),
    module_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    spec_content TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_migration_modules_project ON migration_modules(project_id);
CREATE INDEX IF NOT EXISTS idx_migration_modules_status ON migration_modules(status);

-- Migration corrections table
CREATE TABLE IF NOT EXISTS migration_corrections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id INTEGER NOT NULL REFERENCES migration_modules(id),
    section TEXT NOT NULL,
    original_text TEXT NOT NULL,
    corrected_text TEXT NOT NULL,
    reason TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX IF NOT EXISTS idx_migration_corrections_module ON migration_corrections(module_id);
"#;

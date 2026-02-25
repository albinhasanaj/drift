//! V001: Initial schema — Phase 1 tables.
//! file_metadata, parse_cache, functions, scan_history.

pub const MIGRATION_SQL: &str = r#"
-- File metadata: the foundation for incremental scanning.
-- Scanner writes core columns; parsers/detectors update counter caches.
CREATE TABLE IF NOT EXISTS file_metadata (
    path TEXT PRIMARY KEY,
    language TEXT,
    file_size INTEGER NOT NULL,
    content_hash BLOB NOT NULL,
    mtime_secs INTEGER NOT NULL,
    mtime_nanos INTEGER NOT NULL,
    last_scanned_at INTEGER NOT NULL,
    scan_duration_us INTEGER,
    pattern_count INTEGER DEFAULT 0,
    function_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    error TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_file_metadata_language
    ON file_metadata(language);
CREATE INDEX IF NOT EXISTS idx_file_metadata_errors
    ON file_metadata(path) WHERE error IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_file_metadata_scanned
    ON file_metadata(last_scanned_at);

-- Parse cache: keyed by content hash for deduplication.
-- Same content always produces same parse result.
CREATE TABLE IF NOT EXISTS parse_cache (
    content_hash BLOB PRIMARY KEY,
    language TEXT NOT NULL,
    parse_result_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- Functions table: extracted by parsers, consumed by call graph builder.
CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT NOT NULL,
    name TEXT NOT NULL,
    qualified_name TEXT,
    language TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    parameter_count INTEGER NOT NULL DEFAULT 0,
    return_type TEXT,
    is_exported INTEGER NOT NULL DEFAULT 0,
    is_async INTEGER NOT NULL DEFAULT 0,
    body_hash BLOB,
    signature_hash BLOB,
    UNIQUE(file, name, line)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_functions_file ON functions(file);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_functions_qualified ON functions(qualified_name)
    WHERE qualified_name IS NOT NULL;

-- Scan history: append-only log of scan operations.
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    root_path TEXT NOT NULL,
    total_files INTEGER,
    added_files INTEGER,
    modified_files INTEGER,
    removed_files INTEGER,
    unchanged_files INTEGER,
    duration_ms INTEGER,
    status TEXT NOT NULL DEFAULT 'running',
    error TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_scan_history_time
    ON scan_history(started_at DESC);
"#;

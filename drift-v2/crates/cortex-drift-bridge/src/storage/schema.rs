//! Schema SQL constants extracted from tables.rs.
//! Used by both migrations.rs and tables.rs (create_bridge_tables).

/// V1 schema: 5 bridge tables + 4 indexes.
pub const BRIDGE_TABLES_V1: &str = "
    CREATE TABLE IF NOT EXISTS bridge_grounding_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        memory_id TEXT NOT NULL,
        grounding_score REAL NOT NULL,
        classification TEXT NOT NULL,
        evidence TEXT NOT NULL,
        created_at INTEGER NOT NULL DEFAULT (unixepoch())
    ) STRICT;

    CREATE TABLE IF NOT EXISTS bridge_grounding_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        total_memories INTEGER NOT NULL,
        grounded_count INTEGER NOT NULL,
        validated_count INTEGER NOT NULL,
        partial_count INTEGER NOT NULL,
        weak_count INTEGER NOT NULL,
        invalidated_count INTEGER NOT NULL,
        avg_score REAL NOT NULL DEFAULT 0.0,
        error_count INTEGER NOT NULL DEFAULT 0,
        trigger_type TEXT,
        created_at INTEGER NOT NULL DEFAULT (unixepoch())
    ) STRICT;

    CREATE TABLE IF NOT EXISTS bridge_event_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        memory_type TEXT,
        memory_id TEXT,
        confidence REAL,
        created_at INTEGER NOT NULL DEFAULT (unixepoch())
    ) STRICT;

    CREATE TABLE IF NOT EXISTS bridge_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        metric_name TEXT NOT NULL,
        metric_value REAL NOT NULL,
        recorded_at INTEGER NOT NULL DEFAULT (unixepoch())
    ) STRICT;

    CREATE TABLE IF NOT EXISTS bridge_memories (
        id TEXT PRIMARY KEY NOT NULL,
        memory_type TEXT NOT NULL,
        content TEXT NOT NULL,
        summary TEXT NOT NULL,
        confidence REAL NOT NULL,
        importance TEXT NOT NULL,
        tags TEXT NOT NULL DEFAULT '[]',
        linked_patterns TEXT NOT NULL DEFAULT '[]',
        created_at INTEGER NOT NULL DEFAULT (unixepoch())
    ) STRICT;

    CREATE INDEX IF NOT EXISTS idx_grounding_results_memory ON bridge_grounding_results(memory_id);
    CREATE INDEX IF NOT EXISTS idx_event_log_type ON bridge_event_log(event_type);
    CREATE INDEX IF NOT EXISTS idx_metrics_name ON bridge_metrics(metric_name);
    CREATE INDEX IF NOT EXISTS idx_memories_type ON bridge_memories(memory_type);
";

/// All 5 bridge table names.
pub const BRIDGE_TABLE_NAMES: [&str; 5] = [
    "bridge_grounding_results",
    "bridge_grounding_snapshots",
    "bridge_event_log",
    "bridge_metrics",
    "bridge_memories",
];

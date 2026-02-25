//! v001: Core tables — memories, relationships, patterns, constraints, files, functions, schema_version.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER PRIMARY KEY,
            applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE TABLE IF NOT EXISTS memories (
            id                TEXT PRIMARY KEY,
            memory_type       TEXT NOT NULL,
            content           TEXT NOT NULL,
            summary           TEXT NOT NULL DEFAULT '',
            transaction_time  TEXT NOT NULL,
            valid_time        TEXT NOT NULL,
            valid_until       TEXT,
            confidence        REAL NOT NULL DEFAULT 1.0,
            importance        TEXT NOT NULL DEFAULT 'normal',
            last_accessed     TEXT NOT NULL,
            access_count      INTEGER NOT NULL DEFAULT 0,
            tags              TEXT NOT NULL DEFAULT '[]',
            archived          INTEGER NOT NULL DEFAULT 0,
            superseded_by     TEXT,
            supersedes        TEXT,
            content_hash      TEXT NOT NULL,
            created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_memories_type ON memories(memory_type);
        CREATE INDEX IF NOT EXISTS idx_memories_importance ON memories(importance);
        CREATE INDEX IF NOT EXISTS idx_memories_confidence ON memories(confidence);
        CREATE INDEX IF NOT EXISTS idx_memories_archived ON memories(archived);
        CREATE INDEX IF NOT EXISTS idx_memories_content_hash ON memories(content_hash);
        CREATE INDEX IF NOT EXISTS idx_memories_last_accessed ON memories(last_accessed);
        CREATE INDEX IF NOT EXISTS idx_memories_transaction_time ON memories(transaction_time);

        CREATE TABLE IF NOT EXISTS memory_relationships (
            source_id          TEXT NOT NULL,
            target_id          TEXT NOT NULL,
            relationship_type  TEXT NOT NULL,
            strength           REAL NOT NULL DEFAULT 1.0,
            evidence           TEXT NOT NULL DEFAULT '[]',
            created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (source_id, target_id, relationship_type),
            FOREIGN KEY (source_id) REFERENCES memories(id) ON DELETE CASCADE,
            FOREIGN KEY (target_id) REFERENCES memories(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_relationships_source ON memory_relationships(source_id);
        CREATE INDEX IF NOT EXISTS idx_relationships_target ON memory_relationships(target_id);

        CREATE TABLE IF NOT EXISTS memory_patterns (
            memory_id     TEXT NOT NULL,
            pattern_id    TEXT NOT NULL,
            pattern_name  TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (memory_id, pattern_id),
            FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS memory_constraints (
            memory_id        TEXT NOT NULL,
            constraint_id    TEXT NOT NULL,
            constraint_name  TEXT NOT NULL,
            created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (memory_id, constraint_id),
            FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS memory_files (
            memory_id     TEXT NOT NULL,
            file_path     TEXT NOT NULL,
            line_start    INTEGER,
            line_end      INTEGER,
            content_hash  TEXT,
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (memory_id, file_path),
            FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_files_path ON memory_files(file_path);

        CREATE TABLE IF NOT EXISTS memory_functions (
            memory_id      TEXT NOT NULL,
            function_name  TEXT NOT NULL,
            file_path      TEXT NOT NULL,
            signature      TEXT,
            created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (memory_id, function_name, file_path),
            FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_functions_name ON memory_functions(function_name);
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

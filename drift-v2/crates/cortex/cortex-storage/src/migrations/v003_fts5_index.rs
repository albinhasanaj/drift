//! v003: FTS5 virtual table on content + summary + tags, with sync triggers.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
            content,
            summary,
            tags,
            content='memories',
            content_rowid='rowid'
        );

        -- Sync triggers: keep FTS5 in sync with the memories table.
        CREATE TRIGGER IF NOT EXISTS memory_fts_insert AFTER INSERT ON memories BEGIN
            INSERT INTO memory_fts(rowid, content, summary, tags)
            VALUES (new.rowid, new.content, new.summary, new.tags);
        END;

        CREATE TRIGGER IF NOT EXISTS memory_fts_delete BEFORE DELETE ON memories BEGIN
            INSERT INTO memory_fts(memory_fts, rowid, content, summary, tags)
            VALUES ('delete', old.rowid, old.content, old.summary, old.tags);
        END;

        CREATE TRIGGER IF NOT EXISTS memory_fts_update AFTER UPDATE ON memories BEGIN
            INSERT INTO memory_fts(memory_fts, rowid, content, summary, tags)
            VALUES ('delete', old.rowid, old.content, old.summary, old.tags);
            INSERT INTO memory_fts(rowid, content, summary, tags)
            VALUES (new.rowid, new.content, new.summary, new.tags);
        END;
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

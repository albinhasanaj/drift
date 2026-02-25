//! v002: sqlite-vec virtual table — memory_embeddings, memory_embedding_link.
//!
//! Note: sqlite-vec requires the extension to be loaded at runtime.
//! We create the linking table here; the virtual table creation is
//! handled at engine startup when the extension is available.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;

use crate::to_storage_err;

pub fn migrate(conn: &Connection) -> CortexResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS memory_embeddings (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            content_hash  TEXT NOT NULL UNIQUE,
            embedding     BLOB NOT NULL,
            dimensions    INTEGER NOT NULL,
            model_name    TEXT NOT NULL DEFAULT 'unknown',
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );

        CREATE INDEX IF NOT EXISTS idx_embeddings_hash ON memory_embeddings(content_hash);

        CREATE TABLE IF NOT EXISTS memory_embedding_link (
            memory_id     TEXT NOT NULL,
            embedding_id  INTEGER NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (memory_id),
            FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE,
            FOREIGN KEY (embedding_id) REFERENCES memory_embeddings(id) ON DELETE CASCADE
        );
        ",
    )
    .map_err(|e| to_storage_err(e.to_string()))?;
    Ok(())
}

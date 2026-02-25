//! parse_cache queries: get by content hash, insert, invalidate.

use drift_core::errors::StorageError;
use rusqlite::{params, Connection};

/// A cached parse result record.
#[derive(Debug, Clone)]
pub struct ParseCacheRecord {
    pub content_hash: Vec<u8>,
    pub language: String,
    pub parse_result_json: String,
    pub created_at: i64,
}

/// Get a cached parse result by content hash.
pub fn get_by_hash(
    conn: &Connection,
    content_hash: &[u8],
) -> Result<Option<ParseCacheRecord>, StorageError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT content_hash, language, parse_result_json, created_at
             FROM parse_cache WHERE content_hash = ?1",
        )
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    let mut rows = stmt
        .query_map(params![content_hash], |row| {
            Ok(ParseCacheRecord {
                content_hash: row.get(0)?,
                language: row.get(1)?,
                parse_result_json: row.get(2)?,
                created_at: row.get(3)?,
            })
        })
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })?;

    match rows.next() {
        Some(Ok(record)) => Ok(Some(record)),
        Some(Err(e)) => Err(StorageError::SqliteError {
            message: e.to_string(),
        }),
        None => Ok(None),
    }
}

/// Insert or replace a parse cache entry.
pub fn insert(
    conn: &Connection,
    content_hash: &[u8],
    language: &str,
    parse_result_json: &str,
    created_at: i64,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO parse_cache
         (content_hash, language, parse_result_json, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![content_hash, language, parse_result_json, created_at],
    )
    .map_err(|e| StorageError::SqliteError {
        message: e.to_string(),
    })?;
    Ok(())
}

/// Invalidate a cache entry by content hash.
pub fn invalidate(conn: &Connection, content_hash: &[u8]) -> Result<(), StorageError> {
    conn.execute(
        "DELETE FROM parse_cache WHERE content_hash = ?1",
        params![content_hash],
    )
    .map_err(|e| StorageError::SqliteError {
        message: e.to_string(),
    })?;
    Ok(())
}

/// Count entries in the parse cache.
pub fn count(conn: &Connection) -> Result<i64, StorageError> {
    conn.query_row("SELECT COUNT(*) FROM parse_cache", [], |row| row.get(0))
        .map_err(|e| StorageError::SqliteError {
            message: e.to_string(),
        })
}

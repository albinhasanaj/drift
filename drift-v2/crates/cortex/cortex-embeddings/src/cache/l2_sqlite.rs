//! L2 SQLite-backed embedding cache.
//!
//! D-01: Real SQLite persistence. Embeddings survive process restarts.
//! When a DB path is provided at construction, uses a dedicated SQLite
//! file. Falls back to an in-memory HashMap when no path is given
//! (e.g., in-memory mode or tests).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use tracing::debug;

/// L2 persistent embedding cache backed by SQLite.
///
/// Stores `content_hash → embedding` as blob rows. Millisecond access times.
pub struct L2SqliteCache {
    /// Real SQLite connection when a DB path is available.
    conn: Option<Mutex<Connection>>,
    /// In-memory fallback when no SQLite connection is available.
    fallback: std::collections::HashMap<String, Vec<u8>>,
}

impl L2SqliteCache {
    /// Create an in-memory-only L2 cache (no persistence).
    pub fn new() -> Self {
        Self {
            conn: None,
            fallback: std::collections::HashMap::new(),
        }
    }

    /// D-01: Create an L2 cache backed by a real SQLite file.
    /// Embeddings written here survive process restarts.
    pub fn open(db_path: &Path) -> Self {
        let cache_path = db_path.with_extension("embeddings.db");
        match Connection::open(&cache_path) {
            Ok(conn) => {
                // Create the cache table if it doesn't exist.
                let _ = conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS embedding_cache (
                        content_hash TEXT PRIMARY KEY,
                        embedding BLOB NOT NULL,
                        created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    );
                    PRAGMA journal_mode = WAL;
                    PRAGMA synchronous = NORMAL;",
                );
                debug!(path = %cache_path.display(), "L2 SQLite cache opened");
                Self {
                    conn: Some(Mutex::new(conn)),
                    fallback: std::collections::HashMap::new(),
                }
            }
            Err(e) => {
                debug!(error = %e, "L2 SQLite cache open failed, using in-memory fallback");
                Self::new()
            }
        }
    }

    /// Look up an embedding by content hash.
    pub fn get(&self, content_hash: &str) -> Option<Vec<f32>> {
        if let Some(ref conn_mutex) = self.conn {
            if let Ok(conn) = conn_mutex.lock() {
                let result: Result<Vec<u8>, _> = conn.query_row(
                    "SELECT embedding FROM embedding_cache WHERE content_hash = ?1",
                    params![content_hash],
                    |row| row.get(0),
                );
                if let Ok(bytes) = result {
                    return Some(bytes_to_f32(&bytes));
                }
            }
            return None;
        }
        self.fallback.get(content_hash).map(|b| bytes_to_f32(b))
    }

    /// Store an embedding keyed by content hash.
    pub fn insert(&mut self, content_hash: String, embedding: &[f32]) {
        let bytes = f32_to_bytes(embedding);
        if let Some(ref conn_mutex) = self.conn {
            if let Ok(conn) = conn_mutex.lock() {
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO embedding_cache (content_hash, embedding) VALUES (?1, ?2)",
                    params![content_hash, bytes],
                );
                return;
            }
        }
        self.fallback.insert(content_hash, bytes);
    }

    /// Number of cached embeddings.
    pub fn len(&self) -> usize {
        if let Some(ref conn_mutex) = self.conn {
            if let Ok(conn) = conn_mutex.lock() {
                let count: i64 = conn
                    .query_row("SELECT COUNT(*) FROM embedding_cache", [], |row| row.get(0))
                    .unwrap_or(0);
                return count as usize;
            }
        }
        self.fallback.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        if let Some(ref conn_mutex) = self.conn {
            if let Ok(conn) = conn_mutex.lock() {
                let _ = conn.execute("DELETE FROM embedding_cache", []);
                return;
            }
        }
        self.fallback.clear();
    }

    /// Check if a content hash exists in the cache.
    pub fn contains(&self, content_hash: &str) -> bool {
        if let Some(ref conn_mutex) = self.conn {
            if let Ok(conn) = conn_mutex.lock() {
                let exists: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM embedding_cache WHERE content_hash = ?1)",
                        params![content_hash],
                        |row| row.get(0),
                    )
                    .unwrap_or(false);
                return exists;
            }
        }
        self.fallback.contains_key(content_hash)
    }
}

fn f32_to_bytes(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|f| f.to_le_bytes()).collect()
}

fn bytes_to_f32(bytes: &[u8]) -> Vec<f32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

impl Default for L2SqliteCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_fallback() {
        let mut cache = L2SqliteCache::new();
        let hash = "deadbeef".to_string();
        let embedding = vec![1.0f32, 2.5, -3.7, 0.0];
        cache.insert(hash.clone(), &embedding);
        let got = cache.get(&hash).unwrap();
        assert_eq!(got, embedding);
    }

    #[test]
    fn miss_returns_none() {
        let cache = L2SqliteCache::new();
        assert!(cache.get("missing").is_none());
    }

    #[test]
    fn contains_check() {
        let mut cache = L2SqliteCache::new();
        cache.insert("exists".to_string(), &[1.0]);
        assert!(cache.contains("exists"));
        assert!(!cache.contains("nope"));
    }

    #[test]
    fn clear_works() {
        let mut cache = L2SqliteCache::new();
        cache.insert("a".to_string(), &[1.0]);
        cache.insert("b".to_string(), &[2.0]);
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn sqlite_backed_roundtrip() {
        let dir = std::env::temp_dir().join("l2_cache_test");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("test.db");

        let mut cache = L2SqliteCache::open(&db_path);
        cache.insert("hash1".to_string(), &[1.0, 2.0, 3.0]);
        assert_eq!(cache.get("hash1"), Some(vec![1.0, 2.0, 3.0]));
        assert!(cache.contains("hash1"));
        assert_eq!(cache.len(), 1);

        // Clean up.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sqlite_survives_reopen() {
        let dir = std::env::temp_dir().join("l2_cache_reopen_test");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("persist.db");

        // Write.
        {
            let mut cache = L2SqliteCache::open(&db_path);
            cache.insert("persist-hash".to_string(), &[4.0, 5.0]);
        }

        // Reopen and read.
        {
            let cache = L2SqliteCache::open(&db_path);
            let got = cache.get("persist-hash");
            assert_eq!(got, Some(vec![4.0, 5.0]), "embedding should survive reopen");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}

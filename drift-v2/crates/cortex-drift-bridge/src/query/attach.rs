//! ATTACH/DETACH lifecycle with RAII guard pattern (auto-detach on drop).
//!
//! IMPORTANT: Cross-DB writes are NOT atomic in WAL mode.
//! Pattern: ATTACH drift.db READ-ONLY, execute read query, DETACH.
//! Never write to drift.db from the bridge (D6 compliance).
//! For bridge writes that depend on drift.db reads:
//!   1. Read from drift.db (via ATTACH)
//!   2. DETACH drift.db
//!   3. Write to bridge.db/cortex.db in a separate transaction

use rusqlite::Connection;

use crate::errors::{BridgeError, BridgeResult};

/// RAII guard that automatically DETACHes the attached database on drop.
pub struct AttachGuard<'a> {
    conn: &'a Connection,
    alias: String,
    detached: bool,
}

impl<'a> AttachGuard<'a> {
    /// ATTACH a database file as the given alias.
    /// Returns a guard that will auto-DETACH on drop.
    pub fn attach(conn: &'a Connection, db_path: &str, alias: &str) -> BridgeResult<Self> {
        conn.execute(
            &format!("ATTACH DATABASE ?1 AS {}", sanitize_alias(alias)),
            rusqlite::params![db_path],
        )
        .map_err(|e| BridgeError::AttachFailed {
            db_path: db_path.to_string(),
            source: e,
        })?;

        Ok(Self {
            conn,
            alias: alias.to_string(),
            detached: false,
        })
    }

    /// Explicitly DETACH before the guard is dropped.
    /// Useful when you need error handling on the DETACH itself.
    pub fn detach(mut self) -> BridgeResult<()> {
        self.do_detach()?;
        self.detached = true;
        Ok(())
    }

    /// Get the alias this guard is managing.
    pub fn alias(&self) -> &str {
        &self.alias
    }

    fn do_detach(&self) -> BridgeResult<()> {
        self.conn
            .execute_batch(&format!("DETACH DATABASE {}", sanitize_alias(&self.alias)))?;
        Ok(())
    }
}

impl<'a> Drop for AttachGuard<'a> {
    fn drop(&mut self) {
        if !self.detached {
            // Best-effort DETACH on drop — log but don't panic
            if let Err(e) = self.do_detach() {
                tracing::warn!(
                    alias = %self.alias,
                    error = %e,
                    "Failed to DETACH database on guard drop"
                );
            }
            self.detached = true;
        }
    }
}

/// Sanitize an alias name to prevent SQL injection.
/// Only allows alphanumeric characters and underscores.
fn sanitize_alias(alias: &str) -> String {
    alias
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_alias() {
        assert_eq!(sanitize_alias("drift_db"), "drift_db");
        assert_eq!(sanitize_alias("drift;DROP TABLE"), "driftDROPTABLE");
        assert_eq!(sanitize_alias(""), "");
    }

    #[test]
    fn test_attach_guard_nonexistent_file() {
        let conn = Connection::open_in_memory().unwrap();
        // Attaching a nonexistent file creates it in SQLite by default
        // so we test with an invalid path
        let result = AttachGuard::attach(&conn, "/nonexistent/path/db.sqlite", "test_db");
        // This may succeed (SQLite creates the file) or fail depending on permissions
        // Either way, no panic
        drop(result);
    }
}

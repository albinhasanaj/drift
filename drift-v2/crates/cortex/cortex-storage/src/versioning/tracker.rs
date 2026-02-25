//! On every memory update, snapshot current content as a new version.

use rusqlite::Connection;

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;

use crate::queries::version_ops;

/// Tracks memory content evolution by creating version snapshots.
pub struct VersionTracker;

impl VersionTracker {
    /// Snapshot the current state of a memory before an update.
    pub fn snapshot(
        conn: &Connection,
        memory: &BaseMemory,
        changed_by: &str,
        reason: &str,
    ) -> CortexResult<i64> {
        let content_json = serde_json::to_string(&memory.content).unwrap_or_default();

        let version = version_ops::insert_version(
            conn,
            &memory.id,
            &content_json,
            &memory.summary,
            memory.confidence.value(),
            changed_by,
            reason,
        )?;

        // Enforce retention after creating a new version.
        super::retention::enforce(conn, &memory.id)?;

        Ok(version)
    }
}

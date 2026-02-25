//! Mutation log for incremental sync.
//!
//! Tracks which local mutations need to be pushed to the cloud.
//! Backed by the `sync_log` SQLite table from migration v010.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Direction of a sync operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncDirection {
    Push,
    Pull,
}

/// Status of a sync log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

/// A single entry in the sync log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncLogEntry {
    pub direction: SyncDirection,
    pub memory_id: String,
    pub operation: String,
    pub status: SyncStatus,
    pub details: String,
    pub timestamp: DateTime<Utc>,
}

/// In-memory sync log. In production, reads/writes the `sync_log` table.
#[derive(Debug, Default)]
pub struct SyncLog {
    entries: Vec<SyncLogEntry>,
}

impl SyncLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new sync log entry.
    pub fn record(&mut self, entry: SyncLogEntry) {
        self.entries.push(entry);
    }

    /// Get all pending entries for a given direction.
    pub fn pending(&self, direction: SyncDirection) -> Vec<&SyncLogEntry> {
        self.entries
            .iter()
            .filter(|e| e.direction == direction && e.status == SyncStatus::Pending)
            .collect()
    }

    /// Mark entries for a memory as completed.
    pub fn mark_completed(&mut self, memory_id: &str, direction: SyncDirection) {
        for entry in &mut self.entries {
            if entry.memory_id == memory_id
                && entry.direction == direction
                && entry.status == SyncStatus::Pending
            {
                entry.status = SyncStatus::Completed;
            }
        }
    }

    /// Mark entries for a memory as failed.
    pub fn mark_failed(&mut self, memory_id: &str, direction: SyncDirection) {
        for entry in &mut self.entries {
            if entry.memory_id == memory_id
                && entry.direction == direction
                && entry.status == SyncStatus::Pending
            {
                entry.status = SyncStatus::Failed;
            }
        }
    }

    /// Total number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Count of pending entries.
    pub fn pending_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status == SyncStatus::Pending)
            .count()
    }
}

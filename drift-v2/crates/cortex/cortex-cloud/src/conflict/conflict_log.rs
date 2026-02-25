//! Conflict logging: records every conflict with resolution details.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::resolution::ResolutionStrategy;

/// A logged conflict event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictRecord {
    /// The memory ID that was in conflict.
    pub memory_id: String,
    /// Local content hash at time of conflict.
    pub local_hash: String,
    /// Remote content hash at time of conflict.
    pub remote_hash: String,
    /// Strategy used to resolve.
    pub strategy: ResolutionStrategy,
    /// Who/what resolved it.
    pub resolved_by: ConflictResolver,
    /// When the conflict was detected.
    pub detected_at: DateTime<Utc>,
    /// When the conflict was resolved (None if still pending).
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Who resolved the conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolver {
    /// Resolved automatically by the system.
    System,
    /// Resolved manually by a user.
    User(String),
}

/// In-memory conflict log. In production, this would be backed by the
/// `conflict_log` SQLite table from migration v010.
#[derive(Debug, Default)]
pub struct ConflictLog {
    records: Vec<ConflictRecord>,
}

impl ConflictLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a conflict resolution.
    pub fn record(&mut self, record: ConflictRecord) {
        tracing::info!(
            "cloud: conflict recorded for memory {} ({:?})",
            record.memory_id,
            record.strategy
        );
        self.records.push(record);
    }

    /// Get all conflict records.
    pub fn records(&self) -> &[ConflictRecord] {
        &self.records
    }

    /// Get unresolved conflicts (resolved_at is None).
    pub fn unresolved(&self) -> Vec<&ConflictRecord> {
        self.records
            .iter()
            .filter(|r| r.resolved_at.is_none())
            .collect()
    }

    /// Count of total conflicts recorded.
    pub fn total_count(&self) -> usize {
        self.records.len()
    }

    /// Count of unresolved conflicts.
    pub fn unresolved_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.resolved_at.is_none())
            .count()
    }
}

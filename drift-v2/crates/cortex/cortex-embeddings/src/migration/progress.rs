//! Embedding migration progress tracking.
//!
//! Tracks total, completed, remaining, ETA, and status for background
//! re-embedding operations.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Migration status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    Pending,
    InProgress,
    Complete,
    Failed,
}

/// Thread-safe migration progress tracker.
pub struct MigrationProgress {
    total: AtomicU64,
    completed: AtomicU64,
    failed: AtomicU64,
    status: std::sync::atomic::AtomicU8,
    started_at: Option<Instant>,
}

impl MigrationProgress {
    /// Create a new progress tracker for the given total count.
    pub fn new(total: u64) -> Self {
        Self {
            total: AtomicU64::new(total),
            completed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            status: std::sync::atomic::AtomicU8::new(0), // Pending
            started_at: None,
        }
    }

    /// Mark the migration as started.
    pub fn start(&mut self) {
        self.status.store(1, Ordering::Relaxed); // InProgress
        self.started_at = Some(Instant::now());
    }

    /// Record a successfully re-embedded memory.
    pub fn record_success(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed re-embedding attempt.
    pub fn record_failure(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Mark the migration as complete.
    pub fn mark_complete(&self) {
        self.status.store(2, Ordering::Relaxed);
    }

    /// Mark the migration as failed.
    pub fn mark_failed(&self) {
        self.status.store(3, Ordering::Relaxed);
    }

    /// Get a snapshot of the current progress.
    pub fn snapshot(&self) -> ProgressSnapshot {
        let total = self.total.load(Ordering::Relaxed);
        let completed = self.completed.load(Ordering::Relaxed);
        let failed = self.failed.load(Ordering::Relaxed);
        let remaining = total.saturating_sub(completed).saturating_sub(failed);

        let status = match self.status.load(Ordering::Relaxed) {
            0 => MigrationStatus::Pending,
            1 => MigrationStatus::InProgress,
            2 => MigrationStatus::Complete,
            _ => MigrationStatus::Failed,
        };

        let eta_seconds = self.started_at.and_then(|start| {
            if completed == 0 {
                return None;
            }
            let elapsed = start.elapsed().as_secs_f64();
            let rate = completed as f64 / elapsed;
            if rate > 0.0 {
                Some((remaining as f64 / rate) as u64)
            } else {
                None
            }
        });

        ProgressSnapshot {
            total,
            completed,
            failed,
            remaining,
            status,
            eta_seconds,
        }
    }
}

/// Immutable snapshot of migration progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressSnapshot {
    pub total: u64,
    pub completed: u64,
    pub failed: u64,
    pub remaining: u64,
    pub status: MigrationStatus,
    pub eta_seconds: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state() {
        let progress = MigrationProgress::new(100);
        let snap = progress.snapshot();
        assert_eq!(snap.total, 100);
        assert_eq!(snap.completed, 0);
        assert_eq!(snap.remaining, 100);
        assert_eq!(snap.status, MigrationStatus::Pending);
    }

    #[test]
    fn track_progress() {
        let mut progress = MigrationProgress::new(10);
        progress.start();
        progress.record_success();
        progress.record_success();
        progress.record_failure();

        let snap = progress.snapshot();
        assert_eq!(snap.completed, 2);
        assert_eq!(snap.failed, 1);
        assert_eq!(snap.remaining, 7);
        assert_eq!(snap.status, MigrationStatus::InProgress);
    }

    #[test]
    fn mark_complete() {
        let progress = MigrationProgress::new(5);
        for _ in 0..5 {
            progress.record_success();
        }
        progress.mark_complete();

        let snap = progress.snapshot();
        assert_eq!(snap.status, MigrationStatus::Complete);
        assert_eq!(snap.completed, 5);
        assert_eq!(snap.remaining, 0);
    }
}

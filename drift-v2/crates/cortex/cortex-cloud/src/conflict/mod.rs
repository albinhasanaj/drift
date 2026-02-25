//! Conflict detection, resolution, and logging.

pub mod conflict_log;
pub mod detection;
pub mod resolution;

use chrono::Utc;

use conflict_log::{ConflictLog, ConflictRecord, ConflictResolver as ConflictResolverActor};
use detection::DetectedConflict;
use resolution::{resolve, ResolutionOutcome, ResolutionStrategy};

pub use conflict_log::ConflictRecord as LoggedConflict;
pub use detection::detect_conflicts;
pub use resolution::ResolutionStrategy as Strategy;

/// Orchestrates conflict detection, resolution, and logging.
#[derive(Debug)]
pub struct ConflictResolver {
    strategy: ResolutionStrategy,
    log: ConflictLog,
}

impl ConflictResolver {
    pub fn new(strategy: ResolutionStrategy) -> Self {
        Self {
            strategy,
            log: ConflictLog::new(),
        }
    }

    /// Resolve a detected conflict using the configured strategy.
    pub fn resolve(&mut self, conflict: &DetectedConflict) -> ResolutionOutcome {
        let outcome = resolve(conflict, self.strategy);

        // Log the resolution.
        self.log.record(ConflictRecord {
            memory_id: conflict.memory_id.clone(),
            local_hash: conflict.local_hash.clone(),
            remote_hash: conflict.remote_hash.clone(),
            strategy: self.strategy,
            resolved_by: if outcome.needs_manual_resolution {
                ConflictResolverActor::User("pending".into())
            } else {
                ConflictResolverActor::System
            },
            detected_at: Utc::now(),
            resolved_at: if outcome.needs_manual_resolution {
                None
            } else {
                Some(Utc::now())
            },
        });

        outcome
    }

    /// Get the conflict log.
    pub fn log(&self) -> &ConflictLog {
        &self.log
    }

    /// Change the default resolution strategy.
    pub fn set_strategy(&mut self, strategy: ResolutionStrategy) {
        self.strategy = strategy;
    }

    /// Current strategy.
    pub fn strategy(&self) -> ResolutionStrategy {
        self.strategy
    }
}

impl Default for ConflictResolver {
    fn default() -> Self {
        Self::new(ResolutionStrategy::default())
    }
}

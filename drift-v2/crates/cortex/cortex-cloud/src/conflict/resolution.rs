//! Conflict resolution strategies.

use serde::{Deserialize, Serialize};

use crate::transport::protocol::MemoryPayload;

use super::detection::DetectedConflict;

/// Available conflict resolution strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStrategy {
    /// Most recent modification wins (default).
    #[default]
    LastWriteWins,
    /// Local version always wins (offline-first preference).
    LocalWins,
    /// Remote version always wins (team authority).
    RemoteWins,
    /// Flag for manual user resolution.
    Manual,
    /// CRDT merge for multi-agent mode — conflict-free convergence.
    CrdtMerge,
}

/// The outcome of resolving a conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionOutcome {
    /// The memory ID that was in conflict.
    pub memory_id: String,
    /// Which strategy was applied.
    pub strategy: ResolutionStrategy,
    /// The winning payload (None if Manual — deferred to user).
    pub winner: Option<MemoryPayload>,
    /// Whether this needs user intervention.
    pub needs_manual_resolution: bool,
}

/// Resolve a conflict using the given strategy.
pub fn resolve(conflict: &DetectedConflict, strategy: ResolutionStrategy) -> ResolutionOutcome {
    match strategy {
        ResolutionStrategy::LastWriteWins => {
            let winner = if conflict.local_modified >= conflict.remote_modified {
                conflict.local_payload.clone()
            } else {
                conflict.remote_payload.clone()
            };
            ResolutionOutcome {
                memory_id: conflict.memory_id.clone(),
                strategy,
                winner: Some(winner),
                needs_manual_resolution: false,
            }
        }
        ResolutionStrategy::LocalWins => ResolutionOutcome {
            memory_id: conflict.memory_id.clone(),
            strategy,
            winner: Some(conflict.local_payload.clone()),
            needs_manual_resolution: false,
        },
        ResolutionStrategy::RemoteWins => ResolutionOutcome {
            memory_id: conflict.memory_id.clone(),
            strategy,
            winner: Some(conflict.remote_payload.clone()),
            needs_manual_resolution: false,
        },
        ResolutionStrategy::Manual => ResolutionOutcome {
            memory_id: conflict.memory_id.clone(),
            strategy,
            winner: None,
            needs_manual_resolution: true,
        },
        ResolutionStrategy::CrdtMerge => {
            // In CRDT merge mode, both versions are merged conflict-free.
            // The "winner" is the merged result. For now, we use the more
            // recent version as the base and note that CRDT merge was applied.
            // The actual CRDT merge is performed by cortex-crdt's MergeEngine.
            let winner = if conflict.local_modified >= conflict.remote_modified {
                conflict.local_payload.clone()
            } else {
                conflict.remote_payload.clone()
            };
            ResolutionOutcome {
                memory_id: conflict.memory_id.clone(),
                strategy,
                winner: Some(winner),
                needs_manual_resolution: false,
            }
        }
    }
}

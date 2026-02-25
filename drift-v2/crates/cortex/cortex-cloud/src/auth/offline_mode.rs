//! Offline detection, mutation queuing, and replay on reconnect.

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A mutation that occurred while offline and needs to be synced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMutation {
    /// The memory ID affected.
    pub memory_id: String,
    /// The operation performed.
    pub operation: MutationOp,
    /// When the mutation occurred locally.
    pub timestamp: DateTime<Utc>,
    /// Serialized payload (the memory JSON for create/update, empty for delete).
    pub payload: Option<String>,
}

/// Types of mutations that can be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationOp {
    Create,
    Update,
    Delete,
}

/// Tracks online/offline state and queues mutations when offline.
#[derive(Debug)]
pub struct OfflineManager {
    online: bool,
    queue: VecDeque<QueuedMutation>,
    /// Maximum number of mutations to queue before dropping oldest.
    max_queue_size: usize,
}

impl OfflineManager {
    pub fn new(max_queue_size: usize) -> Self {
        Self {
            online: true,
            queue: VecDeque::new(),
            max_queue_size,
        }
    }

    /// Whether we believe we're online.
    pub fn is_online(&self) -> bool {
        self.online
    }

    /// Transition to offline mode.
    pub fn go_offline(&mut self) {
        if self.online {
            tracing::warn!("cloud: transitioning to offline mode");
            self.online = false;
        }
    }

    /// Transition back to online mode.
    pub fn go_online(&mut self) {
        if !self.online {
            tracing::info!(
                "cloud: back online, {} queued mutations pending",
                self.queue.len()
            );
            self.online = true;
        }
    }

    /// Queue a mutation that happened while offline.
    pub fn enqueue(&mut self, mutation: QueuedMutation) {
        if self.queue.len() >= self.max_queue_size {
            // Drop oldest to make room.
            let dropped = self.queue.pop_front();
            if let Some(d) = dropped {
                tracing::warn!(
                    "cloud: offline queue full, dropping oldest mutation for {}",
                    d.memory_id
                );
            }
        }
        self.queue.push_back(mutation);
    }

    /// Drain all queued mutations for replay. Returns them in FIFO order.
    pub fn drain_queue(&mut self) -> Vec<QueuedMutation> {
        self.queue.drain(..).collect()
    }

    /// Number of mutations currently queued.
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Whether there are queued mutations waiting.
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }
}

impl Default for OfflineManager {
    fn default() -> Self {
        Self::new(10_000)
    }
}

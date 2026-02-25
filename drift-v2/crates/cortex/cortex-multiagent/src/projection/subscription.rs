//! Live projection subscriptions — push deltas to subscribers.

use std::collections::HashMap;
use std::sync::Mutex;

use tracing::debug;

use cortex_core::errors::{CortexResult, MultiAgentError};

/// Manages live projection subscriptions with bounded delta queues.
pub struct SubscriptionManager {
    subscriptions: Mutex<HashMap<String, SubscriptionState>>,
    max_queue_size: usize,
}

/// State for a single live projection subscription.
#[derive(Debug, Clone)]
pub struct SubscriptionState {
    /// The projection this subscription is for.
    pub projection_id: String,
    /// Pending deltas (serialized JSON).
    pub delta_queue: Vec<String>,
    /// Maximum queue capacity.
    pub max_queue_size: usize,
}

impl SubscriptionManager {
    /// Create a new subscription manager with the given max queue size.
    pub fn new(max_queue_size: usize) -> Self {
        Self {
            subscriptions: Mutex::new(HashMap::new()),
            max_queue_size,
        }
    }

    /// Subscribe to a projection's live updates.
    pub fn subscribe(&self, projection_id: &str) -> CortexResult<SubscriptionState> {
        let state = SubscriptionState {
            projection_id: projection_id.to_string(),
            delta_queue: Vec::new(),
            max_queue_size: self.max_queue_size,
        };
        let mut subs = self.subscriptions.lock().map_err(|e| {
            cortex_core::CortexError::ConcurrencyError(format!("subscription lock: {e}"))
        })?;
        subs.insert(projection_id.to_string(), state.clone());
        debug!(projection_id, "subscribed to projection");
        Ok(state)
    }

    /// Unsubscribe from a projection.
    pub fn unsubscribe(&self, projection_id: &str) -> CortexResult<()> {
        let mut subs = self.subscriptions.lock().map_err(|e| {
            cortex_core::CortexError::ConcurrencyError(format!("subscription lock: {e}"))
        })?;
        subs.remove(projection_id);
        debug!(projection_id, "unsubscribed from projection");
        Ok(())
    }

    /// Push a delta to a projection's subscription queue.
    pub fn push_delta(&self, projection_id: &str, delta_json: String) -> CortexResult<()> {
        let mut subs = self.subscriptions.lock().map_err(|e| {
            cortex_core::CortexError::ConcurrencyError(format!("subscription lock: {e}"))
        })?;
        let state = subs
            .get_mut(projection_id)
            .ok_or_else(|| MultiAgentError::ProjectionNotFound(projection_id.to_string()))?;

        state.delta_queue.push(delta_json);
        debug!(
            projection_id,
            queue_depth = state.delta_queue.len(),
            "delta pushed to subscription"
        );
        Ok(())
    }

    /// Drain all pending deltas from a projection's queue.
    pub fn drain_queue(&self, projection_id: &str) -> CortexResult<Vec<String>> {
        let mut subs = self.subscriptions.lock().map_err(|e| {
            cortex_core::CortexError::ConcurrencyError(format!("subscription lock: {e}"))
        })?;
        let state = subs
            .get_mut(projection_id)
            .ok_or_else(|| MultiAgentError::ProjectionNotFound(projection_id.to_string()))?;

        let drained = std::mem::take(&mut state.delta_queue);
        debug!(
            projection_id,
            count = drained.len(),
            "drained subscription queue"
        );
        Ok(drained)
    }

    /// Get the current queue depth for a projection.
    pub fn queue_depth(&self, projection_id: &str) -> CortexResult<usize> {
        let subs = self.subscriptions.lock().map_err(|e| {
            cortex_core::CortexError::ConcurrencyError(format!("subscription lock: {e}"))
        })?;
        let state = subs
            .get(projection_id)
            .ok_or_else(|| MultiAgentError::ProjectionNotFound(projection_id.to_string()))?;
        Ok(state.delta_queue.len())
    }
}

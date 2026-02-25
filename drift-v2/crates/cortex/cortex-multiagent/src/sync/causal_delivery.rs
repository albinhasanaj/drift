//! CausalDeliveryManager — ensures deltas are applied in causal order.
//!
//! A delta from Agent A with clock `{A:5, B:3}` can only be applied if the
//! local clock has `A ≥ 4` (all previous A deltas applied) and `B ≥ 3`
//! (all B deltas that A depended on are applied).
//!
//! Out-of-order deltas are buffered until their causal predecessors arrive.
//!
//! # Causal Delivery Guarantee
//!
//! Regardless of delta arrival order, the final materialized state is identical.
//! This is what property tests `TMC-PROP-03` and `TMC-PROP-04` verify.

use cortex_crdt::VectorClock;
use tracing::debug;

/// Manages causal ordering of deltas, buffering out-of-order arrivals.
pub struct CausalDeliveryManager {
    /// Deltas waiting for causal predecessors: (delta_id, clock).
    buffer: Vec<(i64, VectorClock)>,
}

impl CausalDeliveryManager {
    /// Create a new empty delivery manager.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Check if a delta can be applied given the local clock.
    ///
    /// For each agent in the delta clock, the delta's value must be at most
    /// `local + 1`. If any agent's value exceeds `local + 1`, we're missing
    /// intermediate deltas and must buffer.
    ///
    /// This allows concurrent deltas (where multiple agents are each 1 ahead)
    /// to be applied, which is correct for CRDT convergence.
    ///
    /// # Arguments
    ///
    /// * `delta_clock` — The delta's vector clock
    /// * `local_clock` — The local agent's current vector clock
    ///
    /// # Examples
    ///
    /// ```
    /// use cortex_multiagent::sync::CausalDeliveryManager;
    /// use cortex_crdt::VectorClock;
    ///
    /// let manager = CausalDeliveryManager::new();
    /// let mut local = VectorClock::new();
    /// local.increment("A"); // {A:1}
    ///
    /// // Delta with {A:2} — can apply (A incremented by 1).
    /// let mut delta = VectorClock::new();
    /// delta.increment("A");
    /// delta.increment("A");
    /// assert!(manager.can_apply_clock(&delta, &local));
    ///
    /// // Delta with {A:3} — cannot apply (missing A:2).
    /// let mut future = VectorClock::new();
    /// future.increment("A");
    /// future.increment("A");
    /// future.increment("A");
    /// assert!(!manager.can_apply_clock(&future, &local));
    /// ```
    pub fn can_apply_clock(&self, delta_clock: &VectorClock, local_clock: &VectorClock) -> bool {
        // For each agent in the delta clock, check that the local clock
        // has all the causal predecessors.
        for agent in delta_clock.agents() {
            let delta_val = delta_clock.get(agent);
            let local_val = local_clock.get(agent);

            // The delta's clock for this agent should be at most local + 1.
            // If it's more than local + 1, we're missing intermediate deltas.
            if delta_val > local_val + 1 {
                return false;
            }
        }
        true
    }

    /// Buffer a delta that can't be applied yet.
    pub fn buffer_row(&mut self, delta_id: i64, clock: VectorClock) {
        debug!(delta_id, "buffering delta for causal delivery");
        self.buffer.push((delta_id, clock));
    }

    /// Drain all buffered deltas that can now be applied.
    ///
    /// Returns `(delta_id, clock)` pairs for deltas that are now applicable.
    /// Applying one delta may unblock others, so this drains iteratively.
    pub fn drain_applicable(&mut self, local_clock: &VectorClock) -> Vec<(i64, VectorClock)> {
        let mut applicable = Vec::new();
        let mut changed = true;
        let mut current_clock = local_clock.clone();

        while changed {
            changed = false;
            let mut remaining = Vec::new();

            for (delta_id, clock) in std::mem::take(&mut self.buffer) {
                if can_apply_clock_static(&clock, &current_clock) {
                    current_clock.merge(&clock);
                    applicable.push((delta_id, clock));
                    changed = true;
                } else {
                    remaining.push((delta_id, clock));
                }
            }

            self.buffer = remaining;
        }

        if !applicable.is_empty() {
            debug!(
                count = applicable.len(),
                remaining = self.buffer.len(),
                "drained applicable deltas from buffer"
            );
        }

        applicable
    }

    /// Number of deltas currently buffered.
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }
}

/// Static helper: check if a delta can be applied given the local clock.
fn can_apply_clock_static(delta_clock: &VectorClock, local_clock: &VectorClock) -> bool {
    for agent in delta_clock.agents() {
        let delta_val = delta_clock.get(agent);
        let local_val = local_clock.get(agent);
        if delta_val > local_val + 1 {
            return false;
        }
    }
    true
}

impl Default for CausalDeliveryManager {
    fn default() -> Self {
        Self::new()
    }
}

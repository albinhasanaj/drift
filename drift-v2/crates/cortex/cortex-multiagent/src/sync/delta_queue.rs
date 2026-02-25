//! DeltaQueue — persistent SQLite-backed queue for pending deltas.
//!
//! Deltas are enqueued by the source agent and dequeued by the target agent
//! during sync. Applied deltas can be purged after a retention period.

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use tracing::{debug, instrument};

use cortex_core::errors::CortexResult;
use cortex_crdt::VectorClock;

use cortex_storage::queries::multiagent_ops;

/// Persistent delta queue backed by the `delta_queue` SQLite table.
pub struct DeltaQueue;

impl DeltaQueue {
    /// Enqueue a delta for a target agent.
    ///
    /// # Arguments
    ///
    /// * `conn` — Database connection
    /// * `source_agent` — The agent producing the delta
    /// * `target_agent` — The agent that should receive the delta
    /// * `memory_id` — The memory this delta applies to
    /// * `delta_json` — Serialized delta payload
    /// * `clock` — Vector clock at time of delta creation
    /// * `max_queue_size` — Maximum pending deltas before backpressure (0 = unlimited)
    #[instrument(skip(conn, delta_json))]
    pub fn enqueue(
        conn: &Connection,
        source_agent: &str,
        target_agent: &str,
        memory_id: &str,
        delta_json: &str,
        clock: &VectorClock,
        max_queue_size: usize,
    ) -> CortexResult<()> {
        debug!(source_agent, target_agent, memory_id, "enqueuing delta");

        // Backpressure check.
        if max_queue_size > 0 {
            let pending = multiagent_ops::pending_delta_count(conn, target_agent)?;
            if pending >= max_queue_size {
                return Err(cortex_core::errors::MultiAgentError::SyncFailed(format!(
                    "delta queue for agent {} is full ({} pending, max {})",
                    target_agent, pending, max_queue_size
                ))
                .into());
            }
        }

        let clock_json = serde_json::to_string(clock).map_err(|e| {
            cortex_core::CortexError::ValidationError(format!(
                "failed to serialize vector clock: {e}"
            ))
        })?;
        let now = Utc::now().to_rfc3339();

        multiagent_ops::enqueue_delta(
            conn,
            source_agent,
            target_agent,
            memory_id,
            delta_json,
            &clock_json,
            &now,
        )?;

        Ok(())
    }

    /// Dequeue pending deltas for a target agent (up to `limit`).
    ///
    /// Returns deltas ordered by creation time, oldest first.
    /// Only returns unapplied deltas.
    #[instrument(skip(conn))]
    pub fn dequeue(
        conn: &Connection,
        target_agent: &str,
        limit: usize,
    ) -> CortexResult<Vec<multiagent_ops::DeltaRow>> {
        debug!(target_agent, limit, "dequeuing deltas");
        multiagent_ops::dequeue_deltas(conn, target_agent, limit)
    }

    /// Mark deltas as applied.
    ///
    /// Applied deltas are excluded from future `dequeue` calls but remain
    /// in the database until purged.
    #[instrument(skip(conn))]
    pub fn mark_applied(
        conn: &Connection,
        delta_ids: &[i64],
    ) -> CortexResult<()> {
        debug!(count = delta_ids.len(), "marking deltas applied");
        let now = Utc::now().to_rfc3339();
        multiagent_ops::mark_deltas_applied(conn, delta_ids, &now)
    }

    /// Count pending (unapplied) deltas for a target agent.
    #[instrument(skip(conn))]
    pub fn pending_count(
        conn: &Connection,
        target_agent: &str,
    ) -> CortexResult<usize> {
        debug!(target_agent, "counting pending deltas");
        multiagent_ops::pending_delta_count(conn, target_agent)
    }

    /// Purge applied deltas older than the given timestamp.
    ///
    /// Returns the number of deltas purged.
    #[instrument(skip(conn))]
    pub fn purge_applied(
        conn: &Connection,
        older_than: DateTime<Utc>,
    ) -> CortexResult<usize> {
        debug!(%older_than, "purging applied deltas");
        let ts = older_than.to_rfc3339();
        multiagent_ops::purge_applied_deltas(conn, &ts)
    }
}

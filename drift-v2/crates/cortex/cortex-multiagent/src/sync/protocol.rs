//! DeltaSyncEngine — three-phase sync protocol between agents.
//!
//! ```text
//! Agent A                              Agent B
//!    |                                    |
//!    |-- SyncRequest { my_clock } ------->|
//!    |                                    |
//!    |<-- SyncResponse { deltas,          |
//!    |       their_clock }                |
//!    |                                    |
//!    |-- apply deltas, update clock       |
//!    |                                    |
//!    |-- SyncAck { new_clock } ---------->|
//!    |                                    |
//! ```

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};

use cortex_core::errors::CortexResult;
use cortex_core::models::agent::AgentId;
use cortex_crdt::VectorClock;

use cortex_storage::queries::multiagent_ops;

use super::causal_delivery::CausalDeliveryManager;
use super::delta_queue::DeltaQueue;

/// A sync request from one agent to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    /// The agent initiating the sync.
    pub source_agent: AgentId,
    /// The source agent's current vector clock.
    pub clock: VectorClock,
}

/// A sync response containing deltas and the responder's clock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Deltas the requester is missing.
    pub deltas: Vec<DeltaEntry>,
    /// The responder's current vector clock.
    pub clock: VectorClock,
}

/// A single delta entry in a sync response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaEntry {
    /// Database delta ID.
    pub delta_id: i64,
    /// The memory this delta applies to.
    pub memory_id: String,
    /// The agent that produced this delta.
    pub source_agent: String,
    /// The delta payload (serialized FieldDelta list).
    pub delta_json: String,
    /// Vector clock at time of delta creation.
    pub vector_clock: VectorClock,
    /// When this delta was created.
    pub created_at: DateTime<Utc>,
}

/// Acknowledgment after applying deltas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncAck {
    /// The agent sending the ack.
    pub agent_id: AgentId,
    /// The agent's clock after applying deltas.
    pub clock: VectorClock,
}

/// Summary of a sync operation.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Number of deltas sent to the peer.
    pub deltas_sent: usize,
    /// Number of deltas received from the peer.
    pub deltas_received: usize,
    /// Number of deltas successfully applied.
    pub deltas_applied: usize,
    /// Number of deltas buffered (waiting for causal predecessors).
    pub deltas_buffered: usize,
}

/// Orchestrates delta sync between agents.
pub struct DeltaSyncEngine;

impl DeltaSyncEngine {
    /// Initiate a sync from `source_agent` to `target_agent`.
    ///
    /// 1. Dequeue pending deltas for the source from the target's queue
    /// 2. Apply deltas respecting causal ordering
    /// 3. Mark applied deltas
    #[instrument(skip(conn))]
    pub fn initiate_sync(
        conn: &Connection,
        source_agent: &AgentId,
        target_agent: &AgentId,
        local_clock: &mut VectorClock,
    ) -> CortexResult<SyncResult> {
        info!(
            source = %source_agent,
            target = %target_agent,
            "initiating delta sync"
        );

        // Dequeue deltas targeted at source_agent from target_agent.
        let rows = DeltaQueue::dequeue(conn, &source_agent.0, 100)?;
        let deltas_received = rows.len();

        let mut delivery_manager = CausalDeliveryManager::new();
        let mut deltas_applied = 0_usize;
        let mut applied_ids = Vec::new();

        // Process each delta through causal delivery.
        for row in &rows {
            let delta_clock: VectorClock =
                serde_json::from_str(&row.vector_clock).unwrap_or_default();

            if delivery_manager.can_apply_clock(&delta_clock, local_clock) {
                // Apply: merge clock and mark applied.
                local_clock.merge(&delta_clock);
                local_clock.increment(&source_agent.0);
                applied_ids.push(row.delta_id);
                deltas_applied += 1;

                debug!(
                    delta_id = row.delta_id,
                    memory_id = %row.memory_id,
                    "delta applied"
                );
            } else {
                // Buffer for later.
                delivery_manager.buffer_row(row.delta_id, delta_clock);
                debug!(
                    delta_id = row.delta_id,
                    memory_id = %row.memory_id,
                    "delta buffered (causal predecessor missing)"
                );
            }
        }

        // Drain any buffered deltas that are now applicable.
        let drained = delivery_manager.drain_applicable(local_clock);
        for (delta_id, delta_clock) in &drained {
            local_clock.merge(delta_clock);
            local_clock.increment(&source_agent.0);
            applied_ids.push(*delta_id);
            deltas_applied += 1;
        }

        let deltas_buffered = deltas_received - deltas_applied;

        // Mark applied deltas in the database.
        if !applied_ids.is_empty() {
            let now = Utc::now().to_rfc3339();
            multiagent_ops::mark_deltas_applied(conn, &applied_ids, &now)?;
        }

        info!(
            source = %source_agent,
            target = %target_agent,
            deltas_received,
            deltas_applied,
            deltas_buffered,
            "sync complete"
        );

        Ok(SyncResult {
            deltas_sent: 0,
            deltas_received,
            deltas_applied,
            deltas_buffered,
        })
    }

    /// Handle a sync request: compute deltas the requester is missing.
    #[instrument(skip(conn))]
    pub fn handle_sync_request(
        conn: &Connection,
        request: &SyncRequest,
    ) -> CortexResult<SyncResponse> {
        debug!(
            source = %request.source_agent,
            "handling sync request"
        );

        let rows = DeltaQueue::dequeue(conn, &request.source_agent.0, 100)?;

        let deltas: Vec<DeltaEntry> = rows
            .iter()
            .map(|row| {
                let clock: VectorClock =
                    serde_json::from_str(&row.vector_clock).unwrap_or_default();
                let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                DeltaEntry {
                    delta_id: row.delta_id,
                    memory_id: row.memory_id.clone(),
                    source_agent: row.source_agent.clone(),
                    delta_json: row.delta_json.clone(),
                    vector_clock: clock,
                    created_at,
                }
            })
            .collect();

        Ok(SyncResponse {
            deltas,
            clock: request.clock.clone(),
        })
    }

    /// Acknowledge a sync: persist the peer's vector clock for future delta computation.
    #[instrument(skip(conn))]
    pub fn acknowledge_sync(
        conn: &Connection,
        ack: &SyncAck,
    ) -> CortexResult<()> {
        debug!(
            agent = %ack.agent_id,
            "sync acknowledged — persisting peer clock"
        );

        // A-02: Persist the peer's clock so future syncs can compute
        // which deltas the peer has already seen.
        let clock_json = serde_json::to_string(&ack.clock).map_err(|e| {
            cortex_core::CortexError::ValidationError(format!(
                "failed to serialize peer clock: {e}"
            ))
        })?;
        let now = Utc::now().to_rfc3339();

        multiagent_ops::upsert_peer_clock(
            conn,
            &ack.agent_id.0,
            &ack.agent_id.0, // peer's own clock state
            &clock_json,
            &now,
        )?;

        info!(
            agent = %ack.agent_id,
            "peer clock persisted"
        );

        Ok(())
    }
}

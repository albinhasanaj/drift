//! ProvenanceTracker — record and query provenance chains.
//!
//! Every cross-agent interaction appends a hop. Provenance is append-only:
//! existing hops are never modified or deleted.
//!
//! # Examples
//!
//! ```no_run
//! use cortex_multiagent::provenance::ProvenanceTracker;
//! use cortex_core::models::provenance::{ProvenanceHop, ProvenanceAction};
//! use cortex_core::models::agent::AgentId;
//! use chrono::Utc;
//!
//! // Record a hop and retrieve the chain.
//! // let tracker = ProvenanceTracker;
//! // let hop = ProvenanceHop {
//! //     agent_id: AgentId::from("agent-1"),
//! //     action: ProvenanceAction::Created,
//! //     timestamp: Utc::now(),
//! //     confidence_delta: 0.0,
//! // };
//! // tracker.record_hop(conn, "mem-1", &hop).unwrap();
//! // let chain = tracker.get_chain(conn, "mem-1").unwrap();
//! // assert_eq!(chain.len(), 1);
//! ```

use chrono::DateTime;
use rusqlite::Connection;
use tracing::{debug, instrument};

use cortex_core::errors::CortexResult;
use cortex_core::models::agent::AgentId;
use cortex_core::models::provenance::{
    ProvenanceAction, ProvenanceHop, ProvenanceOrigin, ProvenanceRecord,
};
use cortex_storage::queries::multiagent_ops;

/// Records and queries provenance chains for memories.
///
/// Provenance is append-only: once a hop is recorded, it is never modified
/// or deleted. This provides an immutable audit trail of how knowledge
/// flows between agents.
pub struct ProvenanceTracker;

impl ProvenanceTracker {
    /// Append a provenance hop to a memory's chain.
    ///
    /// The hop is inserted at the next available `hop_index`. Confidence
    /// delta must be in `[-1.0, 1.0]`.
    #[instrument(skip(conn), fields(memory_id, agent_id = %hop.agent_id, action = ?hop.action))]
    pub fn record_hop(
        conn: &Connection,
        memory_id: &str,
        hop: &ProvenanceHop,
    ) -> CortexResult<()> {
        debug!(
            memory_id,
            agent_id = %hop.agent_id,
            action = ?hop.action,
            confidence_delta = hop.confidence_delta,
            "recording provenance hop"
        );

        // Validate confidence_delta range.
        if !(-1.0..=1.0).contains(&hop.confidence_delta) {
            return Err(cortex_core::CortexError::ValidationError(format!(
                "confidence_delta {} out of range [-1.0, 1.0]",
                hop.confidence_delta
            )));
        }

        let chain = multiagent_ops::get_provenance_chain(conn, memory_id)?;
        let hop_index = chain.len() as i32;
        let timestamp_str = hop.timestamp.to_rfc3339();
        let action_str = action_to_str(&hop.action);

        multiagent_ops::insert_provenance_hop(
            conn,
            &multiagent_ops::InsertProvenanceHopParams {
                memory_id,
                hop_index,
                agent_id: &hop.agent_id.0,
                action: action_str,
                timestamp: &timestamp_str,
                confidence_delta: hop.confidence_delta,
                details: None,
            },
        )?;

        Ok(())
    }

    /// Get the full provenance record for a memory.
    ///
    /// Returns `None` if no provenance hops exist for this memory.
    #[instrument(skip(conn))]
    pub fn get_provenance(
        conn: &Connection,
        memory_id: &str,
    ) -> CortexResult<Option<ProvenanceRecord>> {
        debug!(memory_id, "getting provenance record");

        let rows = multiagent_ops::get_provenance_chain(conn, memory_id)?;
        if rows.is_empty() {
            return Ok(None);
        }

        let chain: Vec<ProvenanceHop> = rows.iter().map(row_to_hop).collect();
        let origin = origin_from_action(&chain[0].action);
        let chain_confidence = compute_chain_confidence(&chain);

        Ok(Some(ProvenanceRecord {
            memory_id: memory_id.to_string(),
            origin,
            chain,
            chain_confidence,
        }))
    }

    /// Get the hop chain for a memory (ordered by hop_index).
    #[instrument(skip(conn))]
    pub fn get_chain(
        conn: &Connection,
        memory_id: &str,
    ) -> CortexResult<Vec<ProvenanceHop>> {
        debug!(memory_id, "getting provenance chain");
        let rows = multiagent_ops::get_provenance_chain(conn, memory_id)?;
        Ok(rows.iter().map(row_to_hop).collect())
    }

    /// Get the origin of a memory (determined by the first hop's action).
    #[instrument(skip(conn))]
    pub fn get_origin(
        conn: &Connection,
        memory_id: &str,
    ) -> CortexResult<ProvenanceOrigin> {
        debug!(memory_id, "getting provenance origin");
        let origin_row = multiagent_ops::get_provenance_origin(conn, memory_id)?;
        match origin_row {
            Some(row) => {
                let action = str_to_action(&row.action);
                Ok(origin_from_action(&action))
            }
            None => Ok(ProvenanceOrigin::Human), // Default if no provenance.
        }
    }

    /// Compute the chain confidence for a memory.
    ///
    /// Product of `(1.0 + confidence_delta)` for each hop, clamped to `[0.0, 1.0]`.
    ///
    /// # Example
    ///
    /// ```text
    /// Created (delta=0.0) → Shared (delta=0.0) → Validated (delta=+0.1) → Used (delta=+0.05)
    /// chain = 1.0 × 1.0 × 1.1 × 1.05 = 1.155 → clamped to 1.0
    /// ```
    #[instrument(skip(conn))]
    pub fn chain_confidence(
        conn: &Connection,
        memory_id: &str,
    ) -> CortexResult<f64> {
        debug!(memory_id, "computing chain confidence");
        let chain = Self::get_chain(conn, memory_id)?;
        Ok(compute_chain_confidence(&chain))
    }
}

/// Compute chain confidence: product of (1.0 + delta) for each hop, clamped [0.0, 1.0].
fn compute_chain_confidence(chain: &[ProvenanceHop]) -> f64 {
    if chain.is_empty() {
        return 1.0;
    }
    let product: f64 = chain
        .iter()
        .map(|hop| 1.0 + hop.confidence_delta)
        .product();
    product.clamp(0.0, 1.0)
}

/// Convert a `ProvenanceAction` to its storage string representation.
fn action_to_str(action: &ProvenanceAction) -> &'static str {
    match action {
        ProvenanceAction::Created => "created",
        ProvenanceAction::SharedTo => "shared_to",
        ProvenanceAction::ProjectedTo => "projected_to",
        ProvenanceAction::MergedWith => "merged_with",
        ProvenanceAction::ConsolidatedFrom => "consolidated_from",
        ProvenanceAction::ValidatedBy => "validated_by",
        ProvenanceAction::UsedInDecision => "used_in_decision",
        ProvenanceAction::CorrectedBy => "corrected_by",
        ProvenanceAction::ReclassifiedFrom => "reclassified_from",
        ProvenanceAction::Retracted => "retracted",
    }
}

/// Parse a storage string into a `ProvenanceAction`.
fn str_to_action(s: &str) -> ProvenanceAction {
    match s {
        "created" => ProvenanceAction::Created,
        "shared_to" => ProvenanceAction::SharedTo,
        "projected_to" => ProvenanceAction::ProjectedTo,
        "merged_with" => ProvenanceAction::MergedWith,
        "consolidated_from" => ProvenanceAction::ConsolidatedFrom,
        "validated_by" => ProvenanceAction::ValidatedBy,
        "used_in_decision" => ProvenanceAction::UsedInDecision,
        "corrected_by" => ProvenanceAction::CorrectedBy,
        "reclassified_from" => ProvenanceAction::ReclassifiedFrom,
        "retracted" => ProvenanceAction::Retracted,
        _ => ProvenanceAction::Created, // Fallback.
    }
}

/// Determine the provenance origin from the first hop's action.
fn origin_from_action(action: &ProvenanceAction) -> ProvenanceOrigin {
    match action {
        ProvenanceAction::Created => ProvenanceOrigin::AgentCreated,
        ProvenanceAction::ProjectedTo => ProvenanceOrigin::Projected,
        ProvenanceAction::SharedTo => ProvenanceOrigin::Derived,
        ProvenanceAction::MergedWith => ProvenanceOrigin::Derived,
        ProvenanceAction::ConsolidatedFrom => ProvenanceOrigin::Derived,
        ProvenanceAction::Retracted => ProvenanceOrigin::Derived,
        _ => ProvenanceOrigin::Human,
    }
}

/// Convert a storage row to a `ProvenanceHop`.
fn row_to_hop(row: &multiagent_ops::ProvenanceRow) -> ProvenanceHop {
    let timestamp = DateTime::parse_from_rfc3339(&row.timestamp)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    ProvenanceHop {
        agent_id: AgentId::from(row.agent_id.as_str()),
        action: str_to_action(&row.action),
        timestamp,
        confidence_delta: row.confidence_delta,
    }
}

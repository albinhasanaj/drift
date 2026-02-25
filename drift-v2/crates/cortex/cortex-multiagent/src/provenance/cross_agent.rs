//! CrossAgentTracer — trace knowledge across agent boundaries.
//!
//! Follows provenance chains to discover how knowledge flows between agents,
//! tracking confidence at each hop and identifying all agents involved.

use rusqlite::Connection;
use tracing::{debug, instrument};

use cortex_core::errors::CortexResult;
use cortex_core::models::agent::AgentId;

use super::tracker::ProvenanceTracker;

/// A trace of knowledge flow across agent boundaries.
#[derive(Debug, Clone)]
pub struct CrossAgentTrace {
    /// The memory being traced.
    pub memory_id: String,
    /// Agents involved in the chain, ordered by first involvement.
    pub agents_involved: Vec<AgentId>,
    /// Total number of hops in the chain.
    pub hop_count: usize,
    /// Confidence at each hop (cumulative product).
    pub confidence_chain: Vec<f64>,
    /// Total confidence through the entire chain.
    pub total_confidence: f64,
}

/// Traces knowledge across agent boundaries via provenance chains.
pub struct CrossAgentTracer;

impl CrossAgentTracer {
    /// Trace a memory's provenance across agent boundaries.
    ///
    /// Follows the provenance chain up to `max_depth` hops, recording
    /// each agent transition and the cumulative confidence at each hop.
    ///
    /// # Arguments
    ///
    /// * `conn` — Database connection
    /// * `memory_id` — The memory to trace
    /// * `max_depth` — Maximum number of hops to follow
    #[instrument(skip(conn), fields(memory_id, max_depth))]
    pub fn trace_cross_agent(
        conn: &Connection,
        memory_id: &str,
        max_depth: usize,
    ) -> CortexResult<CrossAgentTrace> {
        debug!(memory_id, max_depth, "tracing cross-agent provenance");

        let chain = ProvenanceTracker::get_chain(conn, memory_id)?;

        let mut agents_involved: Vec<AgentId> = Vec::new();
        let mut confidence_chain: Vec<f64> = Vec::new();
        let mut cumulative_confidence = 1.0_f64;

        let hops_to_process = chain.len().min(max_depth);

        for hop in chain.iter().take(hops_to_process) {
            // Track unique agents in order of first appearance.
            if !agents_involved.iter().any(|a| a == &hop.agent_id) {
                agents_involved.push(hop.agent_id.clone());
            }

            // Accumulate confidence.
            cumulative_confidence *= 1.0 + hop.confidence_delta;
            confidence_chain.push(cumulative_confidence.clamp(0.0, 1.0));
        }

        let total_confidence = cumulative_confidence.clamp(0.0, 1.0);

        debug!(
            memory_id,
            agents = agents_involved.len(),
            hops = hops_to_process,
            total_confidence,
            "cross-agent trace complete"
        );

        Ok(CrossAgentTrace {
            memory_id: memory_id.to_string(),
            agents_involved,
            hop_count: hops_to_process,
            confidence_chain,
            total_confidence,
        })
    }
}

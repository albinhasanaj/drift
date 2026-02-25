//! CorrectionPropagator — propagate corrections through provenance chains.
//!
//! When a memory is corrected, the correction propagates to downstream
//! memories with exponential dampening: `strength = base × 0.7^hop_distance`.
//! Propagation stops when strength falls below the threshold (default 0.05).
//!
//! # Dampening Rationale
//!
//! A correction at the source has full effect. One hop away, 70% effect.
//! Two hops, 49%. This prevents a single correction from cascading through
//! the entire knowledge graph while still propagating important corrections
//! to nearby dependents.

use chrono::Utc;
use rusqlite::Connection;
use tracing::{debug, info, instrument};

use cortex_core::config::MultiAgentConfig;
use cortex_core::errors::CortexResult;
use cortex_core::models::agent::AgentId;
use cortex_core::models::provenance::{ProvenanceAction, ProvenanceHop};

use cortex_storage::queries::multiagent_ops;

use super::tracker::ProvenanceTracker;

/// Result of a correction propagation to a single memory.
#[derive(Debug, Clone)]
pub struct CorrectionResult {
    /// The memory that was (or would be) corrected.
    pub memory_id: String,
    /// How many hops from the original correction.
    pub hop_distance: usize,
    /// The dampened correction strength at this hop.
    pub correction_strength: f64,
    /// Whether the correction was actually applied (false if below threshold).
    pub applied: bool,
}

/// Propagates corrections through provenance chains with exponential dampening.
pub struct CorrectionPropagator {
    /// Dampening factor per hop (default: 0.7).
    dampening_factor: f64,
    /// Minimum strength before propagation stops (default: 0.05).
    min_threshold: f64,
}

impl CorrectionPropagator {
    /// Create a new propagator from config.
    pub fn new(config: &MultiAgentConfig) -> Self {
        Self {
            dampening_factor: config.correction_dampening_factor,
            min_threshold: config.correction_min_threshold,
        }
    }

    /// Propagate a correction through the provenance chain of a memory.
    ///
    /// Traces the provenance chain from `memory_id`, applying dampened
    /// corrections at each hop. Records a `CorrectedBy` provenance hop
    /// for each affected memory.
    ///
    /// Returns the list of all memories in the chain with their correction
    /// strengths and whether the correction was applied.
    #[instrument(skip(self, conn), fields(memory_id, correction))]
    pub fn propagate_correction(
        &self,
        conn: &Connection,
        memory_id: &str,
        correction: &str,
    ) -> CortexResult<Vec<CorrectionResult>> {
        info!(memory_id, correction, "propagating correction");

        let chain = multiagent_ops::get_provenance_chain(conn, memory_id)?;
        let mut results = Vec::new();

        // The original memory gets full correction (distance 0).
        results.push(CorrectionResult {
            memory_id: memory_id.to_string(),
            hop_distance: 0,
            correction_strength: 1.0,
            applied: true,
        });

        // Find downstream memories by looking at provenance hops that reference
        // shared/projected actions — these indicate the memory was propagated.
        // For each hop in the chain, we look for memories that were derived from this one.
        for (distance, row) in chain.iter().enumerate() {
            let hop_distance = distance + 1;
            let strength = self.correction_strength(hop_distance);

            let result = CorrectionResult {
                memory_id: row.memory_id.clone(),
                hop_distance,
                correction_strength: strength,
                applied: strength >= self.min_threshold,
            };

            if result.applied {
                // Record a CorrectedBy provenance hop on the affected memory.
                let hop = ProvenanceHop {
                    agent_id: AgentId::from(row.agent_id.as_str()),
                    action: ProvenanceAction::CorrectedBy,
                    timestamp: Utc::now(),
                    confidence_delta: -(1.0 - strength) * 0.1, // Small negative delta.
                };
                ProvenanceTracker::record_hop(conn, &row.memory_id, &hop)?;

                debug!(
                    memory_id = %row.memory_id,
                    hop_distance,
                    strength,
                    "correction applied"
                );
            } else {
                debug!(
                    memory_id = %row.memory_id,
                    hop_distance,
                    strength,
                    "correction below threshold, not applied"
                );
            }

            results.push(result);
        }

        info!(
            memory_id,
            total_affected = results.len(),
            "correction propagation complete"
        );
        Ok(results)
    }

    /// Compute the correction strength at a given hop distance.
    ///
    /// `strength = dampening_factor ^ hop_distance`
    ///
    /// Examples with default dampening (0.7):
    /// - Distance 0: 1.0
    /// - Distance 1: 0.7
    /// - Distance 2: 0.49
    /// - Distance 3: 0.343
    /// - Distance 4: 0.2401
    /// - Distance 5: 0.168
    pub fn correction_strength(&self, hop_distance: usize) -> f64 {
        self.dampening_factor.powi(hop_distance as i32)
    }
}

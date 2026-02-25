//! TrustEvidenceTracker — accumulate trust evidence from cross-agent interactions.
//!
//! All evidence updates are performed atomically within the caller's transaction
//! context. Each method increments the appropriate counter and recomputes the
//! overall trust score.

use chrono::Utc;
use rusqlite::Connection;
use tracing::{debug, instrument};

use cortex_core::errors::CortexResult;
use cortex_core::models::agent::AgentId;
use cortex_core::models::cross_agent::{AgentTrust, TrustEvidence};

use cortex_storage::queries::multiagent_ops;

use super::bootstrap::bootstrap_trust;
use super::scorer::TrustScorer;

/// Accumulates trust evidence from cross-agent interactions.
///
/// Each method loads the current trust record (or bootstraps a new one),
/// increments the appropriate counter, recomputes the trust score, and
/// persists the update.
pub struct TrustEvidenceTracker;

impl TrustEvidenceTracker {
    /// Record that `agent_id` validated a memory from `target_agent`.
    ///
    /// Increments `validated_count` and `total_received`, then recomputes trust.
    #[instrument(skip(conn))]
    pub fn record_validation(
        conn: &Connection,
        agent_id: &AgentId,
        target_agent: &AgentId,
        memory_id: &str,
    ) -> CortexResult<()> {
        // Prevent self-trust manipulation.
        if agent_id == target_agent {
            return Err(cortex_core::CortexError::ValidationError(
                "agent cannot record trust evidence about itself".to_string(),
            ));
        }

        debug!(
            agent_id = %agent_id,
            target_agent = %target_agent,
            memory_id,
            "recording validation evidence"
        );

        let mut trust = load_or_bootstrap(conn, agent_id, target_agent)?;
        trust.evidence.validated_count += 1;
        trust.evidence.total_received += 1;
        trust.overall_trust = TrustScorer::compute_overall_trust(&trust.evidence);
        trust.last_updated = Utc::now();

        TrustScorer::update_trust(conn, &trust)?;
        Ok(())
    }

    /// Record that `agent_id` found a contradiction in a memory from `target_agent`.
    ///
    /// Increments `contradicted_count` and `total_received`, then recomputes trust.
    #[instrument(skip(conn))]
    pub fn record_contradiction(
        conn: &Connection,
        agent_id: &AgentId,
        target_agent: &AgentId,
        memory_id: &str,
    ) -> CortexResult<()> {
        // Prevent self-trust manipulation.
        if agent_id == target_agent {
            return Err(cortex_core::CortexError::ValidationError(
                "agent cannot record trust evidence about itself".to_string(),
            ));
        }

        debug!(
            agent_id = %agent_id,
            target_agent = %target_agent,
            memory_id,
            "recording contradiction evidence"
        );

        let mut trust = load_or_bootstrap(conn, agent_id, target_agent)?;
        trust.evidence.contradicted_count += 1;
        trust.evidence.total_received += 1;
        trust.overall_trust = TrustScorer::compute_overall_trust(&trust.evidence);
        trust.last_updated = Utc::now();

        TrustScorer::update_trust(conn, &trust)?;
        Ok(())
    }

    /// Record that `agent_id` found a memory from `target_agent` useful.
    ///
    /// Increments `useful_count` and `total_received`, then recomputes trust.
    #[instrument(skip(conn))]
    pub fn record_usage(
        conn: &Connection,
        agent_id: &AgentId,
        target_agent: &AgentId,
        memory_id: &str,
    ) -> CortexResult<()> {
        // Prevent self-trust manipulation.
        if agent_id == target_agent {
            return Err(cortex_core::CortexError::ValidationError(
                "agent cannot record trust evidence about itself".to_string(),
            ));
        }

        debug!(
            agent_id = %agent_id,
            target_agent = %target_agent,
            memory_id,
            "recording usage evidence"
        );

        let mut trust = load_or_bootstrap(conn, agent_id, target_agent)?;
        trust.evidence.useful_count += 1;
        trust.evidence.total_received += 1;
        trust.overall_trust = TrustScorer::compute_overall_trust(&trust.evidence);
        trust.last_updated = Utc::now();

        TrustScorer::update_trust(conn, &trust)?;
        Ok(())
    }

    /// Get the current trust evidence from `agent_id` toward `target_agent`.
    #[instrument(skip(conn))]
    pub fn get_evidence(
        conn: &Connection,
        agent_id: &AgentId,
        target_agent: &AgentId,
    ) -> CortexResult<TrustEvidence> {
        debug!(
            agent_id = %agent_id,
            target_agent = %target_agent,
            "getting trust evidence"
        );

        let row = multiagent_ops::get_trust(conn, &agent_id.0, &target_agent.0)?;
        match row {
            Some(row) => {
                let evidence: TrustEvidence =
                    serde_json::from_str(&row.evidence).unwrap_or_default();
                Ok(evidence)
            }
            None => Ok(TrustEvidence::default()),
        }
    }
}

/// Load existing trust or bootstrap a new record.
fn load_or_bootstrap(
    conn: &Connection,
    agent_id: &AgentId,
    target_agent: &AgentId,
) -> CortexResult<AgentTrust> {
    let row = multiagent_ops::get_trust(conn, &agent_id.0, &target_agent.0)?;
    match row {
        Some(row) => {
            let evidence: TrustEvidence =
                serde_json::from_str(&row.evidence).unwrap_or_default();
            let domain_trust = row
                .domain_trust
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let last_updated = chrono::DateTime::parse_from_rfc3339(&row.last_updated)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(AgentTrust {
                agent_id: agent_id.clone(),
                target_agent: target_agent.clone(),
                overall_trust: row.overall_trust,
                domain_trust,
                evidence,
                last_updated,
            })
        }
        None => {
            // Bootstrap new trust relationship.
            let trust = bootstrap_trust(agent_id, target_agent);
            TrustScorer::update_trust(conn, &trust)?;
            Ok(trust)
        }
    }
}

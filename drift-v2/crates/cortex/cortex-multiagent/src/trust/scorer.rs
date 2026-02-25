//! TrustScorer — compute and manage agent trust scores.
//!
//! Trust formula: `(validated + useful) / (total + 1) × (1 - contradicted / (total + 1))`
//!
//! The multiplication means contradictions have outsized impact. An agent with
//! 10 validated, 2 contradicted, 3 useful, 20 total:
//! - Positive: (10 + 3) / 21 = 0.619
//! - Negative: 1 - 2/21 = 0.905
//! - Overall: 0.619 × 0.905 = 0.560
//!
//! This asymmetric penalty creates a conservative trust model — appropriate
//! for a code-aware system where bad knowledge can cause bugs.

use std::collections::HashMap;

use chrono::Utc;
use rusqlite::Connection;
use tracing::{debug, instrument};

use cortex_core::config::MultiAgentConfig;
use cortex_core::errors::{CortexResult, MultiAgentError};
use cortex_core::models::agent::AgentId;
use cortex_core::models::cross_agent::{AgentTrust, TrustEvidence};

use cortex_storage::queries::multiagent_ops;

/// Computes and manages agent trust scores.
pub struct TrustScorer {
    config: MultiAgentConfig,
}

impl TrustScorer {
    /// Create a new TrustScorer with the given config.
    pub fn new(config: &MultiAgentConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Get the config.
    pub fn config(&self) -> &MultiAgentConfig {
        &self.config
    }

    /// Get the bootstrap trust score for new agents from config.
    pub fn bootstrap_score(&self) -> f64 {
        self.config.trust_bootstrap_score
    }

    /// Compute config-weighted trust score.
    ///
    /// Uses the configured penalty/bonus weights instead of the default
    /// symmetric formula. This allows operators to tune how aggressively
    /// contradictions penalize trust vs how quickly validations build it.
    pub fn compute_weighted_trust(&self, evidence: &TrustEvidence) -> f64 {
        let total = evidence.total_received as f64;
        if total < f64::EPSILON {
            return self.config.trust_bootstrap_score;
        }

        let validation_score = evidence.validated_count as f64 * self.config.trust_validation_bonus;
        let usage_score = evidence.useful_count as f64 * self.config.trust_usage_bonus;
        let contradiction_penalty = evidence.contradicted_count as f64 * self.config.trust_contradiction_penalty;

        let raw = self.config.trust_bootstrap_score + validation_score + usage_score - contradiction_penalty;
        raw.clamp(0.0, 1.0)
    }

    /// Get the trust relationship from `agent_id` toward `target_agent`.
    #[instrument(skip(conn))]
    pub fn get_trust(
        conn: &Connection,
        agent_id: &AgentId,
        target_agent: &AgentId,
    ) -> CortexResult<AgentTrust> {
        debug!(agent_id = %agent_id, target_agent = %target_agent, "getting trust");

        let row = multiagent_ops::get_trust(conn, &agent_id.0, &target_agent.0)?;
        match row {
            Some(row) => Ok(trust_from_row(&row, agent_id, target_agent)),
            None => Err(MultiAgentError::TrustComputationFailed(format!(
                "no trust record for {} → {}",
                agent_id, target_agent
            ))
            .into()),
        }
    }

    /// Compute the overall trust score from evidence.
    ///
    /// Formula: `(validated + useful) / (total + 1) × (1 - contradicted / (total + 1))`
    /// Result is clamped to `[0.0, 1.0]`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cortex_multiagent::trust::TrustScorer;
    /// use cortex_core::models::cross_agent::TrustEvidence;
    ///
    /// let evidence = TrustEvidence {
    ///     validated_count: 5,
    ///     contradicted_count: 1,
    ///     useful_count: 3,
    ///     total_received: 10,
    /// };
    /// let trust = TrustScorer::compute_overall_trust(&evidence);
    /// // (5+3)/(10+1) × (1 - 1/(10+1)) = 8/11 × 10/11 ≈ 0.661
    /// assert!((trust - 0.661).abs() < 0.01);
    /// ```
    pub fn compute_overall_trust(evidence: &TrustEvidence) -> f64 {
        let total = evidence.total_received as f64;
        let positive = (evidence.validated_count + evidence.useful_count) as f64;
        let negative = evidence.contradicted_count as f64;

        let trust = (positive / (total + 1.0)) * (1.0 - negative / (total + 1.0));
        trust.clamp(0.0, 1.0)
    }

    /// Compute domain-specific trust using the same formula scoped to a domain.
    ///
    /// Uses the same formula as `compute_overall_trust` but with domain-specific
    /// evidence counts.
    pub fn compute_domain_trust(evidence: &TrustEvidence) -> f64 {
        // Same formula, just scoped to domain evidence.
        Self::compute_overall_trust(evidence)
    }

    /// Compute effective confidence by modulating memory confidence with trust.
    ///
    /// `effective = memory_confidence × trust_score`
    ///
    /// # Examples
    ///
    /// ```
    /// use cortex_multiagent::trust::TrustScorer;
    ///
    /// let effective = TrustScorer::effective_confidence(0.85, 0.9);
    /// assert!((effective - 0.765).abs() < 0.001);
    /// ```
    pub fn effective_confidence(memory_confidence: f64, trust_score: f64) -> f64 {
        (memory_confidence * trust_score).clamp(0.0, 1.0)
    }

    /// Update (upsert) a trust record in the database.
    #[instrument(skip(conn))]
    pub fn update_trust(
        conn: &Connection,
        trust: &AgentTrust,
    ) -> CortexResult<()> {
        debug!(
            agent_id = %trust.agent_id,
            target_agent = %trust.target_agent,
            overall_trust = trust.overall_trust,
            "updating trust"
        );

        let domain_json = if trust.domain_trust.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&trust.domain_trust).map_err(|e| {
                cortex_core::CortexError::ValidationError(format!(
                    "failed to serialize domain trust: {e}"
                ))
            })?)
        };
        let evidence_json = serde_json::to_string(&trust.evidence).map_err(|e| {
            cortex_core::CortexError::ValidationError(format!(
                "failed to serialize trust evidence: {e}"
            ))
        })?;
        let last_updated = trust.last_updated.to_rfc3339();

        multiagent_ops::upsert_trust(
            conn,
            &trust.agent_id.0,
            &trust.target_agent.0,
            trust.overall_trust,
            domain_json.as_deref(),
            &evidence_json,
            &last_updated,
        )?;

        Ok(())
    }
}

/// Convert a storage row to an `AgentTrust`.
fn trust_from_row(
    row: &multiagent_ops::TrustRow,
    agent_id: &AgentId,
    target_agent: &AgentId,
) -> AgentTrust {
    let domain_trust: HashMap<String, f64> = row
        .domain_trust
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let evidence: TrustEvidence = serde_json::from_str(&row.evidence).unwrap_or_default();

    let last_updated = chrono::DateTime::parse_from_rfc3339(&row.last_updated)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    AgentTrust {
        agent_id: agent_id.clone(),
        target_agent: target_agent.clone(),
        overall_trust: row.overall_trust,
        domain_trust,
        evidence,
        last_updated,
    }
}

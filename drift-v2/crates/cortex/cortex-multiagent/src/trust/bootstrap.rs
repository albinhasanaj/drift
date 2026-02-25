//! Trust bootstrap for new and spawned agents.
//!
//! - New agents start at `overall_trust = 0.5` (neutral).
//! - Spawned agents inherit `parent_trust × discount` (default 0.8).
//! - Evidence always starts empty — spawned agents must earn their own.

use chrono::Utc;

use cortex_core::models::agent::AgentId;
use cortex_core::models::cross_agent::{AgentTrust, TrustEvidence};

/// Bootstrap trust for a new agent.
///
/// New agents start at `overall_trust = 0.5` (neutral, "I don't know").
/// This is the correct starting point: no evidence means no opinion,
/// not distrust.
///
/// # Examples
///
/// ```
/// use cortex_multiagent::trust::bootstrap_trust;
/// use cortex_core::models::agent::AgentId;
///
/// let trust = bootstrap_trust(&AgentId::from("observer"), &AgentId::from("new-agent"));
/// assert!((trust.overall_trust - 0.5).abs() < f64::EPSILON);
/// assert_eq!(trust.evidence.total_received, 0);
/// ```
pub fn bootstrap_trust(agent_id: &AgentId, target_agent: &AgentId) -> AgentTrust {
    AgentTrust {
        agent_id: agent_id.clone(),
        target_agent: target_agent.clone(),
        overall_trust: 0.5,
        domain_trust: Default::default(),
        evidence: TrustEvidence::default(),
        last_updated: Utc::now(),
    }
}

/// Bootstrap trust for a spawned agent from its parent's trust.
///
/// The spawned agent inherits `parent_trust × discount` for both overall
/// and domain-specific trust. Evidence starts empty — the spawned agent
/// must earn its own reputation.
///
/// # Arguments
///
/// * `parent_trust` — The parent agent's trust record
/// * `discount` — Discount factor (default: 0.8)
///
/// # Examples
///
/// ```
/// use cortex_multiagent::trust::bootstrap_from_parent;
/// use cortex_core::models::cross_agent::{AgentTrust, TrustEvidence};
/// use cortex_core::models::agent::AgentId;
/// use chrono::Utc;
///
/// let parent = AgentTrust {
///     agent_id: AgentId::from("observer"),
///     target_agent: AgentId::from("parent"),
///     overall_trust: 0.8,
///     domain_trust: Default::default(),
///     evidence: TrustEvidence { validated_count: 10, contradicted_count: 0, useful_count: 5, total_received: 15 },
///     last_updated: Utc::now(),
/// };
///
/// let spawned = bootstrap_from_parent(&parent, &AgentId::from("child"), 0.8);
/// assert!((spawned.overall_trust - 0.64).abs() < 0.001); // 0.8 × 0.8
/// assert_eq!(spawned.evidence.total_received, 0); // Evidence starts empty.
/// ```
pub fn bootstrap_from_parent(
    parent_trust: &AgentTrust,
    spawned_agent: &AgentId,
    discount: f64,
) -> AgentTrust {
    let overall = (parent_trust.overall_trust * discount).clamp(0.0, 1.0);

    let domain_trust = parent_trust
        .domain_trust
        .iter()
        .map(|(domain, &score)| (domain.clone(), (score * discount).clamp(0.0, 1.0)))
        .collect();

    AgentTrust {
        agent_id: parent_trust.agent_id.clone(),
        target_agent: spawned_agent.clone(),
        overall_trust: overall,
        domain_trust,
        evidence: TrustEvidence::default(), // Spawned agent starts with empty evidence.
        last_updated: Utc::now(),
    }
}

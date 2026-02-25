//! Trust decay toward neutral (0.5).
//!
//! Without new evidence, trust scores drift toward 0.5 (neutral, "I don't know")
//! rather than 0.0 ("I don't trust"). This prevents stale trust scores from
//! permanently biasing agent interactions.
//!
//! Formula: `trust_new = trust + (0.5 - trust) × (1 - decay_rate^days)`
//!
//! With default `decay_rate = 0.99`:
//! - After 100 days: drifts ~63% toward 0.5
//! - After 200 days: drifts ~86% toward 0.5

use cortex_core::models::cross_agent::AgentTrust;
use tracing::debug;

/// Apply trust decay toward neutral (0.5).
///
/// # Arguments
///
/// * `trust` — The trust record to decay (modified in place)
/// * `days_since_evidence` — Days since the last evidence was recorded
/// * `decay_rate` — Daily retention rate (default: 0.99)
///
/// # Formula
///
/// ```text
/// trust_new = trust + (0.5 - trust) × (1 - decay_rate^days)
/// ```
///
/// # Examples
///
/// ```
/// use cortex_core::models::cross_agent::{AgentTrust, TrustEvidence};
/// use cortex_core::models::agent::AgentId;
/// use cortex_multiagent::trust::apply_trust_decay;
/// use chrono::Utc;
///
/// let mut trust = AgentTrust {
///     agent_id: AgentId::from("a"),
///     target_agent: AgentId::from("b"),
///     overall_trust: 0.9,
///     domain_trust: Default::default(),
///     evidence: TrustEvidence::default(),
///     last_updated: Utc::now(),
/// };
///
/// apply_trust_decay(&mut trust, 100.0, 0.99);
/// // 0.9 + (0.5 - 0.9) × (1 - 0.99^100) ≈ 0.9 + (-0.4) × 0.634 ≈ 0.646
/// assert!(trust.overall_trust < 0.9);
/// assert!(trust.overall_trust > 0.5);
/// ```
pub fn apply_trust_decay(trust: &mut AgentTrust, days_since_evidence: f64, decay_rate: f64) {
    let decay_factor = 1.0 - decay_rate.powf(days_since_evidence);

    let old_trust = trust.overall_trust;
    trust.overall_trust += (0.5 - trust.overall_trust) * decay_factor;
    trust.overall_trust = trust.overall_trust.clamp(0.0, 1.0);

    // Also decay domain-specific trust scores.
    for (_domain, domain_trust) in trust.domain_trust.iter_mut() {
        *domain_trust += (0.5 - *domain_trust) * decay_factor;
        *domain_trust = domain_trust.clamp(0.0, 1.0);
    }

    debug!(
        agent_id = %trust.agent_id,
        target_agent = %trust.target_agent,
        old_trust,
        new_trust = trust.overall_trust,
        days_since_evidence,
        "trust decay applied"
    );
}

//! CrossAgentValidator — detect and resolve contradictions between agents.
//!
//! Resolution strategy:
//! 1. Trust diff > 0.3 → `TrustWins` (higher-trust agent wins)
//! 2. Trust diff ≤ 0.3 AND different scope tags → `ContextDependent`
//! 3. Trust diff ≤ 0.3 AND newer + validated → `TemporalSupersession`
//! 4. Otherwise → `NeedsHumanReview`

use tracing::{info, warn, instrument};

use cortex_core::config::MultiAgentConfig;
use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::models::agent::AgentId;
use cortex_core::models::cross_agent::{
    ContradictionResolution, CrossAgentContradiction,
};

/// Detects and resolves contradictions between agents' memories.
pub struct CrossAgentValidator {
    config: MultiAgentConfig,
}

impl CrossAgentValidator {
    /// Create a new CrossAgentValidator.
    pub fn new(config: &MultiAgentConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Detect contradictions between memories from different agents.
    ///
    /// `memories` is a flat list of memories from multiple agents.
    /// `similarity_fn` returns a similarity score (0.0–1.0) between two memories.
    /// `trust_fn` returns the trust score for an agent.
    ///
    /// Two memories contradict when they are semantically similar (similarity > 0.7)
    /// but have opposing content (detected by the caller's similarity function
    /// returning a negative signal or by tag analysis).
    #[instrument(skip(self, memories, contradiction_fn, trust_fn))]
    pub fn detect_contradictions<C, T>(
        &self,
        memories: &[BaseMemory],
        contradiction_fn: &C,
        trust_fn: &T,
    ) -> CortexResult<Vec<CrossAgentContradiction>>
    where
        C: Fn(&BaseMemory, &BaseMemory) -> Option<String>,
        T: Fn(&AgentId) -> f64,
    {
        let mut contradictions = Vec::new();

        for i in 0..memories.len() {
            for j in (i + 1)..memories.len() {
                let mem_a = &memories[i];
                let mem_b = &memories[j];

                // Skip same-agent comparisons.
                if mem_a.source_agent == mem_b.source_agent {
                    continue;
                }

                // Check if these memories contradict.
                if let Some(contradiction_type) = contradiction_fn(mem_a, mem_b) {
                    let trust_a = trust_fn(&mem_a.source_agent);
                    let trust_b = trust_fn(&mem_b.source_agent);

                    let resolution = self.resolve_by_trust(
                        trust_a,
                        trust_b,
                        &mem_a.source_agent,
                        &mem_b.source_agent,
                        mem_a,
                        mem_b,
                    );

                    warn!(
                        memory_a = %mem_a.id,
                        agent_a = %mem_a.source_agent,
                        memory_b = %mem_b.id,
                        agent_b = %mem_b.source_agent,
                        contradiction_type = %contradiction_type,
                        resolution = ?resolution,
                        "cross-agent contradiction detected"
                    );

                    contradictions.push(CrossAgentContradiction {
                        memory_a: mem_a.id.clone(),
                        agent_a: mem_a.source_agent.clone(),
                        trust_a,
                        memory_b: mem_b.id.clone(),
                        agent_b: mem_b.source_agent.clone(),
                        trust_b,
                        contradiction_type,
                        resolution,
                    });
                }
            }
        }

        info!(
            contradictions = contradictions.len(),
            "cross-agent contradiction detection complete"
        );

        Ok(contradictions)
    }

    /// Resolve a contradiction using the deterministic resolution strategy.
    ///
    /// 1. Trust diff > 0.3 → TrustWins (higher-trust agent)
    /// 2. Different scope tags → ContextDependent
    /// 3. Newer + validated → TemporalSupersession
    /// 4. Otherwise → NeedsHumanReview
    pub fn resolve_contradiction(
        &self,
        contradiction: &CrossAgentContradiction,
    ) -> ContradictionResolution {
        let trust_diff = (contradiction.trust_a - contradiction.trust_b).abs();

        if trust_diff > self.config.contradiction_trust_auto_resolve_threshold {
            ContradictionResolution::TrustWins
        } else {
            ContradictionResolution::NeedsHumanReview
        }
    }

    /// Internal resolution with full memory context for scope tag and temporal checks.
    fn resolve_by_trust(
        &self,
        trust_a: f64,
        trust_b: f64,
        _agent_a: &AgentId,
        _agent_b: &AgentId,
        mem_a: &BaseMemory,
        mem_b: &BaseMemory,
    ) -> ContradictionResolution {
        let trust_diff = (trust_a - trust_b).abs();

        // Rule 1: Large trust difference → higher-trust agent wins.
        if trust_diff > self.config.contradiction_trust_auto_resolve_threshold {
            return ContradictionResolution::TrustWins;
        }

        // Rule 2: Different scope tags → context-dependent.
        if has_different_scope_tags(mem_a, mem_b) {
            return ContradictionResolution::ContextDependent;
        }

        // Rule 3: Newer + validated → temporal supersession.
        if is_temporal_supersession(mem_a, mem_b) {
            return ContradictionResolution::TemporalSupersession;
        }

        // Rule 4: Fallback → needs human review.
        ContradictionResolution::NeedsHumanReview
    }
}

/// Check if two memories have different scope tags (indicating different contexts).
fn has_different_scope_tags(mem_a: &BaseMemory, mem_b: &BaseMemory) -> bool {
    if mem_a.tags.is_empty() || mem_b.tags.is_empty() {
        return false;
    }
    // If the tag sets are completely disjoint, they're in different contexts.
    let tags_a: std::collections::HashSet<&String> = mem_a.tags.iter().collect();
    let tags_b: std::collections::HashSet<&String> = mem_b.tags.iter().collect();
    tags_a.is_disjoint(&tags_b)
}

/// Check if one memory temporally supersedes the other.
/// A newer memory supersedes an older one if it's significantly newer
/// and has higher confidence (indicating validation).
fn is_temporal_supersession(mem_a: &BaseMemory, mem_b: &BaseMemory) -> bool {
    let time_diff = (mem_a.valid_time - mem_b.valid_time).num_hours().abs();
    if time_diff < 1 {
        return false;
    }

    let (newer, older) = if mem_a.valid_time > mem_b.valid_time {
        (mem_a, mem_b)
    } else {
        (mem_b, mem_a)
    };

    // Newer memory must have higher confidence (indicating validation).
    newer.confidence.value() > older.confidence.value()
}

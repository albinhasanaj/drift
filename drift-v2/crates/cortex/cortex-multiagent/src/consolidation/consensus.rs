//! ConsensusDetector — find independently corroborated knowledge across agents.
//!
//! When 2+ agents independently learn the same thing (embedding similarity > 0.9),
//! that's strong evidence. The confidence boost (+0.2) rewards consensus.
//!
//! # Examples
//!
//! ```no_run
//! use cortex_multiagent::consolidation::ConsensusDetector;
//! use cortex_core::config::MultiAgentConfig;
//!
//! let detector = ConsensusDetector::new(&MultiAgentConfig::default());
//! // detector.detect_consensus(&memories_by_namespace, &similarity_fn, 0.9);
//! ```

use std::collections::HashMap;

use tracing::{debug, info, instrument};

use cortex_core::config::MultiAgentConfig;
use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::models::agent::AgentId;

/// A candidate for consensus — multiple agents independently agree.
#[derive(Debug, Clone)]
pub struct ConsensusCandidate {
    /// (agent_id, memory_id) pairs that form the consensus.
    pub memories: Vec<(AgentId, String)>,
    /// Average embedding similarity across the group.
    pub similarity: f64,
    /// Number of distinct agents in the consensus.
    pub agent_count: usize,
    /// Confidence boost to apply (default: +0.2).
    pub confidence_boost: f64,
}

/// Detects consensus across agent namespaces using embedding similarity.
pub struct ConsensusDetector {
    config: MultiAgentConfig,
}

impl ConsensusDetector {
    /// Create a new ConsensusDetector with the given config.
    pub fn new(config: &MultiAgentConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Detect consensus across memories from multiple namespaces.
    ///
    /// `memories_by_agent` maps agent_id → list of memories from that agent.
    /// `similarity_fn` computes embedding similarity between two memories (0.0–1.0).
    ///
    /// Returns consensus candidates where agent_count >= config.consensus_min_agents
    /// and similarity >= config.consensus_similarity_threshold.
    #[instrument(skip(self, memories_by_agent, similarity_fn))]
    pub fn detect_consensus<F>(
        &self,
        memories_by_agent: &HashMap<AgentId, Vec<BaseMemory>>,
        similarity_fn: &F,
        threshold: f64,
    ) -> CortexResult<Vec<ConsensusCandidate>>
    where
        F: Fn(&BaseMemory, &BaseMemory) -> f64,
    {
        let threshold = if threshold > 0.0 {
            threshold
        } else {
            self.config.consensus_similarity_threshold
        };
        let min_agents = self.config.consensus_min_agents;
        let confidence_boost = self.config.consensus_confidence_boost;

        let agents: Vec<&AgentId> = memories_by_agent.keys().collect();
        if agents.len() < min_agents {
            debug!(
                agent_count = agents.len(),
                min_agents,
                "not enough agents for consensus detection"
            );
            return Ok(Vec::new());
        }

        let mut candidates: Vec<ConsensusCandidate> = Vec::new();
        // Track which memories have already been assigned to a consensus group.
        let mut used: HashMap<String, bool> = HashMap::new();

        // For each memory from each agent, find similar memories from other agents.
        for (i, agent_a) in agents.iter().enumerate() {
            let memories_a = &memories_by_agent[*agent_a];
            for mem_a in memories_a {
                if used.contains_key(&mem_a.id) {
                    continue;
                }

                let mut group: Vec<(AgentId, String)> =
                    vec![((*agent_a).clone(), mem_a.id.clone())];
                let mut total_similarity = 0.0;
                let mut comparisons = 0;

                for agent_b in agents.iter().skip(i + 1) {
                    let memories_b = &memories_by_agent[*agent_b];
                    for mem_b in memories_b {
                        if used.contains_key(&mem_b.id) {
                            continue;
                        }

                        let sim = similarity_fn(mem_a, mem_b);
                        if sim >= threshold {
                            group.push(((*agent_b).clone(), mem_b.id.clone()));
                            total_similarity += sim;
                            comparisons += 1;
                            break; // One match per agent is enough.
                        }
                    }
                }

                let agent_count = group
                    .iter()
                    .map(|(a, _)| a.clone())
                    .collect::<std::collections::HashSet<_>>()
                    .len();

                if agent_count >= min_agents {
                    let avg_similarity = if comparisons > 0 {
                        total_similarity / comparisons as f64
                    } else {
                        1.0
                    };

                    // Mark all memories in this group as used.
                    for (_, mid) in &group {
                        used.insert(mid.clone(), true);
                    }

                    info!(
                        agent_count,
                        similarity = format!("{:.3}", avg_similarity),
                        memory_count = group.len(),
                        "consensus detected"
                    );

                    candidates.push(ConsensusCandidate {
                        memories: group,
                        similarity: avg_similarity,
                        agent_count,
                        confidence_boost,
                    });
                }
            }
        }

        info!(
            candidates = candidates.len(),
            "consensus detection complete"
        );

        Ok(candidates)
    }
}

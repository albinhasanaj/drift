//! Cross-agent causal traversal — follow causal chains across agent boundaries.
//!
//! Provides `trace_cross_agent()` to traverse the causal graph across agent
//! boundaries, and `cross_agent_narrative()` to generate a human-readable
//! narrative from the trace.

use cortex_core::errors::CortexResult;
use cortex_core::models::agent::AgentId;

use super::stable_graph::IndexedGraph;

/// A single hop in a cross-agent causal trace.
#[derive(Debug, Clone)]
pub struct CrossAgentHop {
    /// The memory at this hop.
    pub memory_id: String,
    /// The agent that owns this memory.
    pub source_agent: Option<AgentId>,
    /// The relation type from this hop to the next.
    pub relation: String,
    /// Strength of the causal link.
    pub strength: f64,
    /// Depth in the traversal (0 = root).
    pub depth: usize,
}

/// Result of a cross-agent causal trace.
#[derive(Debug, Clone)]
pub struct CrossAgentTrace {
    /// The root memory that started the trace.
    pub root_memory_id: String,
    /// Ordered list of hops in the trace.
    pub hops: Vec<CrossAgentHop>,
    /// Number of distinct agents encountered.
    pub agent_count: usize,
    /// Maximum depth reached.
    pub max_depth_reached: usize,
}

/// Trace causal relationships across agent boundaries.
///
/// Starting from `memory_id`, follows outgoing causal edges up to `max_depth`,
/// recording each hop including the source agent. This enables understanding
/// how knowledge flows between agents through causal chains.
pub fn trace_cross_agent(
    graph: &IndexedGraph,
    memory_id: &str,
    max_depth: usize,
) -> CortexResult<CrossAgentTrace> {
    let mut hops = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut agents = std::collections::HashSet::new();
    let mut max_depth_reached = 0;

    trace_recursive(
        graph,
        memory_id,
        0,
        max_depth,
        &mut visited,
        &mut hops,
        &mut agents,
        &mut max_depth_reached,
    );

    Ok(CrossAgentTrace {
        root_memory_id: memory_id.to_string(),
        hops,
        agent_count: agents.len(),
        max_depth_reached,
    })
}

/// Recursive DFS traversal of the causal graph.
#[allow(clippy::too_many_arguments)]
fn trace_recursive(
    graph: &IndexedGraph,
    memory_id: &str,
    depth: usize,
    max_depth: usize,
    visited: &mut std::collections::HashSet<String>,
    hops: &mut Vec<CrossAgentHop>,
    agents: &mut std::collections::HashSet<String>,
    max_depth_reached: &mut usize,
) {
    if depth > max_depth || visited.contains(memory_id) {
        return;
    }
    visited.insert(memory_id.to_string());
    *max_depth_reached = (*max_depth_reached).max(depth);

    let node_idx = match graph.get_node(memory_id) {
        Some(idx) => idx,
        None => return,
    };

    // Get the node's source_agent from metadata if available.
    let source_agent = graph
        .graph
        .node_weight(node_idx)
        .and_then(|n| {
            // The node's memory_type field could encode agent info,
            // but for now we use None for single-agent edges.
            if n.memory_type.starts_with("agent:") {
                Some(AgentId::from(n.memory_type.trim_start_matches("agent:")))
            } else {
                None
            }
        });

    if let Some(ref agent) = source_agent {
        agents.insert(agent.0.clone());
    }

    // Traverse outgoing edges.
    use petgraph::Direction;
    let neighbors: Vec<_> = graph
        .graph
        .neighbors_directed(node_idx, Direction::Outgoing)
        .collect();

    for neighbor_idx in neighbors {
        let edge_idx = match graph.graph.find_edge(node_idx, neighbor_idx) {
            Some(idx) => idx,
            None => continue,
        };

        let weight = match graph.graph.edge_weight(edge_idx) {
            Some(w) => w,
            None => continue,
        };

        let neighbor_node = match graph.graph.node_weight(neighbor_idx) {
            Some(n) => n,
            None => continue,
        };

        hops.push(CrossAgentHop {
            memory_id: neighbor_node.memory_id.clone(),
            source_agent: source_agent.clone(),
            relation: weight.relation.as_str().to_string(),
            strength: weight.strength,
            depth: depth + 1,
        });

        trace_recursive(
            graph,
            &neighbor_node.memory_id,
            depth + 1,
            max_depth,
            visited,
            hops,
            agents,
            max_depth_reached,
        );
    }
}

/// Generate a human-readable narrative from a cross-agent trace.
pub fn cross_agent_narrative(trace: &CrossAgentTrace) -> String {
    if trace.hops.is_empty() {
        return format!(
            "Memory '{}' has no cross-agent causal relationships.",
            trace.root_memory_id
        );
    }

    let mut narrative = format!(
        "Cross-agent causal trace for '{}' ({} agents, {} hops, depth {}):\n",
        trace.root_memory_id,
        trace.agent_count,
        trace.hops.len(),
        trace.max_depth_reached,
    );

    for hop in &trace.hops {
        let agent_str = hop
            .source_agent
            .as_ref()
            .map(|a| format!(" [agent: {}]", a))
            .unwrap_or_default();

        narrative.push_str(&format!(
            "  {} → '{}'{} (relation: {}, strength: {:.2})\n",
            "  ".repeat(hop.depth.saturating_sub(1)),
            hop.memory_id,
            agent_str,
            hop.relation,
            hop.strength,
        ));
    }

    narrative
}

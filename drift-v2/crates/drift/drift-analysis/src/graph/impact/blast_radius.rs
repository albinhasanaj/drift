//! Blast radius computation via transitive caller analysis.

use drift_core::types::collections::FxHashSet;
use petgraph::graph::NodeIndex;

use crate::call_graph::types::CallGraph;

use super::types::{BlastRadius, RiskScore};

/// Compute the blast radius for a function.
///
/// Uses inverse BFS to find all transitive callers — every function
/// that would be affected by a change to the target function.
pub fn compute_blast_radius(
    graph: &CallGraph,
    function_id: NodeIndex,
    max_callers_for_normalization: u32,
) -> BlastRadius {
    let (callers, max_depth) = transitive_callers(graph, function_id);
    let caller_count = callers.len() as u32;

    // Normalize blast radius to 0.0-1.0
    let blast_factor = (caller_count as f32 / max_callers_for_normalization as f32).min(1.0);

    // CG-IMPACT-01: Compute real sensitivity from node properties
    let node = &graph.graph[function_id];
    let sensitivity = compute_sensitivity(node);

    // CG-IMPACT-02: Estimate complexity from line span
    let complexity = compute_complexity_estimate(node);

    // Test coverage: approximate — functions in test files are covered
    let test_coverage = if node.file.to_lowercase().contains("test") { 0.8 } else { 0.2 };

    let risk_score = RiskScore::compute(
        blast_factor,
        sensitivity,
        test_coverage,
        complexity,
        0.0, // Change frequency: requires git history (out of scope)
    );

    BlastRadius {
        function_id,
        transitive_callers: callers,
        caller_count,
        risk_score,
        max_depth,
    }
}

/// Compute blast radius for all functions in the graph.
pub fn compute_all_blast_radii(graph: &CallGraph) -> Vec<BlastRadius> {
    let max_callers = graph.function_count().max(1) as u32;

    graph
        .graph
        .node_indices()
        .map(|idx| compute_blast_radius(graph, idx, max_callers))
        .collect()
}

/// CG-IMPACT-01: Compute sensitivity score from node properties.
fn compute_sensitivity(node: &crate::call_graph::types::FunctionNode) -> f32 {
    let mut score = 0.0f32;

    // Entry points that handle user input are more sensitive
    if node.is_entry_point {
        score += 0.3;
    }

    // Exported functions have higher API surface sensitivity
    if node.is_exported {
        score += 0.2;
    }

    // Functions with security-related names
    let name_lower = node.name.to_lowercase();
    if name_lower.contains("auth") || name_lower.contains("login")
        || name_lower.contains("password") || name_lower.contains("token")
        || name_lower.contains("secret") || name_lower.contains("crypt")
        || name_lower.contains("permission") || name_lower.contains("session")
    {
        score += 0.4;
    }

    // Database/IO functions
    if name_lower.contains("query") || name_lower.contains("execute")
        || name_lower.contains("write") || name_lower.contains("delete")
    {
        score += 0.2;
    }

    score.min(1.0)
}

/// CG-IMPACT-02: Estimate complexity from function line span.
fn compute_complexity_estimate(node: &crate::call_graph::types::FunctionNode) -> f32 {
    let line_span = node.end_line.saturating_sub(node.line) as f32;
    // Normalize: 0-10 lines → low, 10-50 → medium, 50+ → high
    if line_span <= 10.0 {
        line_span / 50.0
    } else if line_span <= 50.0 {
        0.2 + (line_span - 10.0) / 80.0
    } else {
        (0.7 + (line_span - 50.0) / 200.0).min(1.0)
    }
}

/// Find all transitive callers via inverse BFS.
/// Returns (callers, max_depth).
fn transitive_callers(graph: &CallGraph, start: NodeIndex) -> (Vec<NodeIndex>, u32) {
    let mut visited = FxHashSet::default();
    let mut queue = std::collections::VecDeque::new();
    let mut result = Vec::new();
    let mut max_depth = 0u32;

    visited.insert(start);
    queue.push_back((start, 0u32));

    while let Some((node, depth)) = queue.pop_front() {
        if node != start {
            result.push(node);
            if depth > max_depth {
                max_depth = depth;
            }
        }

        for caller in graph.graph.neighbors_directed(node, petgraph::Direction::Incoming) {
            if visited.insert(caller) {
                queue.push_back((caller, depth + 1));
            }
        }
    }

    (result, max_depth)
}

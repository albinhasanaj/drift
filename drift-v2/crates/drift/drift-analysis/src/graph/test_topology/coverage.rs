//! Coverage mapping via call graph BFS.
//!
//! Maps test functions to the source functions they cover by following
//! outgoing call edges from test functions.

use drift_core::types::collections::FxHashSet;
use petgraph::graph::NodeIndex;

use crate::call_graph::types::CallGraph;

use super::types::CoverageMapping;

/// Compute coverage mapping from the call graph.
///
/// Identifies test functions (by naming convention) and traces their
/// outgoing calls to determine which source functions they cover.
pub fn compute_coverage(graph: &CallGraph) -> CoverageMapping {
    let mut mapping = CoverageMapping::default();

    // Classify nodes as test or source
    let (test_nodes, source_nodes) = classify_nodes(graph);

    mapping.total_test_functions = test_nodes.len();
    mapping.total_source_functions = source_nodes.len();

    let source_set: FxHashSet<NodeIndex> = source_nodes.into_iter().collect();

    // For each test function, BFS forward to find covered source functions
    for &test_idx in &test_nodes {
        let covered = trace_test_coverage(graph, test_idx, &source_set);

        for &source_idx in &covered {
            mapping
                .source_to_test
                .entry(source_idx)
                .or_default()
                .insert(test_idx);
        }

        mapping.test_to_source.insert(test_idx, covered);
    }

    mapping
}

/// Classify nodes into test functions and source functions.
fn classify_nodes(graph: &CallGraph) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
    let mut test_nodes = Vec::new();
    let mut source_nodes = Vec::new();

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        if is_test_function(&node.name, &node.file) {
            test_nodes.push(idx);
        } else {
            source_nodes.push(idx);
        }
    }

    (test_nodes, source_nodes)
}

/// Check if a function is a test function based on naming conventions.
fn is_test_function(name: &str, file: &str) -> bool {
    let name_lower = name.to_lowercase();
    let file_lower = file.to_lowercase();

    // Name-based detection
    let name_match = name_lower.starts_with("test_")
        || name_lower.starts_with("test")
        || name_lower.starts_with("it_")
        || name_lower.starts_with("spec_")
        || name_lower.starts_with("should_")
        || name_lower.ends_with("_test")
        || name_lower.ends_with("_spec")
        || name_lower == "it"
        || name_lower == "describe"
        || name_lower == "expect";

    // File-based detection
    let file_match = file_lower.contains("test")
        || file_lower.contains("spec")
        || file_lower.contains("__tests__")
        || file_lower.ends_with("_test.rs")
        || file_lower.ends_with("_test.go")
        || file_lower.ends_with(".test.ts")
        || file_lower.ends_with(".test.js")
        || file_lower.ends_with(".spec.ts")
        || file_lower.ends_with(".spec.js");

    name_match || file_match
}

/// Trace coverage from a test function via BFS.
fn trace_test_coverage(
    graph: &CallGraph,
    test_node: NodeIndex,
    source_set: &FxHashSet<NodeIndex>,
) -> FxHashSet<NodeIndex> {
    let mut covered = FxHashSet::default();
    let mut visited = FxHashSet::default();
    let mut queue = std::collections::VecDeque::new();

    visited.insert(test_node);
    queue.push_back(test_node);

    while let Some(node) = queue.pop_front() {
        for neighbor in graph.graph.neighbors_directed(node, petgraph::Direction::Outgoing) {
            if visited.insert(neighbor) {
                if source_set.contains(&neighbor) {
                    covered.insert(neighbor);
                }
                queue.push_back(neighbor);
            }
        }
    }

    covered
}

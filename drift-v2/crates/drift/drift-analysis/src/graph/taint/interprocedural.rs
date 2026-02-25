//! Interprocedural taint analysis — cross-function taint via function summaries.
//!
//! Phase 2 of taint analysis. Propagates taint across function boundaries
//! using the call graph and function summaries.
//! Performance target: <100ms per function.

use drift_core::errors::TaintError;
use drift_core::types::collections::{FxHashMap, FxHashSet};
use petgraph::graph::NodeIndex;

use crate::call_graph::types::CallGraph;
use crate::parsers::types::ParseResult;

use super::registry::TaintRegistry;
use super::types::*;

/// Maximum depth for interprocedural taint propagation.
const MAX_TAINT_DEPTH: usize = 50;

/// Summary of a function's taint behavior.
#[derive(Debug, Clone, Default)]
pub struct FunctionSummary {
    /// Parameters that propagate taint to the return value.
    pub tainted_params: FxHashSet<usize>,
    /// Whether the return value is tainted.
    pub returns_taint: bool,
    /// Sinks within this function.
    pub internal_sinks: Vec<SinkType>,
    /// Sources within this function.
    pub internal_sources: Vec<SourceType>,
}

/// Analyze interprocedural taint flows across the call graph.
pub fn analyze_interprocedural(
    call_graph: &CallGraph,
    parse_results: &[ParseResult],
    registry: &TaintRegistry,
    max_depth: Option<usize>,
) -> Result<Vec<TaintFlow>, TaintError> {
    let max_d = max_depth.unwrap_or(MAX_TAINT_DEPTH);

    // Phase 1: Build function summaries
    let summaries = build_function_summaries(call_graph, parse_results, registry);

    // Phase 2: Propagate taint through call graph
    let flows = propagate_taint(call_graph, parse_results, registry, &summaries, max_d)?;

    Ok(flows)
}

/// Build function summaries for all functions in the call graph.
fn build_function_summaries(
    call_graph: &CallGraph,
    parse_results: &[ParseResult],
    registry: &TaintRegistry,
) -> FxHashMap<NodeIndex, FunctionSummary> {
    let mut summaries = FxHashMap::default();

    for idx in call_graph.graph.node_indices() {
        let node = &call_graph.graph[idx];
        let summary = build_single_summary(node, parse_results, registry);
        summaries.insert(idx, summary);
    }

    summaries
}

/// Build a summary for a single function.
fn build_single_summary(
    node: &crate::call_graph::types::FunctionNode,
    parse_results: &[ParseResult],
    registry: &TaintRegistry,
) -> FunctionSummary {
    let mut summary = FunctionSummary::default();

    // Find the parse result for this function's file
    let pr = parse_results.iter().find(|pr| pr.file == node.file);
    let pr = match pr {
        Some(pr) => pr,
        None => return summary,
    };

    // Find the function info
    let func = pr.functions.iter().find(|f| f.name == node.name);
    let func = match func {
        Some(f) => f,
        None => return summary,
    };

    // Check parameters for source patterns
    for (i, param) in func.parameters.iter().enumerate() {
        if registry.match_source(&param.name).is_some() {
            summary.tainted_params.insert(i);
            summary.returns_taint = true;
        }
    }

    // Check call sites within function for sinks/sources
    for call in &pr.call_sites {
        if call.line >= func.line && call.line <= func.end_line {
            let full_name = if let Some(ref receiver) = call.receiver {
                format!("{}.{}", receiver, call.callee_name)
            } else {
                call.callee_name.clone()
            };

            if let Some(sink_pattern) = registry.match_sink(&full_name) {
                summary.internal_sinks.push(sink_pattern.sink_type);
            }
            if let Some(source_pattern) = registry.match_source(&full_name) {
                summary.internal_sources.push(source_pattern.source_type);
                summary.returns_taint = true;
            }
        }
    }

    summary
}

/// Propagate taint through the call graph using function summaries.
fn propagate_taint(
    call_graph: &CallGraph,
    parse_results: &[ParseResult],
    registry: &TaintRegistry,
    summaries: &FxHashMap<NodeIndex, FunctionSummary>,
    max_depth: usize,
) -> Result<Vec<TaintFlow>, TaintError> {
    let mut flows = Vec::new();

    // Find all source nodes (functions that introduce taint)
    let source_nodes: Vec<NodeIndex> = summaries
        .iter()
        .filter(|(_, s)| !s.internal_sources.is_empty() || !s.tainted_params.is_empty())
        .map(|(idx, _)| *idx)
        .collect();

    // For each source, trace taint forward through the call graph
    for source_idx in &source_nodes {
        let source_summary = &summaries[source_idx];
        let source_node = &call_graph.graph[*source_idx];

        let source_type = source_summary
            .internal_sources
            .first()
            .copied()
            .unwrap_or(SourceType::UserInput);

        let source = TaintSource {
            file: source_node.file.clone(),
            line: source_node.line,
            column: 0,
            expression: source_node.name.clone(),
            source_type,
            label: TaintLabel::new(source_idx.index() as u64, source_type),
        };

        // BFS forward from source, looking for sinks
        let mut visited = FxHashSet::default();
        let mut queue = std::collections::VecDeque::new();
        visited.insert(*source_idx);
        queue.push_back((*source_idx, vec![source_node.clone()], 0usize));

        while let Some((current, path_nodes, depth)) = queue.pop_front() {
            if depth > max_depth {
                return Err(TaintError::PathTooLong {
                    length: depth,
                    max: max_depth,
                });
            }

            // Check if current function has sinks
            if let Some(current_summary) = summaries.get(&current) {
                let current_node = &call_graph.graph[current];

                for sink_type in &current_summary.internal_sinks {
                    // Check if any sanitizer along the path neutralizes this sink
                    let is_sanitized = check_path_sanitized(
                        &path_nodes, parse_results, registry, sink_type,
                    );

                    let sink = TaintSink {
                        file: current_node.file.clone(),
                        line: current_node.line,
                        column: 0,
                        expression: current_node.name.clone(),
                        sink_type: *sink_type,
                        required_sanitizers: Vec::new(),
                    };

                    let taint_path: Vec<TaintHop> = path_nodes
                        .iter()
                        .map(|n| TaintHop {
                            file: n.file.clone(),
                            line: n.line,
                            column: 0,
                            function: n.name.clone(),
                            description: format!("Taint propagates through {}", n.name),
                        })
                        .collect();

                    flows.push(TaintFlow {
                        source: source.clone(),
                        sink,
                        path: taint_path,
                        is_sanitized,
                        sanitizers_applied: Vec::new(),
                        cwe_id: sink_type.cwe_id(),
                        confidence: if is_sanitized { 0.3 } else { 0.75 },
                    });
                }
            }

            // Continue BFS to callees
            for neighbor in call_graph.graph.neighbors_directed(current, petgraph::Direction::Outgoing) {
                if visited.insert(neighbor) {
                    let neighbor_node = call_graph.graph[neighbor].clone();
                    let mut new_path = path_nodes.clone();
                    new_path.push(neighbor_node);
                    queue.push_back((neighbor, new_path, depth + 1));
                }
            }
        }
    }

    Ok(flows)
}

/// Check if the path from source to sink has appropriate sanitization.
fn check_path_sanitized(
    path_nodes: &[crate::call_graph::types::FunctionNode],
    parse_results: &[ParseResult],
    registry: &TaintRegistry,
    sink_type: &SinkType,
) -> bool {
    for node in path_nodes {
        if let Some(pr) = parse_results.iter().find(|pr| pr.file == node.file) {
            for call in &pr.call_sites {
                if call.line >= node.line && call.line <= node.end_line {
                    let full_name = if let Some(ref receiver) = call.receiver {
                        format!("{}.{}", receiver, call.callee_name)
                    } else {
                        call.callee_name.clone()
                    };

                    if let Some(sanitizer) = registry.match_sanitizer(&full_name) {
                        if sanitizer.protects_against.contains(sink_type) {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

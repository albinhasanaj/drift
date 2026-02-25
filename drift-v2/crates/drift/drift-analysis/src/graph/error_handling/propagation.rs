//! Phase 3: Propagation chain tracing via call graph.

use drift_core::types::collections::FxHashSet;
use petgraph::graph::NodeIndex;

use crate::call_graph::types::CallGraph;

use super::types::{ErrorHandler, PropagationChain, PropagationNode};
use crate::parsers::types::ParseResult;

/// Trace error propagation chains through the call graph.
///
/// For each function that throws/returns errors, trace the call chain
/// upward to find where (if anywhere) the error is handled.
pub fn trace_propagation(
    call_graph: &CallGraph,
    parse_results: &[ParseResult],
    handlers: &[ErrorHandler],
) -> Vec<PropagationChain> {
    let mut chains = Vec::new();

    // Build a set of functions that have error handlers
    let handler_functions: FxHashSet<String> = handlers
        .iter()
        .map(|h| format!("{}::{}", h.file, h.function))
        .collect();

    // Find functions that throw/return errors
    let error_sources = find_error_sources(parse_results);

    for (file, func_name, line, error_type) in &error_sources {
        let key = format!("{}::{}", file, func_name);
        if let Some(node_idx) = call_graph.get_node(&key) {
            let chain = trace_chain_upward(
                call_graph,
                node_idx,
                &handler_functions,
                file,
                func_name,
                *line,
                error_type.clone(),
            );
            chains.push(chain);
        }
    }

    chains
}

/// Find functions that throw or return errors.
fn find_error_sources(parse_results: &[ParseResult]) -> Vec<(String, String, u32, Option<String>)> {
    let mut sources = Vec::new();

    for pr in parse_results {
        for eh in &pr.error_handling {
            use crate::parsers::types::ErrorHandlingKind;
            match eh.kind {
                ErrorHandlingKind::Throw | ErrorHandlingKind::QuestionMark | ErrorHandlingKind::Unwrap => {
                    let func_name = eh
                        .function_scope
                        .clone()
                        .unwrap_or_else(|| "<module>".to_string());
                    sources.push((
                        pr.file.clone(),
                        func_name,
                        eh.line,
                        eh.caught_type.clone(),
                    ));
                }
                _ => {}
            }
        }
    }

    sources
}

/// Trace a chain upward from an error source through callers.
fn trace_chain_upward(
    call_graph: &CallGraph,
    start: NodeIndex,
    handler_functions: &FxHashSet<String>,
    file: &str,
    func_name: &str,
    line: u32,
    error_type: Option<String>,
) -> PropagationChain {
    let mut functions = Vec::new();
    let mut visited = FxHashSet::default();
    let mut is_handled = false;

    // Start with the error source
    functions.push(PropagationNode {
        file: file.to_string(),
        function: func_name.to_string(),
        line,
        handles_error: false,
        propagates_error: true,
    });

    // BFS upward through callers
    let mut queue = std::collections::VecDeque::new();
    visited.insert(start);
    queue.push_back(start);

    while let Some(current) = queue.pop_front() {
        for caller in call_graph.graph.neighbors_directed(current, petgraph::Direction::Incoming) {
            if visited.insert(caller) {
                let caller_node = &call_graph.graph[caller];
                let caller_key = format!("{}::{}", caller_node.file, caller_node.name);
                let handles = handler_functions.contains(&caller_key);

                functions.push(PropagationNode {
                    file: caller_node.file.clone(),
                    function: caller_node.name.clone(),
                    line: caller_node.line,
                    handles_error: handles,
                    propagates_error: !handles,
                });

                if handles {
                    is_handled = true;
                    // Stop tracing this branch — error is handled
                } else {
                    queue.push_back(caller);
                }
            }
        }
    }

    PropagationChain {
        functions,
        error_type,
        is_handled,
    }
}

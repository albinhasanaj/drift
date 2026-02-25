//! Cross-service reachability for microservice boundaries.
//!
//! Detects when a function in service A calls an API endpoint in service B,
//! and extends reachability across service boundaries.

use drift_core::types::collections::{FxHashMap, FxHashSet};
use petgraph::graph::NodeIndex;

use crate::call_graph::types::CallGraph;

/// A service boundary detected in the codebase.
#[derive(Debug, Clone)]
pub struct ServiceBoundary {
    /// Service name (derived from directory or config).
    pub service_name: String,
    /// Nodes belonging to this service.
    pub nodes: FxHashSet<NodeIndex>,
    /// API endpoints exposed by this service.
    pub endpoints: Vec<ServiceEndpoint>,
}

/// An API endpoint exposed by a service.
#[derive(Debug, Clone)]
pub struct ServiceEndpoint {
    /// The function node implementing this endpoint.
    pub node: NodeIndex,
    /// HTTP method (GET, POST, etc.) if applicable.
    pub method: Option<String>,
    /// Route path (e.g., "/api/users").
    pub path: Option<String>,
}

/// Result of cross-service reachability analysis.
#[derive(Debug, Clone)]
pub struct CrossServiceResult {
    /// Source node.
    pub source: NodeIndex,
    /// Services reachable from source, with the nodes in each.
    pub reachable_services: FxHashMap<String, FxHashSet<NodeIndex>>,
    /// Cross-service edges (caller_service, callee_service, caller_node, callee_node).
    pub cross_edges: Vec<CrossServiceEdge>,
}

/// An edge that crosses a service boundary.
#[derive(Debug, Clone)]
pub struct CrossServiceEdge {
    pub caller_service: String,
    pub callee_service: String,
    pub caller_node: NodeIndex,
    pub callee_node: NodeIndex,
}

/// Detect service boundaries from the call graph.
///
/// Heuristic: group nodes by top-level directory (e.g., `services/auth/`, `services/billing/`).
pub fn detect_service_boundaries(graph: &CallGraph) -> Vec<ServiceBoundary> {
    let mut service_map: FxHashMap<String, FxHashSet<NodeIndex>> = FxHashMap::default();

    for idx in graph.graph.node_indices() {
        if let Some(node) = graph.graph.node_weight(idx) {
            let service = extract_service_name(&node.file);
            service_map.entry(service).or_default().insert(idx);
        }
    }

    service_map
        .into_iter()
        .map(|(service_name, nodes)| {
            let endpoints = detect_endpoints(graph, &nodes);
            ServiceBoundary {
                service_name,
                nodes,
                endpoints,
            }
        })
        .collect()
}

/// Compute cross-service reachability from a source node.
pub fn cross_service_reachability(
    graph: &CallGraph,
    source: NodeIndex,
    _boundaries: &[ServiceBoundary],
) -> CrossServiceResult {
    let _source_service = graph
        .graph
        .node_weight(source)
        .map(|n| extract_service_name(&n.file))
        .unwrap_or_default();

    let mut reachable_services: FxHashMap<String, FxHashSet<NodeIndex>> = FxHashMap::default();
    let mut cross_edges = Vec::new();

    // BFS from source, tracking service crossings
    let mut visited = FxHashSet::default();
    let mut queue = std::collections::VecDeque::new();
    visited.insert(source);
    queue.push_back(source);

    while let Some(node) = queue.pop_front() {
        let node_service = graph
            .graph
            .node_weight(node)
            .map(|n| extract_service_name(&n.file))
            .unwrap_or_default();

        reachable_services
            .entry(node_service.clone())
            .or_default()
            .insert(node);

        for neighbor in graph.graph.neighbors_directed(node, petgraph::Direction::Outgoing) {
            if visited.insert(neighbor) {
                let neighbor_service = graph
                    .graph
                    .node_weight(neighbor)
                    .map(|n| extract_service_name(&n.file))
                    .unwrap_or_default();

                if node_service != neighbor_service {
                    cross_edges.push(CrossServiceEdge {
                        caller_service: node_service.clone(),
                        callee_service: neighbor_service,
                        caller_node: node,
                        callee_node: neighbor,
                    });
                }

                queue.push_back(neighbor);
            }
        }
    }

    CrossServiceResult {
        source,
        reachable_services,
        cross_edges,
    }
}

/// Extract service name from file path.
/// Heuristic: use the first directory component after common prefixes.
fn extract_service_name(file: &str) -> String {
    let parts: Vec<&str> = file.split('/').collect();

    // Look for "services/X/", "packages/X/", "apps/X/" patterns
    for (i, part) in parts.iter().enumerate() {
        if matches!(*part, "services" | "packages" | "apps" | "modules" | "microservices") {
            if let Some(name) = parts.get(i + 1) {
                return name.to_string();
            }
        }
    }

    // Fallback: use first directory
    parts.first().unwrap_or(&"default").to_string()
}

/// Detect API endpoints within a set of nodes.
fn detect_endpoints(graph: &CallGraph, nodes: &FxHashSet<NodeIndex>) -> Vec<ServiceEndpoint> {
    let mut endpoints = Vec::new();

    for &idx in nodes {
        if let Some(node) = graph.graph.node_weight(idx) {
            let name_lower = node.name.to_lowercase();
            let file_lower = node.file.to_lowercase();

            let is_endpoint = name_lower.contains("handler")
                || name_lower.contains("controller")
                || name_lower.contains("endpoint")
                || file_lower.contains("route")
                || file_lower.contains("controller")
                || file_lower.contains("api");

            if is_endpoint {
                let method = extract_http_method(&name_lower);
                endpoints.push(ServiceEndpoint {
                    node: idx,
                    method,
                    path: None,
                });
            }
        }
    }

    endpoints
}

/// Extract HTTP method from function name.
fn extract_http_method(name: &str) -> Option<String> {
    if name.starts_with("get") || name.contains("_get") {
        Some("GET".to_string())
    } else if name.starts_with("post") || name.contains("_post") || name.contains("create") {
        Some("POST".to_string())
    } else if name.starts_with("put") || name.contains("_put") || name.contains("update") {
        Some("PUT".to_string())
    } else if name.starts_with("delete") || name.contains("_delete") || name.contains("remove") {
        Some("DELETE".to_string())
    } else if name.starts_with("patch") || name.contains("_patch") {
        Some("PATCH".to_string())
    } else {
        None
    }
}

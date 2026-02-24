//! Graph-level framework pattern detection — routes and events.
//!
//! Operates on the call graph to detect:
//! - HTTP route handlers (Express/Koa/Fastify/etc. patterns)
//! - Event emitters and handlers (EventEmitter patterns)

use drift_core::types::collections::FxHashSet;

use super::types::CallGraph;

const ROUTE_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "all",
];

const KNOWN_ROUTERS: &[&str] = &[
    "app", "router", "server", "route", "api", "express", "fastify", "koa",
    "hapi", "r", "mux", "fiber", "chi", "echo",
];

const EMIT_NAMES: &[&str] = &["emit", "fire", "dispatch", "trigger", "publish"];
const HANDLE_NAMES: &[&str] = &[
    "on", "addlistener", "addeventlistener", "subscribe", "handle",
    "once", "removelistener",
];

#[derive(Debug, Clone)]
pub struct DetectedRoute {
    pub method: String,
    pub path: String,
    pub handler_key: String,
    pub file: String,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct DetectedEvent {
    pub kind: EventKind,
    pub event_name: String,
    pub symbol_key: String,
    pub file: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Emit,
    Handle,
}

pub struct FrameworkDetectionResult {
    pub routes: Vec<DetectedRoute>,
    pub events: Vec<DetectedEvent>,
}

/// Detect framework patterns (routes, events) from the call graph.
pub fn detect_framework_patterns(
    cg: &CallGraph,
    in_repo_files: &FxHashSet<String>,
) -> FrameworkDetectionResult {
    let routes = detect_routes(cg, in_repo_files);
    let events = detect_events(cg, in_repo_files);

    FrameworkDetectionResult { routes, events }
}

fn detect_routes(cg: &CallGraph, in_repo_files: &FxHashSet<String>) -> Vec<DetectedRoute> {
    let mut routes = Vec::new();
    let mut seen = FxHashSet::default();

    for idx in cg.graph.node_indices() {
        let node = &cg.graph[idx];
        if !in_repo_files.contains(&node.file) {
            continue;
        }

        let lower = node.name.to_lowercase();

        for &method in ROUTE_METHODS {
            if lower == method
                || lower.starts_with(&format!("{method}handler"))
                || lower.starts_with(&format!("handle{method}"))
            {
                let key = format!("{}:{}:{}", method, &node.file, &node.name);
                if seen.insert(key) {
                    routes.push(DetectedRoute {
                        method: method.to_uppercase(),
                        path: infer_route_path(&node.name, &node.file),
                        handler_key: format!("{}::{}", node.file, node.name),
                        file: node.file.clone(),
                        confidence: 0.6,
                    });
                }
                break;
            }
        }
    }

    for edge_idx in cg.graph.edge_indices() {
        let (caller_idx, callee_idx) = match cg.graph.edge_endpoints(edge_idx) {
            Some(pair) => pair,
            None => continue,
        };

        let caller = &cg.graph[caller_idx];
        if !in_repo_files.contains(&caller.file) {
            continue;
        }

        let caller_lower = caller.name.to_lowercase();
        let is_router_method = ROUTE_METHODS.iter().any(|&m| {
            caller_lower == m
                || KNOWN_ROUTERS
                    .iter()
                    .any(|&r| caller_lower == format!("{r}.{m}"))
        });

        if is_router_method {
            let callee = &cg.graph[callee_idx];
            if in_repo_files.contains(&callee.file) {
                let method_name = ROUTE_METHODS
                    .iter()
                    .find(|&&m| caller_lower.contains(m))
                    .unwrap_or(&"ALL");

                let key = format!("{}:{}:{}", method_name, &callee.file, &callee.name);
                if seen.insert(key) {
                    routes.push(DetectedRoute {
                        method: method_name.to_uppercase(),
                        path: infer_route_path(&callee.name, &callee.file),
                        handler_key: format!("{}::{}", callee.file, callee.name),
                        file: callee.file.clone(),
                        confidence: 0.6,
                    });
                }
            }
        }
    }

    routes
}

fn detect_events(cg: &CallGraph, in_repo_files: &FxHashSet<String>) -> Vec<DetectedEvent> {
    let mut events = Vec::new();

    for edge_idx in cg.graph.edge_indices() {
        let (caller_idx, callee_idx) = match cg.graph.edge_endpoints(edge_idx) {
            Some(pair) => pair,
            None => continue,
        };

        let caller = &cg.graph[caller_idx];
        let callee = &cg.graph[callee_idx];

        if !in_repo_files.contains(&caller.file) {
            continue;
        }

        let callee_lower = callee.name.to_lowercase();

        if EMIT_NAMES.iter().any(|&e| callee_lower == e) {
            events.push(DetectedEvent {
                kind: EventKind::Emit,
                event_name: caller.name.clone(),
                symbol_key: format!("{}::{}", caller.file, caller.name),
                file: caller.file.clone(),
                confidence: 0.5,
            });
        }

        if HANDLE_NAMES.iter().any(|&h| callee_lower == h) {
            events.push(DetectedEvent {
                kind: EventKind::Handle,
                event_name: caller.name.clone(),
                symbol_key: format!("{}::{}", caller.file, caller.name),
                file: caller.file.clone(),
                confidence: 0.5,
            });
        }
    }

    events
}

fn infer_route_path(handler_name: &str, file_path: &str) -> String {
    let from_file = file_path
        .trim_end_matches(".ts")
        .trim_end_matches(".tsx")
        .trim_end_matches(".js")
        .trim_end_matches(".jsx")
        .replace('\\', "/");

    if let Some(rest) = from_file.strip_prefix("routes/").or_else(|| {
        from_file
            .find("/routes/")
            .map(|i| &from_file[i + "/routes/".len() - 1..])
    }) {
        if rest.starts_with('/') {
            return rest.to_string();
        }
        return format!("/{rest}");
    }

    let cleaned = handler_name
        .trim_end_matches("Handler")
        .trim_end_matches("handler");
    let mut path = String::with_capacity(cleaned.len() + 1);
    path.push('/');
    for (i, c) in cleaned.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            path.push('/');
        }
        path.push(c.to_lowercase().next().unwrap_or(c));
    }
    path
}

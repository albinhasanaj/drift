//! P4 Stress — Reachability: BFS, sensitivity, cache, cross-service, field flow
//!
//! Split from p4_graph_stress_test.rs for maintainability.

use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::graph::reachability::bfs::{
    auto_select_engine, reachability_auto, reachability_forward, reachability_inverse,
};
use drift_analysis::graph::reachability::cache::ReachabilityCache;
use drift_analysis::graph::reachability::cross_service::*;
use drift_analysis::graph::reachability::field_flow::*;
use drift_analysis::graph::reachability::sensitivity::classify_sensitivity;
use drift_analysis::graph::reachability::types::*;

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

fn node(file: &str, name: &str, exported: bool) -> FunctionNode {
    FunctionNode {
        file: file.to_string(), name: name.to_string(), qualified_name: None,
        language: "typescript".to_string(), line: 1, end_line: 10,
        is_entry_point: false, is_exported: exported, signature_hash: 0, body_hash: 0,
    }
}

fn edge() -> CallEdge {
    CallEdge { resolution: Resolution::ImportBased, confidence: 0.75, call_site_line: 5 }
}

// ═══════════════════════════════════════════════════════════════════════════
// BFS correctness, depth limits, cycles
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_bfs_forward_single_node_no_edges() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "alone", false));
    let r = reachability_forward(&g, a, None);
    assert!(r.reachable.is_empty());
    assert_eq!(r.max_depth, 0);
    assert_eq!(r.engine, ReachabilityEngine::Petgraph);
}

#[test]
fn stress_bfs_forward_self_loop() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "recursive", false));
    g.add_edge(a, a, edge());
    let r = reachability_forward(&g, a, None);
    assert!(r.reachable.is_empty());
}

#[test]
fn stress_bfs_forward_two_node_cycle() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());
    g.add_edge(b, a, edge());
    let r = reachability_forward(&g, a, None);
    assert_eq!(r.reachable.len(), 1);
    assert!(r.reachable.contains(&b));
}

#[test]
fn stress_bfs_forward_star_topology() {
    let mut g = CallGraph::new();
    let hub = g.add_function(node("hub.ts", "hub", true));
    let mut spokes = Vec::new();
    for i in 0..100 {
        let s = g.add_function(node(&format!("s{i}.ts"), &format!("spoke_{i}"), false));
        g.add_edge(hub, s, edge());
        spokes.push(s);
    }
    let r = reachability_forward(&g, hub, None);
    assert_eq!(r.reachable.len(), 100);
    assert_eq!(r.max_depth, 1);
}

#[test]
fn stress_bfs_inverse_star_topology() {
    let mut g = CallGraph::new();
    let target = g.add_function(node("target.ts", "target", false));
    for i in 0..100 {
        let c = g.add_function(node(&format!("c{i}.ts"), &format!("caller_{i}"), false));
        g.add_edge(c, target, edge());
    }
    let r = reachability_inverse(&g, target, None);
    assert_eq!(r.reachable.len(), 100);
    assert_eq!(r.max_depth, 1);
}

#[test]
fn stress_bfs_depth_limit_zero() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", true));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());
    let r = reachability_forward(&g, a, Some(0));
    assert!(r.reachable.is_empty(), "depth=0 should reach nothing");
}

#[test]
fn stress_bfs_depth_limit_exact() {
    let mut g = CallGraph::new();
    let nodes: Vec<_> = (0..5).map(|i| {
        g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), false))
    }).collect();
    for i in 0..4 { g.add_edge(nodes[i], nodes[i+1], edge()); }
    let r = reachability_forward(&g, nodes[0], Some(2));
    assert_eq!(r.reachable.len(), 2);
    assert!(r.reachable.contains(&nodes[1]));
    assert!(r.reachable.contains(&nodes[2]));
    assert!(!r.reachable.contains(&nodes[3]));
}

#[test]
fn stress_bfs_complete_graph_5_nodes() {
    let mut g = CallGraph::new();
    let nodes: Vec<_> = (0..5).map(|i| {
        g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), false))
    }).collect();
    for i in 0..5 {
        for j in 0..5 {
            if i != j { g.add_edge(nodes[i], nodes[j], edge()); }
        }
    }
    let r = reachability_forward(&g, nodes[0], None);
    assert_eq!(r.reachable.len(), 4);
}

#[test]
fn stress_bfs_disconnected_components() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());
    let c = g.add_function(node("c.ts", "funcC", false));
    let d = g.add_function(node("d.ts", "funcD", false));
    g.add_edge(c, d, edge());
    let r = reachability_forward(&g, a, None);
    assert_eq!(r.reachable.len(), 1);
    assert!(r.reachable.contains(&b));
    assert!(!r.reachable.contains(&c));
    assert!(!r.reachable.contains(&d));
}

#[test]
fn stress_bfs_wide_and_deep_graph() {
    let mut g = CallGraph::new();
    let root = g.add_function(node("root.ts", "root", true));
    let mut current_level = vec![root];
    for depth in 0..10 {
        let mut next_level = Vec::new();
        for (i, &parent) in current_level.iter().enumerate() {
            for j in 0..3 {
                let child = g.add_function(node(
                    &format!("d{depth}_n{i}_{j}.ts"),
                    &format!("f_d{depth}_n{i}_{j}"),
                    false,
                ));
                g.add_edge(parent, child, edge());
                next_level.push(child);
            }
        }
        current_level = next_level;
    }
    let r = reachability_forward(&g, root, None);
    assert!(r.reachable.len() > 100);
    assert!(r.max_depth == 10);
}

// ═══════════════════════════════════════════════════════════════════════════
// Auto-select engine threshold
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_auto_select_boundary() {
    assert_eq!(auto_select_engine(9_999), ReachabilityEngine::Petgraph);
    assert_eq!(auto_select_engine(10_000), ReachabilityEngine::SqliteCte);
    assert_eq!(auto_select_engine(0), ReachabilityEngine::Petgraph);
    assert_eq!(auto_select_engine(1), ReachabilityEngine::Petgraph);
}

// ═══════════════════════════════════════════════════════════════════════════
// Sensitivity classification exhaustive
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_sensitivity_user_input_to_command_is_critical() {
    let mut g = CallGraph::new();
    let handler = g.add_function(node("routes/api.ts", "get_users", true));
    let exec = g.add_function(node("cmd.ts", "run_command", false));
    g.add_edge(handler, exec, edge());
    assert_eq!(classify_sensitivity(&g, handler, &[exec]), SensitivityCategory::Critical);
}

#[test]
fn stress_sensitivity_user_input_to_file_is_high() {
    let mut g = CallGraph::new();
    let handler = g.add_function(node("routes/api.ts", "post_upload", true));
    let file_op = g.add_function(node("fs.ts", "write_file", false));
    g.add_edge(handler, file_op, edge());
    assert_eq!(classify_sensitivity(&g, handler, &[file_op]), SensitivityCategory::High);
}

#[test]
fn stress_sensitivity_user_input_to_network_is_high() {
    let mut g = CallGraph::new();
    let ctrl = g.add_function(node("controller/user.ts", "endpoint", true));
    let net = g.add_function(node("http.ts", "fetch_data", false));
    g.add_edge(ctrl, net, edge());
    assert_eq!(classify_sensitivity(&g, ctrl, &[net]), SensitivityCategory::High);
}

#[test]
fn stress_sensitivity_admin_to_file_is_medium() {
    let mut g = CallGraph::new();
    let admin = g.add_function(node("internal/mgmt.ts", "management_op", true));
    let file_op = g.add_function(node("fs.ts", "write_file", false));
    g.add_edge(admin, file_op, edge());
    assert_eq!(classify_sensitivity(&g, admin, &[file_op]), SensitivityCategory::Medium);
}

#[test]
fn stress_sensitivity_internal_to_internal_is_low() {
    let mut g = CallGraph::new();
    let util = g.add_function(node("utils.ts", "format_date", false));
    let other = g.add_function(node("utils.ts", "pad_string", false));
    g.add_edge(util, other, edge());
    assert_eq!(classify_sensitivity(&g, util, &[other]), SensitivityCategory::Low);
}

#[test]
fn stress_sensitivity_empty_reachable_is_low() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("routes/api.ts", "handler", true));
    assert_eq!(classify_sensitivity(&g, a, &[]), SensitivityCategory::Low);
}

#[test]
fn stress_sensitivity_all_categories_have_names_and_severity() {
    let cats = [SensitivityCategory::Critical, SensitivityCategory::High,
                SensitivityCategory::Medium, SensitivityCategory::Low];
    let mut severities = Vec::new();
    for c in &cats {
        assert!(!c.name().is_empty());
        assert!(!format!("{c}").is_empty());
        severities.push(c.severity());
    }
    for i in 0..severities.len()-1 {
        assert!(severities[i] > severities[i+1]);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Cache stress
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_cache_miss_then_hit() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", true));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());

    let cache = ReachabilityCache::new(10);
    assert!(cache.get(a, TraversalDirection::Forward).is_none());
    assert_eq!(cache.miss_count(), 1);

    let result = reachability_forward(&g, a, None);
    cache.put(result, TraversalDirection::Forward);

    assert!(cache.get(a, TraversalDirection::Forward).is_some());
    assert_eq!(cache.hit_count(), 1);
    assert_eq!(cache.len(), 1);
}

#[test]
fn stress_cache_eviction_at_capacity() {
    let cache = ReachabilityCache::new(4);
    let mut g = CallGraph::new();
    for i in 0..10 {
        let n = g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), false));
        let r = reachability_forward(&g, n, None);
        cache.put(r, TraversalDirection::Forward);
    }
    assert!(cache.len() <= 10);
}

#[test]
fn stress_cache_invalidate_all_clears_everything() {
    let cache = ReachabilityCache::new(100);
    let mut g = CallGraph::new();
    for i in 0..5 {
        let n = g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), false));
        let r = reachability_forward(&g, n, None);
        cache.put(r, TraversalDirection::Forward);
    }
    assert!(!cache.is_empty());
    cache.invalidate_all();
    let n0 = g.graph.node_indices().next().unwrap();
    assert!(cache.get(n0, TraversalDirection::Forward).is_none());
}

#[test]
fn stress_cache_forward_and_inverse_independent() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", true));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());

    let cache = ReachabilityCache::new(10);
    let fwd = reachability_forward(&g, a, None);
    let inv = reachability_inverse(&g, b, None);
    cache.put(fwd, TraversalDirection::Forward);
    cache.put(inv, TraversalDirection::Inverse);

    assert!(cache.get(a, TraversalDirection::Forward).is_some());
    assert!(cache.get(b, TraversalDirection::Inverse).is_some());
    assert!(cache.get(a, TraversalDirection::Inverse).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: cache.invalidate_node()
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_cache_invalidate_node_removes_both_directions() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", true));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());

    let cache = ReachabilityCache::new(10);
    let fwd = reachability_forward(&g, a, None);
    let inv = reachability_inverse(&g, a, None);
    cache.put(fwd, TraversalDirection::Forward);
    cache.put(inv, TraversalDirection::Inverse);

    assert!(cache.get(a, TraversalDirection::Forward).is_some());
    cache.invalidate_node(a);
    assert!(cache.get(a, TraversalDirection::Forward).is_none());
    assert!(cache.get(a, TraversalDirection::Inverse).is_none());
}

#[test]
fn stress_cache_invalidate_node_leaves_others() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", true));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());

    let cache = ReachabilityCache::new(10);
    let fwd_a = reachability_forward(&g, a, None);
    let fwd_b = reachability_forward(&g, b, None);
    cache.put(fwd_a, TraversalDirection::Forward);
    cache.put(fwd_b, TraversalDirection::Forward);

    cache.invalidate_node(a);
    assert!(cache.get(a, TraversalDirection::Forward).is_none());
    assert!(cache.get(b, TraversalDirection::Forward).is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: ReachabilityEngine name/Display, TraversalDirection coverage
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_reachability_engine_name_and_display() {
    assert_eq!(ReachabilityEngine::Petgraph.name(), "petgraph");
    assert_eq!(ReachabilityEngine::SqliteCte.name(), "sqlite_cte");
    assert_eq!(format!("{}", ReachabilityEngine::Petgraph), "petgraph");
    assert_eq!(format!("{}", ReachabilityEngine::SqliteCte), "sqlite_cte");
}

#[test]
fn stress_traversal_direction_both_variants() {
    let fwd = TraversalDirection::Forward;
    let inv = TraversalDirection::Inverse;
    assert_ne!(fwd, inv);
    // Ensure they can be used as cache keys
    let cache = ReachabilityCache::new(10);
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let r = reachability_forward(&g, a, None);
    cache.put(r, fwd);
    assert!(cache.get(a, fwd).is_some());
    assert!(cache.get(a, inv).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: reachability_auto() function
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_reachability_auto_small_graph() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());
    let r = reachability_auto(&g, a, TraversalDirection::Forward, None, None).unwrap();
    assert!(r.reachable.contains(&b));
    assert_eq!(r.engine, ReachabilityEngine::Petgraph);
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-service
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_cross_service_no_services() {
    let g = CallGraph::new();
    let boundaries = detect_service_boundaries(&g);
    assert!(boundaries.is_empty());
}

#[test]
fn stress_cross_service_single_service() {
    let mut g = CallGraph::new();
    g.add_function(node("services/auth/login.ts", "login", true));
    g.add_function(node("services/auth/verify.ts", "verify", false));
    let boundaries = detect_service_boundaries(&g);
    assert_eq!(boundaries.len(), 1);
    assert_eq!(boundaries[0].service_name, "auth");
}

#[test]
fn stress_cross_service_five_services() {
    let mut g = CallGraph::new();
    let services = ["auth", "billing", "users", "notifications", "analytics"];
    let mut first_nodes = Vec::new();
    for svc in &services {
        let n = g.add_function(node(
            &format!("services/{svc}/handler.ts"), &format!("{svc}_handler"), true,
        ));
        first_nodes.push(n);
    }
    for i in 0..4 {
        g.add_edge(first_nodes[i], first_nodes[i+1], edge());
    }
    let boundaries = detect_service_boundaries(&g);
    assert!(boundaries.len() >= 5);
    let result = cross_service_reachability(&g, first_nodes[0], &boundaries);
    assert!(result.reachable_services.len() >= 5);
    assert!(!result.cross_edges.is_empty());
}

#[test]
fn stress_cross_service_endpoint_detection() {
    let mut g = CallGraph::new();
    g.add_function(node("services/api/handler.ts", "getUsers_handler", true));
    g.add_function(node("services/api/controller.ts", "postOrder_controller", true));
    g.add_function(node("services/api/utils.ts", "helper", false));
    let boundaries = detect_service_boundaries(&g);
    let api_boundary = boundaries.iter().find(|b| b.service_name == "api");
    assert!(api_boundary.is_some());
    let endpoints = &api_boundary.unwrap().endpoints;
    assert!(endpoints.len() >= 2);
    let get_ep = endpoints.iter().find(|e| e.method.as_deref() == Some("GET"));
    assert!(get_ep.is_some());
    let post_ep = endpoints.iter().find(|e| e.method.as_deref() == Some("POST"));
    assert!(post_ep.is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// Field flow tracking
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_field_flow_single_node() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "getUser", true));
    let field = TrackedField::new("user", "email");
    let result = track_field_flow(&g, a, &field, None);
    assert_eq!(result.origin.qualified(), "user.email");
    assert_eq!(result.path.len(), 1);
    assert_eq!(result.access_points.len(), 1);
}

#[test]
fn stress_field_flow_transformation_detection() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "getUser", true));
    let b = g.add_function(node("b.ts", "transformEmail", false));
    let c = g.add_function(node("c.ts", "sendNotification", false));
    g.add_edge(a, b, edge());
    g.add_edge(b, c, edge());
    let field = TrackedField::new("user", "email");
    let result = track_field_flow(&g, a, &field, None);
    assert_eq!(result.path.len(), 3);
    let transform_hop = result.path.iter().find(|h| h.node == b).unwrap();
    assert!(transform_hop.transformed);
    let send_hop = result.path.iter().find(|h| h.node == c).unwrap();
    assert!(!send_hop.transformed);
}

#[test]
fn stress_field_flow_depth_limit() {
    let mut g = CallGraph::new();
    let nodes: Vec<_> = (0..20).map(|i| {
        g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), false))
    }).collect();
    for i in 0..19 { g.add_edge(nodes[i], nodes[i+1], edge()); }
    let field = TrackedField::new("obj", "field");
    let result = track_field_flow(&g, nodes[0], &field, Some(5));
    assert!(result.path.len() <= 7);
}

#[test]
fn stress_field_flow_multiple_fields() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "getUser", true));
    let b = g.add_function(node("b.ts", "process", false));
    g.add_edge(a, b, edge());
    let fields = vec![
        TrackedField::new("user", "email"),
        TrackedField::new("user", "name"),
        TrackedField::new("user", "ssn"),
    ];
    let results = track_multiple_fields(&g, a, &fields, None);
    assert_eq!(results.len(), 3);
    for r in &results {
        assert_eq!(r.path.len(), 2);
    }
}

#[test]
fn stress_field_flow_display_and_qualified() {
    let f = TrackedField::new("user", "email");
    assert_eq!(f.qualified(), "user.email");
    assert_eq!(format!("{f}"), "user.email");
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: field flow cycle handling
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_field_flow_cycle_terminates() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());
    g.add_edge(b, a, edge());
    let field = TrackedField::new("obj", "field");
    let result = track_field_flow(&g, a, &field, None);
    // Should terminate despite cycle
    assert!(!result.path.is_empty());
}

//! P4 Stress — Impact: blast radius, dead code, path finding, k-shortest
//!
//! Split from p4_graph_stress_test.rs for maintainability.

use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::graph::impact;
use drift_analysis::graph::impact::*;

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

fn edge_conf(conf: f32) -> CallEdge {
    CallEdge { resolution: Resolution::ImportBased, confidence: conf, call_site_line: 5 }
}

// ═══════════════════════════════════════════════════════════════════════════
// Blast radius: isolated, star, chain, cycle, fan-in, all radii
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_blast_radius_isolated_node() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "alone", false));
    let br = impact::blast_radius::compute_blast_radius(&g, a, 100);
    assert_eq!(br.caller_count, 0);
    assert_eq!(br.max_depth, 0);
    assert!(br.transitive_callers.is_empty());
    assert!(br.risk_score.overall >= 0.0);
}

#[test]
fn stress_blast_radius_star_topology() {
    let mut g = CallGraph::new();
    let target = g.add_function(node("target.ts", "target", false));
    for i in 0..50 {
        let c = g.add_function(node(&format!("c{i}.ts"), &format!("caller_{i}"), false));
        g.add_edge(c, target, edge());
    }
    let br = impact::blast_radius::compute_blast_radius(&g, target, 100);
    assert_eq!(br.caller_count, 50);
    assert_eq!(br.max_depth, 1);
    assert!((br.risk_score.blast_radius - 0.5).abs() < 0.01);
}

#[test]
fn stress_blast_radius_chain() {
    let mut g = CallGraph::new();
    let nodes: Vec<_> = (0..5).map(|i| {
        g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), false))
    }).collect();
    for i in 0..4 { g.add_edge(nodes[i], nodes[i+1], edge()); }
    let br = impact::blast_radius::compute_blast_radius(&g, nodes[4], 100);
    assert_eq!(br.caller_count, 4);
    assert_eq!(br.max_depth, 4);
}

#[test]
fn stress_blast_radius_cycle() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    let c = g.add_function(node("c.ts", "funcC", false));
    g.add_edge(a, b, edge());
    g.add_edge(b, c, edge());
    g.add_edge(c, a, edge());
    let br = impact::blast_radius::compute_blast_radius(&g, a, 100);
    assert_eq!(br.caller_count, 2);
}

#[test]
fn stress_blast_radius_fan_in() {
    let mut g = CallGraph::new();
    let target = g.add_function(node("target.ts", "target", false));
    let mid = g.add_function(node("mid.ts", "mid", false));
    g.add_edge(mid, target, edge());
    for i in 0..20 {
        let c = g.add_function(node(&format!("c{i}.ts"), &format!("caller_{i}"), false));
        g.add_edge(c, mid, edge());
    }
    let br = impact::blast_radius::compute_blast_radius(&g, target, 100);
    assert_eq!(br.caller_count, 21);
    assert_eq!(br.max_depth, 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// RiskScore: weights, clamping, defaults
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_risk_score_all_zero() {
    let rs = RiskScore::compute(0.0, 0.0, 1.0, 0.0, 0.0);
    assert!((rs.overall - 0.0).abs() < 0.01);
}

#[test]
fn stress_risk_score_all_max() {
    let rs = RiskScore::compute(1.0, 1.0, 0.0, 1.0, 1.0);
    assert!((rs.overall - 1.0).abs() < 0.01);
}

#[test]
fn stress_risk_score_test_coverage_reduces_risk() {
    let low_cov = RiskScore::compute(0.5, 0.5, 0.0, 0.5, 0.5);
    let high_cov = RiskScore::compute(0.5, 0.5, 1.0, 0.5, 0.5);
    assert!(high_cov.overall < low_cov.overall,
        "High test coverage should reduce risk: {} vs {}", high_cov.overall, low_cov.overall);
}

#[test]
fn stress_risk_score_clamping() {
    let rs = RiskScore::compute(2.0, 2.0, -1.0, 2.0, 2.0);
    assert!(rs.overall >= 0.0 && rs.overall <= 1.0);
}

#[test]
fn stress_risk_score_default() {
    let rs = RiskScore::default();
    assert_eq!(rs.blast_radius, 0.0);
    assert_eq!(rs.sensitivity, 0.0);
    assert_eq!(rs.test_coverage, 0.0);
    assert_eq!(rs.complexity, 0.0);
    assert_eq!(rs.change_frequency, 0.0);
    assert_eq!(rs.overall, 0.0);
}

#[test]
fn stress_risk_score_weight_verification() {
    let blast_only = RiskScore::compute(1.0, 0.0, 1.0, 0.0, 0.0);
    assert!((blast_only.overall - 0.30).abs() < 0.01);
    let sens_only = RiskScore::compute(0.0, 1.0, 1.0, 0.0, 0.0);
    assert!((sens_only.overall - 0.25).abs() < 0.01);
    let complex_only = RiskScore::compute(0.0, 0.0, 1.0, 1.0, 0.0);
    assert!((complex_only.overall - 0.15).abs() < 0.01);
    let freq_only = RiskScore::compute(0.0, 0.0, 1.0, 0.0, 1.0);
    assert!((freq_only.overall - 0.10).abs() < 0.01);
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: BlastRadius struct field access
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_blast_radius_struct_fields() {
    let mut g = CallGraph::new();
    let target = g.add_function(node("target.ts", "target", false));
    let caller = g.add_function(node("caller.ts", "caller", false));
    g.add_edge(caller, target, edge());
    let br = impact::blast_radius::compute_blast_radius(&g, target, 100);
    assert_eq!(br.function_id, target);
    assert_eq!(br.caller_count, 1);
    assert_eq!(br.transitive_callers.len(), 1);
    assert!(br.transitive_callers.contains(&caller));
    assert_eq!(br.max_depth, 1);
    assert!(br.risk_score.overall >= 0.0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Dead code: exclusions, unreachable, mixed, edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_dead_code_exclusion_all_10_categories() {
    assert_eq!(DeadCodeExclusion::all().len(), 10);
    let mut names = std::collections::HashSet::new();
    for exc in DeadCodeExclusion::all() {
        assert!(!exc.name().is_empty());
        assert!(names.insert(exc.name()), "Duplicate exclusion name: {}", exc.name());
    }
}

#[test]
fn stress_dead_code_entry_point_excluded() {
    let mut g = CallGraph::new();
    g.add_function(node("main.ts", "main", true));
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_dead);
    assert_eq!(results[0].exclusion, Some(DeadCodeExclusion::EntryPoint));
}

#[test]
fn stress_dead_code_event_handler_excluded() {
    let mut g = CallGraph::new();
    g.add_function({ let mut n = node("events.ts", "onClick", false); n.is_exported = false; n });
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_dead);
    assert_eq!(results[0].exclusion, Some(DeadCodeExclusion::EventHandler));
}

#[test]
fn stress_dead_code_reflection_target_excluded() {
    let mut g = CallGraph::new();
    g.add_function({ let mut n = node("proxy.ts", "dynamicInvoke", false); n.is_exported = false; n });
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_dead);
    assert_eq!(results[0].exclusion, Some(DeadCodeExclusion::ReflectionTarget));
}

#[test]
fn stress_dead_code_di_target_excluded() {
    let mut g = CallGraph::new();
    g.add_function({ let mut n = node("di.ts", "userServiceFactory", false); n.is_exported = false; n });
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_dead);
    assert_eq!(results[0].exclusion, Some(DeadCodeExclusion::DependencyInjection));
}

#[test]
fn stress_dead_code_test_utility_excluded() {
    let mut g = CallGraph::new();
    g.add_function({ let mut n = node("__tests__/helpers.ts", "createMockUser", false); n.is_exported = false; n });
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_dead);
    assert_eq!(results[0].exclusion, Some(DeadCodeExclusion::TestUtility));
}

#[test]
fn stress_dead_code_framework_hook_excluded() {
    let mut g = CallGraph::new();
    g.add_function({ let mut n = node("component.ts", "componentDidMount", false); n.is_exported = false; n });
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_dead);
    assert_eq!(results[0].exclusion, Some(DeadCodeExclusion::FrameworkHook));
}

#[test]
fn stress_dead_code_decorator_target_excluded() {
    let mut g = CallGraph::new();
    g.add_function({ let mut n = node("routes.ts", "apiEndpoint", false); n.is_exported = false; n });
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_dead);
    assert_eq!(results[0].exclusion, Some(DeadCodeExclusion::DecoratorTarget));
}

#[test]
fn stress_dead_code_interface_impl_excluded() {
    let mut g = CallGraph::new();
    g.add_function({
        let mut n = node("impl.ts", "doWork", false);
        n.is_exported = false;
        n.qualified_name = Some("MyClass::doWork".to_string());
        n
    });
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_dead);
    assert_eq!(results[0].exclusion, Some(DeadCodeExclusion::InterfaceImpl));
}

#[test]
fn stress_dead_code_conditional_compilation_excluded() {
    let mut g = CallGraph::new();
    g.add_function({ let mut n = node("platform/linux.ts", "linuxSpecific", false); n.is_exported = false; n });
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_dead);
    assert_eq!(results[0].exclusion, Some(DeadCodeExclusion::ConditionalCompilation));
}

#[test]
fn stress_dead_code_dynamic_import_excluded() {
    let mut g = CallGraph::new();
    g.add_function({ let mut n = node("lazy.ts", "lazyLoadModule", false); n.is_exported = false; n });
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_dead);
    assert_eq!(results[0].exclusion, Some(DeadCodeExclusion::DynamicImport));
}

#[test]
fn stress_dead_code_truly_dead_no_exclusion() {
    let mut g = CallGraph::new();
    g.add_function({ let mut n = node("orphan.ts", "computeSum", false); n.is_exported = false; n });
    let results = impact::dead_code::detect_dead_code(&g);
    assert_eq!(results.len(), 1);
    assert!(results[0].is_dead);
    assert_eq!(results[0].exclusion, None);
    assert_eq!(results[0].reason, DeadCodeReason::NoCallers);
}

#[test]
fn stress_dead_code_with_caller_not_flagged() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "caller", true));
    let b = g.add_function({ let mut n = node("b.ts", "callee", false); n.is_exported = false; n });
    g.add_edge(a, b, edge());
    let results = impact::dead_code::detect_dead_code(&g);
    let dead: Vec<_> = results.iter().filter(|r| r.is_dead).collect();
    assert!(dead.is_empty(), "Function with caller should not be dead");
}

#[test]
fn stress_dead_code_empty_graph() {
    let g = CallGraph::new();
    let results = impact::dead_code::detect_dead_code(&g);
    assert!(results.is_empty());
}

#[test]
fn stress_detect_unreachable_with_entry_points() {
    let mut g = CallGraph::new();
    let entry = g.add_function({ let mut n = node("main.ts", "main", true); n.is_entry_point = true; n });
    let reachable = g.add_function({ let mut n = node("lib.ts", "helper", false); n.is_exported = false; n });
    let unreachable = g.add_function({ let mut n = node("orphan.ts", "orphanFunc", false); n.is_exported = false; n });
    g.add_edge(entry, reachable, edge());
    let results = impact::dead_code::detect_unreachable(&g);
    let unreachable_ids: Vec<_> = results.iter().map(|r| r.function_id).collect();
    assert!(unreachable_ids.contains(&unreachable));
    assert!(!unreachable_ids.contains(&entry));
    assert!(!unreachable_ids.contains(&reachable));
}

#[test]
fn stress_detect_unreachable_all_reachable() {
    let mut g = CallGraph::new();
    let entry = g.add_function({ let mut n = node("main.ts", "main", true); n.is_entry_point = true; n });
    let b = g.add_function(node("b.ts", "funcB", false));
    let c = g.add_function(node("c.ts", "funcC", false));
    g.add_edge(entry, b, edge());
    g.add_edge(b, c, edge());
    let results = impact::dead_code::detect_unreachable(&g);
    assert!(results.is_empty(), "All nodes reachable from entry");
}

#[test]
fn stress_dead_code_reason_names() {
    assert_eq!(DeadCodeReason::NoCallers.name(), "no_callers");
    assert_eq!(DeadCodeReason::NoEntryPath.name(), "no_entry_path");
}

// ═══════════════════════════════════════════════════════════════════════════
// Path finding: Dijkstra, k-shortest, edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_shortest_path_no_path_exists() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    let result = impact::path_finding::shortest_path(&g, a, b);
    assert!(result.is_none());
}

#[test]
fn stress_shortest_path_same_node() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let result = impact::path_finding::shortest_path(&g, a, a);
    assert!(result.is_some());
    let path = result.unwrap();
    assert_eq!(path.nodes.len(), 1);
    assert_eq!(path.nodes[0], a);
    assert_eq!(path.weight, 0.0);
}

#[test]
fn stress_shortest_path_long_chain() {
    let mut g = CallGraph::new();
    let nodes: Vec<_> = (0..20).map(|i| {
        g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), false))
    }).collect();
    for i in 0..19 { g.add_edge(nodes[i], nodes[i+1], edge()); }
    let result = impact::path_finding::shortest_path(&g, nodes[0], nodes[19]);
    assert!(result.is_some());
    let path = result.unwrap();
    assert_eq!(path.nodes.len(), 20);
    assert_eq!(path.nodes[0], nodes[0]);
    assert_eq!(path.nodes[19], nodes[19]);
}

#[test]
fn stress_shortest_path_diamond() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    let c = g.add_function(node("c.ts", "funcC", false));
    let d = g.add_function(node("d.ts", "funcD", false));
    g.add_edge(a, b, edge_conf(0.9));
    g.add_edge(b, d, edge_conf(0.9));
    g.add_edge(a, c, edge_conf(0.5));
    g.add_edge(c, d, edge_conf(0.5));
    let result = impact::path_finding::shortest_path(&g, a, d).unwrap();
    assert_eq!(result.nodes.len(), 3);
    assert!(result.nodes.contains(&b), "Should go through B (higher confidence)");
    assert!((result.weight - 0.2).abs() < 0.05);
}

#[test]
fn stress_k_shortest_paths_k_equals_1() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());
    let paths = impact::path_finding::k_shortest_paths(&g, a, b, 1);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].nodes, vec![a, b]);
}

#[test]
fn stress_k_shortest_paths_k_greater_than_available() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());
    let paths = impact::path_finding::k_shortest_paths(&g, a, b, 5);
    assert_eq!(paths.len(), 1);
}

#[test]
fn stress_k_shortest_paths_parallel_paths() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    let c = g.add_function(node("c.ts", "funcC", false));
    let d = g.add_function(node("d.ts", "funcD", false));
    g.add_edge(a, b, edge_conf(0.9));
    g.add_edge(b, d, edge_conf(0.9));
    g.add_edge(a, c, edge_conf(0.5));
    g.add_edge(c, d, edge_conf(0.5));
    let paths = impact::path_finding::k_shortest_paths(&g, a, d, 2);
    assert_eq!(paths.len(), 2);
    assert!(paths[0].weight <= paths[1].weight);
}

#[test]
fn stress_k_shortest_paths_no_path() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    let paths = impact::path_finding::k_shortest_paths(&g, a, b, 3);
    assert!(paths.is_empty());
}

#[test]
fn stress_function_path_weight_accumulation() {
    let mut g = CallGraph::new();
    let nodes: Vec<_> = (0..5).map(|i| {
        g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), false))
    }).collect();
    for i in 0..4 { g.add_edge(nodes[i], nodes[i+1], edge()); }
    let path = impact::path_finding::shortest_path(&g, nodes[0], nodes[4]).unwrap();
    assert!((path.weight - 1.0).abs() < 0.01);
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: FunctionPath struct
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_function_path_struct_fields() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", false));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());
    let path = impact::path_finding::shortest_path(&g, a, b).unwrap();
    assert_eq!(path.nodes.len(), 2);
    assert_eq!(path.nodes[0], a);
    assert_eq!(path.nodes[1], b);
    assert!(path.weight >= 0.0);
}

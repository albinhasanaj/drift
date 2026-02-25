//! P4 Stress — Performance: large graph stress tests
//!
//! Split from p4_graph_stress_test.rs for maintainability.

use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::graph::impact;
use drift_analysis::graph::reachability::bfs::reachability_forward;
use drift_analysis::graph::test_topology;

use std::time::Instant;

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
// Large graph performance tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_perf_10k_node_bfs_under_200ms() {
    let mut g = CallGraph::new();
    let nodes: Vec<_> = (0..10_000).map(|i| {
        g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), i == 0))
    }).collect();
    for i in 0..9_999 { g.add_edge(nodes[i], nodes[i+1], edge()); }
    for i in (0..10_000).step_by(100) {
        let target = (i + 500) % 10_000;
        g.add_edge(nodes[i], nodes[target], edge());
    }
    let start = Instant::now();
    let r = reachability_forward(&g, nodes[0], None);
    let elapsed = start.elapsed();
    assert!(!r.reachable.is_empty());
    assert!(elapsed.as_millis() < 200, "10K BFS took {}ms", elapsed.as_millis());
}

#[test]
fn stress_perf_10k_blast_radius_under_500ms() {
    let mut g = CallGraph::new();
    let nodes: Vec<_> = (0..10_000).map(|i| {
        g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), false))
    }).collect();
    for i in 0..9_999 { g.add_edge(nodes[i], nodes[i+1], edge()); }
    let start = Instant::now();
    let br = impact::blast_radius::compute_blast_radius(&g, nodes[9_999], 10_000);
    let elapsed = start.elapsed();
    assert_eq!(br.caller_count, 9_999);
    assert!(elapsed.as_millis() < 500, "10K blast radius took {}ms", elapsed.as_millis());
}

#[test]
fn stress_perf_dead_code_10k_nodes_under_500ms() {
    let mut g = CallGraph::new();
    for i in 0..10_000 {
        g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), i < 100));
    }
    let start = Instant::now();
    let results = impact::dead_code::detect_dead_code(&g);
    let elapsed = start.elapsed();
    assert!(!results.is_empty());
    assert!(elapsed.as_millis() < 500, "10K dead code took {}ms", elapsed.as_millis());
}

#[test]
fn stress_perf_coverage_1k_tests_1k_sources() {
    let mut g = CallGraph::new();
    let tests: Vec<_> = (0..1_000).map(|i| {
        g.add_function(node(&format!("test_{i}.ts"), &format!("test_func_{i}"), false))
    }).collect();
    let sources: Vec<_> = (0..1_000).map(|i| {
        g.add_function(node(&format!("src/{i}.ts"), &format!("source_{i}"), false))
    }).collect();
    for (i, &test_node) in tests.iter().enumerate() {
        for j in 0..10 {
            let target = (i * 10 + j) % 1_000;
            g.add_edge(test_node, sources[target], edge());
        }
    }
    let start = Instant::now();
    let cov = test_topology::coverage::compute_coverage(&g);
    let elapsed = start.elapsed();
    assert_eq!(cov.total_test_functions, 1_000);
    assert_eq!(cov.total_source_functions, 1_000);
    assert!(elapsed.as_millis() < 2_000, "1K×1K coverage took {}ms", elapsed.as_millis());
}

#[test]
fn stress_perf_shortest_path_1k_chain() {
    let mut g = CallGraph::new();
    let nodes: Vec<_> = (0..1_000).map(|i| {
        g.add_function(node(&format!("{i}.ts"), &format!("f{i}"), false))
    }).collect();
    for i in 0..999 { g.add_edge(nodes[i], nodes[i+1], edge()); }
    let start = Instant::now();
    let path = impact::path_finding::shortest_path(&g, nodes[0], nodes[999]);
    let elapsed = start.elapsed();
    assert!(path.is_some());
    assert_eq!(path.unwrap().nodes.len(), 1_000);
    assert!(elapsed.as_millis() < 200, "1K shortest path took {}ms", elapsed.as_millis());
}

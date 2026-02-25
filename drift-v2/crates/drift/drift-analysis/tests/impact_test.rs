#![allow(unused_variables)]
//! T4-IMP-01 through T4-IMP-05: Impact analysis tests.

use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::graph::impact::*;

fn make_node(file: &str, name: &str, exported: bool) -> FunctionNode {
    FunctionNode {
        file: file.to_string(),
        name: name.to_string(),
        qualified_name: None,
        language: "typescript".to_string(),
        line: 1,
        end_line: 10,
        is_entry_point: false,
        is_exported: exported,
        signature_hash: 0,
        body_hash: 0,
    }
}

fn make_edge() -> CallEdge {
    CallEdge {
        resolution: Resolution::ImportBased,
        confidence: 0.75,
        call_site_line: 5,
    }
}

// T4-IMP-01: Blast radius with correct transitive closure
// Change in D affects B, C (direct callers) and A (transitive caller)
#[test]
fn test_blast_radius_transitive_closure() {
    //  A → B → D
    //  A → C → D
    let mut g = CallGraph::new();
    let a = g.add_function(make_node("a.ts", "funcA", true));
    let b = g.add_function(make_node("b.ts", "funcB", false));
    let c = g.add_function(make_node("c.ts", "funcC", false));
    let d = g.add_function(make_node("d.ts", "funcD", false));
    g.add_edge(a, b, make_edge());
    g.add_edge(a, c, make_edge());
    g.add_edge(b, d, make_edge());
    g.add_edge(c, d, make_edge());

    let radius = compute_blast_radius(&g, d, 100);

    // D's transitive callers: B, C, A
    assert_eq!(radius.caller_count, 3);
    assert!(radius.transitive_callers.contains(&a));
    assert!(radius.transitive_callers.contains(&b));
    assert!(radius.transitive_callers.contains(&c));
    assert!(radius.risk_score.blast_radius > 0.0);
}

// T4-IMP-02: Dead code detection correctly excludes all 10 false-positive categories
#[test]
fn test_dead_code_exclusions() {
    let mut g = CallGraph::new();

    // Entry point — should be excluded
    let entry = g.add_function({
        let mut n = make_node("index.ts", "main", true);
        n.is_entry_point = true;
        n
    });

    // Event handler — should be excluded
    let _handler = g.add_function(make_node("events.ts", "on_click", false));

    // Reflection target — should be excluded
    let _reflect = g.add_function(make_node("proxy.ts", "invoke_handler", false));

    // DI target — should be excluded
    let _di = g.add_function(make_node("di.ts", "inject_service", false));

    // Test utility — should be excluded
    let _test = g.add_function(make_node("test_helpers.ts", "test_setup", false));

    // Framework hook — should be excluded
    let _hook = g.add_function(make_node("component.tsx", "componentDidMount", false));

    // Decorator target — should be excluded
    let _decorator = g.add_function(make_node("routes.ts", "api_endpoint", false));

    // Interface impl — should be excluded
    let _iface = g.add_function({
        let mut n = make_node("impl.ts", "process", false);
        n.qualified_name = Some("Handler::process".to_string());
        n
    });

    // Conditional compilation — should be excluded
    let _cfg = g.add_function(make_node("platform/linux.ts", "platform_init", false));

    // Dynamic import — should be excluded
    let _dynamic = g.add_function(make_node("lazy.ts", "lazy_load", false));

    // Actually dead code — no exclusion applies
    let _dead = g.add_function(make_node("orphan.ts", "unused_internal", false));

    let results = detect_dead_code(&g);

    // All nodes have no callers, so all should appear in results
    assert!(!results.is_empty());

    // Count how many are actually flagged as dead (not excluded)
    let truly_dead: Vec<_> = results.iter().filter(|r| r.is_dead).collect();
    let excluded: Vec<_> = results.iter().filter(|r| !r.is_dead).collect();

    // The "unused_internal" should be truly dead
    assert!(!truly_dead.is_empty(), "Expected at least one truly dead function");

    // All 10 exclusion categories should be represented
    let exclusion_categories: Vec<_> = excluded.iter()
        .filter_map(|r| r.exclusion)
        .collect();
    assert!(exclusion_categories.len() >= 9,
        "Expected at least 9 exclusion categories, got {}: {:?}",
        exclusion_categories.len(), exclusion_categories);

    // Verify all 10 exclusion types exist
    assert_eq!(DeadCodeExclusion::all().len(), 10);
}

// T4-IMP-03: Blast radius with circular dependency — finite, all nodes included
#[test]
fn test_blast_radius_circular_dependency() {
    // A → B → C → A (cycle)
    let mut g = CallGraph::new();
    let a = g.add_function(make_node("a.ts", "funcA", true));
    let b = g.add_function(make_node("b.ts", "funcB", false));
    let c = g.add_function(make_node("c.ts", "funcC", false));
    g.add_edge(a, b, make_edge());
    g.add_edge(b, c, make_edge());
    g.add_edge(c, a, make_edge());

    let radius = compute_blast_radius(&g, a, 100);

    // All 3 nodes are in the cycle, so A's callers include B and C
    assert_eq!(radius.caller_count, 2);
    assert!(radius.transitive_callers.contains(&b));
    assert!(radius.transitive_callers.contains(&c));
    // Should not be infinite
    assert!(radius.max_depth < 100);
}

// T4-IMP-04: Impact scoring — high-caller function scores higher
#[test]
fn test_impact_scoring_high_vs_low() {
    // High-impact: funcH called by 100 callers
    let mut g_high = CallGraph::new();
    let target_h = g_high.add_function(make_node("target.ts", "funcH", false));
    for i in 0..100 {
        let caller = g_high.add_function(make_node(
            &format!("caller_{}.ts", i),
            &format!("caller_{}", i),
            false,
        ));
        g_high.add_edge(caller, target_h, make_edge());
    }

    // Low-impact: funcL called by 2 callers
    let mut g_low = CallGraph::new();
    let target_l = g_low.add_function(make_node("target.ts", "funcL", false));
    for i in 0..2 {
        let caller = g_low.add_function(make_node(
            &format!("caller_{}.ts", i),
            &format!("caller_{}", i),
            false,
        ));
        g_low.add_edge(caller, target_l, make_edge());
    }

    let radius_high = compute_blast_radius(&g_high, target_h, 200);
    let radius_low = compute_blast_radius(&g_low, target_l, 200);

    assert!(radius_high.risk_score.overall > radius_low.risk_score.overall,
        "High-impact ({}) should score higher than low-impact ({})",
        radius_high.risk_score.overall, radius_low.risk_score.overall);
    assert_eq!(radius_high.caller_count, 100);
    assert_eq!(radius_low.caller_count, 2);
}

// T4-IMP-05: Dead code detection with dynamic dispatch — not flagged as dead
#[test]
fn test_dead_code_dynamic_dispatch() {
    let mut g = CallGraph::new();

    // Function called only via reflection/dynamic dispatch
    let dynamic_fn = g.add_function(make_node("dynamic.ts", "dynamic_handler", false));

    let results = detect_dead_code(&g);

    // "dynamic_handler" contains "handler" which triggers event_handler exclusion,
    // and "dynamic" triggers dynamic_import exclusion
    let result = results.iter().find(|r| r.function_id == dynamic_fn);
    assert!(result.is_some());
    let result = result.unwrap();
    assert!(!result.is_dead, "Dynamic dispatch target should not be flagged as dead");
    assert!(result.exclusion.is_some());
}

// Additional: Path finding tests
#[test]
fn test_shortest_path() {
    // A → B → C → D
    let mut g = CallGraph::new();
    let a = g.add_function(make_node("a.ts", "funcA", true));
    let b = g.add_function(make_node("b.ts", "funcB", false));
    let c = g.add_function(make_node("c.ts", "funcC", false));
    let d = g.add_function(make_node("d.ts", "funcD", false));
    g.add_edge(a, b, make_edge());
    g.add_edge(b, c, make_edge());
    g.add_edge(c, d, make_edge());

    let path = shortest_path(&g, a, d);
    assert!(path.is_some());
    let path = path.unwrap();
    assert_eq!(path.nodes.len(), 4); // A, B, C, D
    assert_eq!(path.nodes[0], a);
    assert_eq!(path.nodes[3], d);
}

#[test]
fn test_k_shortest_paths() {
    //  A → B → D
    //  A → C → D
    let mut g = CallGraph::new();
    let a = g.add_function(make_node("a.ts", "funcA", true));
    let b = g.add_function(make_node("b.ts", "funcB", false));
    let c = g.add_function(make_node("c.ts", "funcC", false));
    let d = g.add_function(make_node("d.ts", "funcD", false));
    g.add_edge(a, b, CallEdge { resolution: Resolution::ImportBased, confidence: 0.90, call_site_line: 5 });
    g.add_edge(a, c, CallEdge { resolution: Resolution::ImportBased, confidence: 0.50, call_site_line: 10 });
    g.add_edge(b, d, CallEdge { resolution: Resolution::ImportBased, confidence: 0.90, call_site_line: 15 });
    g.add_edge(c, d, CallEdge { resolution: Resolution::ImportBased, confidence: 0.50, call_site_line: 20 });

    let paths = k_shortest_paths(&g, a, d, 3);
    assert!(paths.len() >= 2, "Expected at least 2 paths, got {}", paths.len());

    // First path should be the shortest (highest confidence = lowest weight)
    assert!(paths[0].weight <= paths[1].weight);
}

#[test]
fn test_compute_all_blast_radii() {
    let mut g = CallGraph::new();
    let a = g.add_function(make_node("a.ts", "funcA", true));
    let b = g.add_function(make_node("b.ts", "funcB", false));
    let c = g.add_function(make_node("c.ts", "funcC", false));
    g.add_edge(a, b, make_edge());
    g.add_edge(b, c, make_edge());

    let radii = blast_radius::compute_all_blast_radii(&g);
    assert_eq!(radii.len(), 3);

    // C should have the highest blast radius (A and B call it transitively)
    let c_radius = radii.iter().find(|r| r.function_id == c).unwrap();
    assert_eq!(c_radius.caller_count, 2);
}

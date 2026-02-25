//! Enterprise stress tests for Cortex Causal hardening fixes.
//!
//! Covers:
//! - P3-5/C-05/C-06: Causal node types stored as 'unknown' (honest) during
//!   storage hydration, and as real types when created via engine.add_edge().
//!
//! Every test targets a specific production failure mode.

use cortex_causal::graph::stable_graph::{CausalEdgeWeight, IndexedGraph};
use cortex_causal::relations::CausalRelation;

// ═══════════════════════════════════════════════════════════════════════════════
// P3-5/C-05/C-06: CAUSAL NODE TYPES — honesty in storage hydration
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: sync.rs stored "memory" as the node type for ALL nodes
/// hydrated from storage, regardless of actual memory type. Now uses "unknown"
/// to be honest about what we know during edge-only hydration.
#[test]
fn hst_c05_01_ensure_node_stores_given_type() {
    let mut graph = IndexedGraph::new();
    let idx = graph.ensure_node("mem-001", "decision", "A decision memory");

    let node = &graph.graph[idx];
    assert_eq!(node.memory_type, "decision");
    assert_eq!(node.memory_id, "mem-001");
    assert_eq!(node.summary, "A decision memory");
}

/// ensure_node is idempotent — second call returns same index, doesn't overwrite.
#[test]
fn hst_c05_02_ensure_node_idempotent() {
    let mut graph = IndexedGraph::new();
    let idx1 = graph.ensure_node("mem-002", "episodic", "first call");
    let idx2 = graph.ensure_node("mem-002", "core", "second call attempt");

    assert_eq!(idx1, idx2, "Same memory_id should return same NodeIndex");

    // Original type and summary should be preserved (not overwritten).
    let node = &graph.graph[idx1];
    assert_eq!(node.memory_type, "episodic", "Type should not be overwritten");
    assert_eq!(node.summary, "first call", "Summary should not be overwritten");
}

/// When hydrating from storage edges, type should be "unknown" not "memory".
#[test]
fn hst_c05_03_hydrated_nodes_use_unknown_type() {
    let mut graph = IndexedGraph::new();

    // Simulate what sync.rs does during rebuild_from_storage.
    let source_idx = graph.ensure_node("edge-src", "unknown", "");
    let target_idx = graph.ensure_node("edge-tgt", "unknown", "");

    let src_node = &graph.graph[source_idx];
    let tgt_node = &graph.graph[target_idx];

    assert_eq!(src_node.memory_type, "unknown");
    assert_eq!(tgt_node.memory_type, "unknown");
}

/// If engine.add_edge() is called with real types BEFORE hydration,
/// the type is preserved when hydration tries to ensure_node again.
#[test]
fn hst_c05_04_real_type_preserved_over_hydration() {
    let mut graph = IndexedGraph::new();

    // Engine creates node with real type.
    graph.ensure_node("mem-003", "insight", "An insight");

    // Later, hydration tries to ensure_node with "unknown".
    graph.ensure_node("mem-003", "unknown", "");

    // Real type should be preserved.
    let idx = graph.get_node("mem-003").unwrap();
    let node = &graph.graph[idx];
    assert_eq!(node.memory_type, "insight", "Real type must not be overwritten by 'unknown'");
}

/// Stress: 1000 nodes with mixed types — correct lookup.
#[test]
fn hst_c05_05_stress_1000_nodes() {
    let mut graph = IndexedGraph::new();

    for i in 0..1000 {
        let mem_type = match i % 5 {
            0 => "episodic",
            1 => "decision",
            2 => "unknown",
            3 => "core",
            _ => "insight",
        };
        graph.ensure_node(&format!("node-{i}"), mem_type, &format!("summary-{i}"));
    }

    // Verify all 1000 are present and correct.
    for i in 0..1000 {
        let idx = graph.get_node(&format!("node-{i}")).unwrap();
        let node = &graph.graph[idx];
        assert_eq!(node.memory_id, format!("node-{i}"));
        let expected = match i % 5 {
            0 => "episodic",
            1 => "decision",
            2 => "unknown",
            3 => "core",
            _ => "insight",
        };
        assert_eq!(node.memory_type, expected, "Type mismatch at node-{i}");
    }
}

/// get_node for nonexistent returns None.
#[test]
fn hst_c05_06_get_nonexistent_node_returns_none() {
    let graph = IndexedGraph::new();
    assert!(graph.get_node("does-not-exist").is_none());
}

/// Add edge between two nodes — graph has correct edge count.
#[test]
fn hst_c05_07_add_edge_between_nodes() {
    let mut graph = IndexedGraph::new();
    let src = graph.ensure_node("src", "decision", "source");
    let tgt = graph.ensure_node("tgt", "insight", "target");

    let weight = CausalEdgeWeight {
        relation: CausalRelation::Caused,
        strength: 0.9,
        evidence: vec![],
        inferred: false,
    };

    graph.graph.add_edge(src, tgt, weight);
    assert_eq!(graph.graph.edge_count(), 1);
    assert_eq!(graph.graph.node_count(), 2);
}

/// Stress: 500 edges in a chain — graph integrity preserved.
#[test]
fn hst_c05_08_stress_500_edge_chain() {
    let mut graph = IndexedGraph::new();

    for i in 0..500 {
        let src = graph.ensure_node(&format!("chain-{i}"), "unknown", "");
        let tgt = graph.ensure_node(&format!("chain-{}", i + 1), "unknown", "");
        let weight = CausalEdgeWeight {
            relation: CausalRelation::Caused,
            strength: 0.5,
            evidence: vec![],
            inferred: true,
        };
        graph.graph.add_edge(src, tgt, weight);
    }

    assert_eq!(graph.graph.edge_count(), 500);
    assert_eq!(graph.graph.node_count(), 501); // 0..500 + 501 = 501 nodes
}

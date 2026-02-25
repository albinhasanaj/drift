//! Property tests for cortex-causal: T7-CAUS-09 through T7-CAUS-12.

use proptest::prelude::*;

use cortex_causal::graph::dag_enforcement;
use cortex_causal::graph::stable_graph::{CausalEdgeWeight, IndexedGraph};
use cortex_causal::relations::CausalRelation;
use cortex_causal::traversal::{TraversalConfig, TraversalEngine};

fn make_edge(strength: f64) -> CausalEdgeWeight {
    CausalEdgeWeight {
        relation: CausalRelation::Caused,
        strength,
        evidence: Vec::new(),
        inferred: false,
    }
}

/// Build a random DAG with `n` nodes and random edges (no cycles).
fn build_random_dag(n: usize, edges: &[(usize, usize, f64)]) -> IndexedGraph {
    let mut graph = IndexedGraph::new();
    for i in 0..n {
        graph.ensure_node(&format!("n{i}"), "core", &format!("Node {i}"));
    }
    for &(src, tgt, strength) in edges {
        if src < n && tgt < n && src != tgt {
            let src_idx = graph.get_node(&format!("n{src}")).unwrap();
            let tgt_idx = graph.get_node(&format!("n{tgt}")).unwrap();
            // Only add if it won't create a cycle.
            if !dag_enforcement::would_create_cycle(&graph, src_idx, tgt_idx) {
                graph.graph.add_edge(src_idx, tgt_idx, make_edge(strength));
            }
        }
    }
    graph
}

// Strategy to generate random edges for a graph of size n.
fn edge_strategy(n: usize) -> impl Strategy<Value = Vec<(usize, usize, f64)>> {
    prop::collection::vec((0..n, 0..n, 0.1_f64..1.0_f64), 0..n * 2)
}

// =============================================================================
// T7-CAUS-09: Property test — DAG enforcement, no cycles
// =============================================================================
proptest! {
    #[test]
    fn t7_caus_09_dag_no_cycles(
        edges in edge_strategy(20)
    ) {
        let graph = build_random_dag(20, &edges);
        let cycles = dag_enforcement::find_cycles(&graph);
        prop_assert!(cycles.is_empty(), "DAG should have no cycles, found {}", cycles.len());
    }
}

// =============================================================================
// T7-CAUS-10: Property test — depth ≤ maxDepth
// =============================================================================
proptest! {
    #[test]
    fn t7_caus_10_depth_bounded(
        max_depth in 1_usize..10,
        edges in edge_strategy(15)
    ) {
        let graph = build_random_dag(15, &edges);
        let config = TraversalConfig {
            max_depth,
            min_strength: 0.0,
            max_nodes: 1000,
        };
        let engine = TraversalEngine::new(config);

        // Test from every node.
        for i in 0..15 {
            let result = engine.trace_effects(&graph, &format!("n{i}"));
            for node in &result.nodes {
                prop_assert!(
                    node.depth <= max_depth,
                    "Node depth {} exceeds max_depth {}",
                    node.depth,
                    max_depth
                );
            }
        }
    }
}

// =============================================================================
// T7-CAUS-11: Property test — nodes ≤ maxNodes
// =============================================================================
proptest! {
    #[test]
    fn t7_caus_11_nodes_bounded(
        max_nodes in 1_usize..50,
        edges in edge_strategy(30)
    ) {
        let graph = build_random_dag(30, &edges);
        let config = TraversalConfig {
            max_depth: 100,
            min_strength: 0.0,
            max_nodes,
        };
        let engine = TraversalEngine::new(config);

        for i in 0..30 {
            let result = engine.trace_effects(&graph, &format!("n{i}"));
            prop_assert!(
                result.nodes.len() <= max_nodes,
                "Got {} nodes, max is {}",
                result.nodes.len(),
                max_nodes
            );
        }
    }
}

// =============================================================================
// T7-CAUS-12: Property test — bidirectional = union
// =============================================================================
proptest! {
    #[test]
    fn t7_caus_12_bidirectional_is_union(
        edges in edge_strategy(15)
    ) {
        let graph = build_random_dag(15, &edges);
        let config = TraversalConfig {
            max_depth: 10,
            min_strength: 0.0,
            max_nodes: 1000,
        };
        let engine = TraversalEngine::new(config);

        for i in 0..15 {
            let node_id = format!("n{i}");
            let origins = engine.trace_origins(&graph, &node_id);
            let effects = engine.trace_effects(&graph, &node_id);
            let bidir = engine.bidirectional(&graph, &node_id);

            let origin_ids: std::collections::HashSet<_> =
                origins.nodes.iter().map(|n| &n.memory_id).collect();
            let effect_ids: std::collections::HashSet<_> =
                effects.nodes.iter().map(|n| &n.memory_id).collect();
            let bidir_ids: std::collections::HashSet<_> =
                bidir.nodes.iter().map(|n| &n.memory_id).collect();

            let union: std::collections::HashSet<_> =
                origin_ids.union(&effect_ids).copied().collect();

            prop_assert_eq!(
                bidir_ids,
                union,
                "Bidirectional should equal union"
            );
        }
    }
}

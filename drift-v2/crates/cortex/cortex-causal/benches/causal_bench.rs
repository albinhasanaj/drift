use criterion::{criterion_group, criterion_main, Criterion};

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

/// Build a DAG with ~1K edges: 200 nodes, ~5 edges per node (forward only).
fn build_1k_edge_dag() -> IndexedGraph {
    let mut graph = IndexedGraph::new();
    let n = 200;
    for i in 0..n {
        graph.ensure_node(&format!("n{i}"), "core", &format!("Node {i}"));
    }
    let mut count = 0;
    for i in 0..n {
        // Connect to up to 5 forward nodes.
        for j in 1..=5 {
            let target = i + j;
            if target < n {
                let src = graph.get_node(&format!("n{i}")).unwrap();
                let tgt = graph.get_node(&format!("n{target}")).unwrap();
                if !dag_enforcement::would_create_cycle(&graph, src, tgt) {
                    graph.graph.add_edge(src, tgt, make_edge(0.7));
                    count += 1;
                }
            }
        }
    }
    assert!(count >= 900, "Should have ~1K edges, got {count}");
    graph
}

fn bench_traversal_depth_5(c: &mut Criterion) {
    let graph = build_1k_edge_dag();
    let config = TraversalConfig {
        max_depth: 5,
        min_strength: 0.0,
        max_nodes: 50,
    };
    let engine = TraversalEngine::new(config);

    c.bench_function("traversal_depth_5_1k_edges", |b| {
        b.iter(|| {
            engine.trace_effects(&graph, "n0");
        });
    });
}

fn bench_dag_enforcement(c: &mut Criterion) {
    let graph = build_1k_edge_dag();

    c.bench_function("dag_cycle_check_1k_edges", |b| {
        let src = graph.get_node("n199").unwrap();
        let tgt = graph.get_node("n0").unwrap();
        b.iter(|| {
            dag_enforcement::would_create_cycle(&graph, src, tgt);
        });
    });
}

criterion_group!(benches, bench_traversal_depth_5, bench_dag_enforcement);
criterion_main!(benches);

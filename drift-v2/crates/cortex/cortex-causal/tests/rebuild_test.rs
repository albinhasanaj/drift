//! Phase C causal graph rebuild tests (C-14, C-15, C-16).
//!
//! Verify that rebuild_from_storage correctly hydrates the in-memory graph
//! from persisted causal edges.

use cortex_core::errors::CortexResult;
use cortex_core::traits::{CausalEdge, CausalEvidence, ICausalStorage};
use cortex_causal::graph::sync;
use cortex_causal::graph::stable_graph::IndexedGraph;

// ── In-memory mock storage for causal tests ──────────────────────────────

struct MockCausalStorage {
    edges: Vec<CausalEdge>,
}

impl MockCausalStorage {
    fn new() -> Self {
        Self { edges: vec![] }
    }

    fn with_edges(edges: Vec<CausalEdge>) -> Self {
        Self { edges }
    }
}

impl ICausalStorage for MockCausalStorage {
    fn add_edge(&self, _edge: &CausalEdge) -> CortexResult<()> {
        Ok(())
    }

    fn get_edges(&self, node_id: &str) -> CortexResult<Vec<CausalEdge>> {
        Ok(self
            .edges
            .iter()
            .filter(|e| e.source_id == node_id || e.target_id == node_id)
            .cloned()
            .collect())
    }

    fn remove_edge(&self, _: &str, _: &str) -> CortexResult<()> {
        Ok(())
    }

    fn update_strength(&self, _: &str, _: &str, _: f64) -> CortexResult<()> {
        Ok(())
    }

    fn add_evidence(&self, _: &str, _: &str, _: &CausalEvidence) -> CortexResult<()> {
        Ok(())
    }

    fn has_cycle(&self, _: &str, _: &str) -> CortexResult<bool> {
        Ok(false)
    }

    fn list_all_node_ids(&self) -> CortexResult<Vec<String>> {
        let mut ids = std::collections::HashSet::new();
        for edge in &self.edges {
            ids.insert(edge.source_id.clone());
            ids.insert(edge.target_id.clone());
        }
        let mut sorted: Vec<String> = ids.into_iter().collect();
        sorted.sort();
        Ok(sorted)
    }

    fn edge_count(&self) -> CortexResult<usize> {
        Ok(self.edges.len())
    }

    fn node_count(&self) -> CortexResult<usize> {
        self.list_all_node_ids().map(|ids| ids.len())
    }

    fn remove_orphaned_edges(&self) -> CortexResult<usize> {
        Ok(0)
    }
}

fn make_edge(source: &str, target: &str, relation: &str, strength: f64) -> CausalEdge {
    CausalEdge {
        source_id: source.to_string(),
        target_id: target.to_string(),
        relation: relation.to_string(),
        strength,
        evidence: vec![],
        source_agent: None,
    }
}

/// C-14: Causal graph survives "restart" — insert edges, rebuild from storage, verify present.
#[test]
fn c14_causal_graph_survives_restart() {
    let storage = MockCausalStorage::with_edges(vec![
        make_edge("mem-1", "mem-2", "Supports", 0.8),
        make_edge("mem-2", "mem-3", "Enables", 0.6),
    ]);

    // Simulate restart: new empty graph, rebuild from storage.
    let mut graph = IndexedGraph::new();
    sync::rebuild_from_storage(&storage, &mut graph).expect("rebuild should succeed");

    // Verify edges are present.
    assert_eq!(graph.graph.edge_count(), 2, "should have 2 edges after rebuild");
    assert!(graph.get_node("mem-1").is_some(), "mem-1 should exist");
    assert!(graph.get_node("mem-2").is_some(), "mem-2 should exist");
    assert!(graph.get_node("mem-3").is_some(), "mem-3 should exist");
}

/// C-15: Rebuild loads ALL edges — 100 unique edges across many nodes.
#[test]
fn c15_causal_rebuild_loads_all_edges() {
    let mut edges = Vec::new();
    // Generate 100 unique edges: source-i → target-i.
    for i in 0..100 {
        let source = format!("src-{i}");
        let target = format!("tgt-{i}");
        edges.push(make_edge(&source, &target, "Supports", 0.5 + (i as f64 * 0.001)));
    }
    let storage = MockCausalStorage::with_edges(edges);

    let mut graph = IndexedGraph::new();
    sync::rebuild_from_storage(&storage, &mut graph).expect("rebuild should succeed");

    // All 100 unique edges should be loaded.
    assert_eq!(
        graph.graph.edge_count(),
        100,
        "should have all 100 edges after rebuild"
    );

    // 200 unique node IDs (100 sources + 100 targets).
    assert_eq!(
        graph.node_index.len(),
        200,
        "should have 200 nodes (100 sources + 100 targets)"
    );
}

/// C-16: Rebuild with empty storage is safe — no errors, empty graph.
#[test]
fn c16_causal_rebuild_empty_storage() {
    let storage = MockCausalStorage::new();

    let mut graph = IndexedGraph::new();
    let result = sync::rebuild_from_storage(&storage, &mut graph);

    assert!(result.is_ok(), "rebuild from empty storage should succeed");
    assert_eq!(graph.graph.node_count(), 0, "graph should be empty");
    assert_eq!(graph.graph.edge_count(), 0, "graph should have no edges");
}

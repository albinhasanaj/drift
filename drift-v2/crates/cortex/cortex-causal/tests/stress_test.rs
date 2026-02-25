//! Stress test: 1000+ memories in the causal narrative system.
//! Verifies coherent narrative generation without OOM or excessive latency.

use std::time::Instant;

use chrono::Utc;
use cortex_causal::graph::stable_graph::{CausalEdgeWeight, EdgeEvidence, IndexedGraph};
use cortex_causal::narrative::NarrativeGenerator;
use cortex_causal::relations::CausalRelation;

fn make_edge(relation: CausalRelation, strength: f64) -> CausalEdgeWeight {
    CausalEdgeWeight {
        relation,
        strength,
        evidence: vec![EdgeEvidence {
            description: "auto-generated evidence".to_string(),
            source: "stress_test".to_string(),
            timestamp: Utc::now(),
        }],
        inferred: false,
    }
}

/// Build a graph with `n` nodes and a mix of chain + cross-links.
fn build_large_graph(n: usize) -> (IndexedGraph, Vec<String>) {
    let mut graph = IndexedGraph::new();
    let mut ids = Vec::with_capacity(n);

    // Create all nodes.
    for i in 0..n {
        let id = format!("mem_{i:04}");
        graph.ensure_node(&id, "episodic", &format!("Memory about topic {}", i % 50));
        ids.push(id);
    }

    // Linear chain: 0→1→2→...→n-1
    let relations = CausalRelation::ALL;
    for i in 0..(n - 1) {
        let rel = relations[i % relations.len()];
        let src = graph.get_node(&ids[i]).unwrap();
        let tgt = graph.get_node(&ids[i + 1]).unwrap();
        graph
            .graph
            .add_edge(src, tgt, make_edge(rel, 0.5 + (i % 5) as f64 * 0.1));
    }

    // Cross-links: every 10th node links to a node 50 ahead (if it exists).
    for i in (0..n).step_by(10) {
        let target_idx = i + 50;
        if target_idx < n {
            let src = graph.get_node(&ids[i]).unwrap();
            let tgt = graph.get_node(&ids[target_idx]).unwrap();
            graph
                .graph
                .add_edge(src, tgt, make_edge(CausalRelation::Supports, 0.7));
        }
    }

    (graph, ids)
}

#[test]
fn stress_1000_nodes_narrative_generation() {
    let (graph, ids) = build_large_graph(1000);

    assert_eq!(graph.node_count(), 1000);
    assert!(
        graph.edge_count() >= 999,
        "Should have at least chain edges"
    );

    let start = Instant::now();

    // Generate narratives for a sample of nodes spread across the graph.
    let sample_indices = [0, 100, 250, 499, 500, 750, 999];
    for &idx in &sample_indices {
        let narrative = NarrativeGenerator::generate(&graph, &ids[idx]);

        // Basic coherence checks.
        assert!(
            !narrative.memory_id.is_empty(),
            "Narrative should have a memory_id"
        );
        assert!(
            !narrative.summary.is_empty(),
            "Narrative should have a summary"
        );
        assert!(
            narrative.confidence >= 0.0 && narrative.confidence <= 1.0,
            "Confidence should be in [0,1], got {}",
            narrative.confidence
        );
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 10,
        "Narrative generation for 7 samples in a 1000-node graph took {:?} (>10s limit)",
        elapsed
    );
}

#[test]
fn stress_2000_nodes_no_oom() {
    let (graph, ids) = build_large_graph(2000);

    assert_eq!(graph.node_count(), 2000);

    let start = Instant::now();

    // Generate narrative for a highly-connected node (middle of chain + cross-links).
    let narrative = NarrativeGenerator::generate(&graph, &ids[500]);
    assert!(!narrative.summary.is_empty());

    // Also test a leaf node.
    let leaf_narrative = NarrativeGenerator::generate(&graph, &ids[1999]);
    assert!(!leaf_narrative.summary.is_empty());

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 10,
        "2000-node narrative generation took {:?} (>10s limit)",
        elapsed
    );
}

#[test]
fn stress_narrative_sections_are_coherent() {
    let (graph, ids) = build_large_graph(1000);

    // Pick a node in the middle that has both incoming and outgoing edges.
    let narrative = NarrativeGenerator::generate(&graph, &ids[500]);

    // A mid-chain node should have at least one section.
    assert!(
        !narrative.sections.is_empty(),
        "Mid-chain node should have narrative sections"
    );

    // Each section should have a non-empty title and at least one entry.
    for section in &narrative.sections {
        assert!(
            !section.title.is_empty(),
            "Section title should not be empty"
        );
        assert!(
            !section.entries.is_empty(),
            "Section '{}' should have entries",
            section.title
        );
        for entry in &section.entries {
            assert!(!entry.is_empty(), "Narrative entry should not be empty");
        }
    }

    // Key points should exist for connected nodes.
    assert!(
        !narrative.key_points.is_empty(),
        "Connected node should have key points"
    );
}

#[test]
fn stress_disconnected_node_graceful() {
    let mut graph = IndexedGraph::new();

    // Add 1000 nodes but NO edges.
    for i in 0..1000 {
        let id = format!("isolated_{i}");
        graph.ensure_node(&id, "episodic", &format!("Isolated memory {i}"));
    }

    let start = Instant::now();

    // Narrative for a disconnected node should still work.
    let narrative = NarrativeGenerator::generate(&graph, "isolated_500");
    assert_eq!(
        narrative.sections.len(),
        0,
        "Disconnected node should have no sections"
    );
    assert!(narrative.key_points.is_empty());
    assert!(!narrative.summary.is_empty());

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_millis() < 1000,
        "Disconnected node narrative took {:?} (should be near-instant)",
        elapsed
    );
}

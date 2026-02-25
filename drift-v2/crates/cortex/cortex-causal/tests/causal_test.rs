//! Tests for cortex-causal: T7-CAUS-01 through T7-CAUS-08.

use chrono::Utc;
use cortex_causal::graph::stable_graph::{CausalEdgeWeight, EdgeEvidence, IndexedGraph};
use cortex_causal::narrative::NarrativeGenerator;
use cortex_causal::relations::CausalRelation;
use cortex_causal::traversal::{TraversalConfig, TraversalEngine};
use cortex_causal::CausalEngine;
use cortex_core::memory::{BaseMemory, Confidence, Importance, MemoryType, TypedContent};

/// Helper to create a test memory with minimal fields.
fn make_memory(id: &str, tags: Vec<&str>) -> BaseMemory {
    let content = TypedContent::Core(cortex_core::memory::types::CoreContent {
        project_name: format!("Memory {id}"),
        description: format!("Description of {id}"),
        metadata: serde_json::Value::Null,
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: content.clone(),
        summary: format!("Summary of {id}"),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::High,
        last_accessed: Utc::now(),
        access_count: 1,
        linked_patterns: Vec::new(),
        linked_constraints: Vec::new(),
        linked_files: Vec::new(),
        linked_functions: Vec::new(),
        tags: tags.into_iter().map(String::from).collect(),
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

fn make_edge(relation: CausalRelation, strength: f64) -> CausalEdgeWeight {
    CausalEdgeWeight {
        relation,
        strength,
        evidence: vec![EdgeEvidence {
            description: "test evidence".to_string(),
            source: "test".to_string(),
            timestamp: Utc::now(),
        }],
        inferred: false,
    }
}

/// Build a linear chain: A → B → C → ... with given depth.
fn build_chain(graph: &mut IndexedGraph, depth: usize) -> Vec<String> {
    let mut ids = Vec::new();
    for i in 0..=depth {
        let id = format!("node_{i}");
        graph.ensure_node(&id, "core", &format!("Node {i}"));
        ids.push(id);
    }
    for i in 0..depth {
        graph.graph.add_edge(
            graph.get_node(&ids[i]).unwrap(),
            graph.get_node(&ids[i + 1]).unwrap(),
            make_edge(CausalRelation::Caused, 0.8),
        );
    }
    ids
}

// =============================================================================
// T7-CAUS-01: DAG enforcement — insert edge creating cycle → rejected
// =============================================================================
#[test]
fn t7_caus_01_dag_enforcement_rejects_cycle() {
    let engine = CausalEngine::new();
    let a = make_memory("a", vec![]);
    let b = make_memory("b", vec![]);
    let c = make_memory("c", vec![]);

    // A → B → C
    engine
        .add_edge(&a, &b, CausalRelation::Caused, 0.8, Vec::new(), None)
        .unwrap();
    engine
        .add_edge(&b, &c, CausalRelation::Caused, 0.8, Vec::new(), None)
        .unwrap();

    // C → A would create a cycle — must be rejected.
    let result = engine.add_edge(&c, &a, CausalRelation::Caused, 0.8, Vec::new(), None);
    assert!(result.is_err(), "Cycle should be rejected");

    // Self-loop should also be rejected.
    let result = engine.add_edge(&a, &a, CausalRelation::Caused, 0.8, Vec::new(), None);
    assert!(result.is_err(), "Self-loop should be rejected");
}

// =============================================================================
// T7-CAUS-02: Traversal depth ≤ maxDepth
// =============================================================================
#[test]
fn t7_caus_02_traversal_depth_limited() {
    let mut graph = IndexedGraph::new();
    let _ids = build_chain(&mut graph, 10);

    let config = TraversalConfig {
        max_depth: 3,
        min_strength: 0.0,
        max_nodes: 100,
    };
    let engine = TraversalEngine::new(config);
    let result = engine.trace_effects(&graph, "node_0");

    // Should only reach depth 3, not 10.
    assert!(
        result.max_depth_reached <= 3,
        "Max depth should be ≤ 3, got {}",
        result.max_depth_reached
    );
    for node in &result.nodes {
        assert!(node.depth <= 3, "Node depth {} exceeds max 3", node.depth);
    }
}

// =============================================================================
// T7-CAUS-03: Traversal nodes ≤ maxNodes
// =============================================================================
#[test]
fn t7_caus_03_traversal_nodes_limited() {
    let mut graph = IndexedGraph::new();

    // Create a wide graph: node_0 → node_1..node_100
    graph.ensure_node("node_0", "core", "Root");
    for i in 1..=100 {
        let id = format!("node_{i}");
        graph.ensure_node(&id, "core", &format!("Node {i}"));
        let src = graph.get_node("node_0").unwrap();
        let tgt = graph.get_node(&id).unwrap();
        graph
            .graph
            .add_edge(src, tgt, make_edge(CausalRelation::Caused, 0.8));
    }

    let config = TraversalConfig {
        max_depth: 5,
        min_strength: 0.0,
        max_nodes: 5,
    };
    let engine = TraversalEngine::new(config);
    let result = engine.trace_effects(&graph, "node_0");

    assert!(
        result.nodes.len() <= 5,
        "Should return ≤ 5 nodes, got {}",
        result.nodes.len()
    );
}

// =============================================================================
// T7-CAUS-04: Bidirectional = union of forward + backward
// =============================================================================
#[test]
fn t7_caus_04_bidirectional_is_union() {
    let mut graph = IndexedGraph::new();
    // A → B → C → D
    let _ids = build_chain(&mut graph, 3);

    let config = TraversalConfig {
        max_depth: 10,
        min_strength: 0.0,
        max_nodes: 100,
    };
    let engine = TraversalEngine::new(config.clone());

    // Query from B (middle node).
    let origins = engine.trace_origins(&graph, "node_1");
    let effects = engine.trace_effects(&graph, "node_1");
    let bidir = engine.bidirectional(&graph, "node_1");

    // Bidirectional should contain all nodes from both.
    let origin_ids: std::collections::HashSet<_> =
        origins.nodes.iter().map(|n| &n.memory_id).collect();
    let effect_ids: std::collections::HashSet<_> =
        effects.nodes.iter().map(|n| &n.memory_id).collect();
    let bidir_ids: std::collections::HashSet<_> =
        bidir.nodes.iter().map(|n| &n.memory_id).collect();

    let union: std::collections::HashSet<_> = origin_ids.union(&effect_ids).copied().collect();

    assert_eq!(
        bidir_ids, union,
        "Bidirectional should equal union of origins and effects"
    );
}

// =============================================================================
// T7-CAUS-05: Narrative generates readable text
// =============================================================================
#[test]
fn t7_caus_05_narrative_generates_text() {
    let mut graph = IndexedGraph::new();
    graph.ensure_node("mem_a", "core", "Adopted singleton pattern");
    graph.ensure_node("mem_b", "core", "Refactored auth module");
    graph.ensure_node("mem_c", "core", "Performance improved 2x");

    let a = graph.get_node("mem_a").unwrap();
    let b = graph.get_node("mem_b").unwrap();
    let c = graph.get_node("mem_c").unwrap();

    graph
        .graph
        .add_edge(a, b, make_edge(CausalRelation::Caused, 0.7));
    graph
        .graph
        .add_edge(b, c, make_edge(CausalRelation::Enabled, 0.6));

    let narrative = NarrativeGenerator::generate(&graph, "mem_b");

    // Should have non-empty summary and sections.
    assert!(!narrative.summary.is_empty(), "Summary should not be empty");
    assert!(
        !narrative.sections.is_empty(),
        "Should have at least one section"
    );
    assert!(!narrative.key_points.is_empty(), "Should have key points");
    assert!(narrative.confidence > 0.0, "Confidence should be > 0");

    // Check sections have content.
    for section in &narrative.sections {
        assert!(!section.title.is_empty());
        assert!(!section.entries.is_empty());
        for entry in &section.entries {
            assert!(!entry.is_empty(), "Narrative entry should not be empty");
        }
    }
}

// =============================================================================
// T7-CAUS-06: Counterfactual identifies downstream effects
// =============================================================================
#[test]
fn t7_caus_06_counterfactual_downstream_effects() {
    let engine = CausalEngine::new();
    let a = make_memory("pattern_x", vec!["pattern"]);
    let b = make_memory("module_y", vec!["module"]);
    let c = make_memory("feature_z", vec!["feature"]);

    // pattern_x → module_y → feature_z
    engine
        .add_edge(&a, &b, CausalRelation::Caused, 0.8, Vec::new(), None)
        .unwrap();
    engine
        .add_edge(&b, &c, CausalRelation::Enabled, 0.7, Vec::new(), None)
        .unwrap();

    // Counterfactual: "what if we hadn't adopted pattern_x?"
    let result = engine.counterfactual("pattern_x").unwrap();

    // Should identify module_y and feature_z as affected.
    let affected_ids: Vec<_> = result.nodes.iter().map(|n| n.memory_id.as_str()).collect();
    assert!(
        affected_ids.contains(&"module_y"),
        "module_y should be affected"
    );
    assert!(
        affected_ids.contains(&"feature_z"),
        "feature_z should be affected"
    );
}

// =============================================================================
// T7-CAUS-07: Graph rebuilds from SQLite (simulated with in-memory round-trip)
// =============================================================================
#[test]
fn t7_caus_07_graph_sync_round_trip() {
    use cortex_causal::graph::sync;

    // Build a graph with edges.
    let mut graph = IndexedGraph::new();
    graph.ensure_node("a", "core", "Node A");
    graph.ensure_node("b", "core", "Node B");

    let edge = make_edge(CausalRelation::Supports, 0.6);

    let a_idx = graph.get_node("a").unwrap();
    let b_idx = graph.get_node("b").unwrap();
    graph.graph.add_edge(a_idx, b_idx, edge.clone());

    // Convert to storage format and back.
    let storage_edge = sync::to_storage_edge("a", "b", &edge);
    let round_tripped = sync::from_storage_edge(&storage_edge);

    assert_eq!(round_tripped.relation, CausalRelation::Supports);
    assert!((round_tripped.strength - 0.6).abs() < f64::EPSILON);
    assert_eq!(round_tripped.evidence.len(), edge.evidence.len());
}

// =============================================================================
// T7-CAUS-08: Inference scorer produces valid strengths (all in 0.0–1.0)
// =============================================================================
#[test]
fn t7_caus_08_inference_scorer_valid_strengths() {
    use cortex_causal::inference::scorer;

    let m1 = make_memory("m1", vec!["rust", "async"]);
    let m2 = make_memory("m2", vec!["rust", "tokio"]);
    let m3 = make_memory("m3", vec!["python", "django"]);

    // All composite scores should be in [0.0, 1.0].
    let pairs = [(&m1, &m2), (&m1, &m3), (&m2, &m3)];
    for (a, b) in &pairs {
        let score = scorer::compute_composite(a, b);
        assert!(
            (0.0..=1.0).contains(&score),
            "Score {score} out of range for ({}, {})",
            a.id,
            b.id
        );

        let breakdown = scorer::compute_breakdown(a, b, 0.3);
        assert!(
            (0.0..=1.0).contains(&breakdown.composite),
            "Breakdown composite out of range"
        );
        for (name, raw, weighted) in &breakdown.strategy_scores {
            assert!(
                (0.0..=1.0).contains(raw),
                "Strategy {name} raw score {raw} out of range"
            );
            assert!(*weighted >= 0.0, "Strategy {name} weighted score negative");
        }
    }
}

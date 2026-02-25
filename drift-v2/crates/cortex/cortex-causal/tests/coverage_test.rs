//! Targeted coverage tests for cortex-causal uncovered paths.
//!
//! Focuses on: graph pruning, inference scorer breakdown, narrative builder,
//! narrative confidence/templates, graph sync conversions, relation methods,
//! inference engine batch, traversal edge cases.

use chrono::Utc;
use cortex_causal::graph::pruning;
use cortex_causal::graph::stable_graph::{CausalEdgeWeight, EdgeEvidence, IndexedGraph};
use cortex_causal::graph::sync;
use cortex_causal::inference::scorer;
use cortex_causal::inference::strategies;
use cortex_causal::inference::InferenceEngine;
use cortex_causal::narrative::builder;
use cortex_causal::narrative::confidence::{chain_confidence, ConfidenceLevel};
use cortex_causal::narrative::templates;
use cortex_causal::relations::CausalRelation;
use cortex_causal::CausalEngine;
use cortex_core::memory::*;
use cortex_core::traits::CausalEdge;

// ─── Helper ──────────────────────────────────────────────────────────────────

fn make_memory(id: &str, tags: Vec<&str>) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Semantic,
        content: TypedContent::Semantic(cortex_core::memory::types::SemanticContent {
            knowledge: format!("concept-{id}"),
            source_episodes: vec![],
            consolidation_confidence: 0.8,
        }),
        summary: format!("Summary for {id}"),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 1,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: tags.into_iter().map(String::from).collect(),
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: format!("hash-{id}"),
    }
}

fn make_edge(relation: CausalRelation, strength: f64) -> CausalEdgeWeight {
    CausalEdgeWeight {
        relation,
        strength,
        evidence: vec![],
        inferred: false,
    }
}

fn make_inferred_edge(relation: CausalRelation, strength: f64) -> CausalEdgeWeight {
    CausalEdgeWeight {
        relation,
        strength,
        evidence: vec![],
        inferred: true,
    }
}

// ─── Graph Pruning ───────────────────────────────────────────────────────────

#[test]
fn prune_weak_edges_removes_below_threshold() {
    let mut graph = IndexedGraph::new();
    let a = graph.ensure_node("a", "domain_agnostic", "Node A");
    let b = graph.ensure_node("b", "domain_agnostic", "Node B");
    let c = graph.ensure_node("c", "domain_agnostic", "Node C");

    graph
        .graph
        .add_edge(a, b, make_edge(CausalRelation::Supports, 0.1));
    graph
        .graph
        .add_edge(b, c, make_edge(CausalRelation::Caused, 0.8));

    let result = pruning::prune_weak_edges(&mut graph, 0.2);
    assert_eq!(result.edges_removed, 1);
    // Node A should be orphaned and removed.
    assert!(result.nodes_removed >= 1);
}

#[test]
fn prune_unvalidated_inferred_removes_empty_evidence() {
    let mut graph = IndexedGraph::new();
    let a = graph.ensure_node("a", "domain_agnostic", "A");
    let b = graph.ensure_node("b", "domain_agnostic", "B");
    let c = graph.ensure_node("c", "domain_agnostic", "C");

    // Inferred with no evidence — should be pruned.
    graph
        .graph
        .add_edge(a, b, make_inferred_edge(CausalRelation::Supports, 0.5));
    // Non-inferred — should stay.
    graph
        .graph
        .add_edge(b, c, make_edge(CausalRelation::Caused, 0.5));

    let removed = pruning::prune_unvalidated_inferred(&mut graph);
    assert_eq!(removed, 1);
}

#[test]
fn prune_keeps_inferred_with_evidence() {
    let mut graph = IndexedGraph::new();
    let a = graph.ensure_node("a", "domain_agnostic", "A");
    let b = graph.ensure_node("b", "domain_agnostic", "B");

    let mut edge = make_inferred_edge(CausalRelation::Supports, 0.5);
    edge.evidence.push(EdgeEvidence {
        description: "validated".to_string(),
        source: "test".to_string(),
        timestamp: Utc::now(),
    });
    graph.graph.add_edge(a, b, edge);

    let removed = pruning::prune_unvalidated_inferred(&mut graph);
    assert_eq!(removed, 0);
}

#[test]
fn full_cleanup_combines_weak_and_unvalidated() {
    let mut graph = IndexedGraph::new();
    let a = graph.ensure_node("a", "domain_agnostic", "A");
    let b = graph.ensure_node("b", "domain_agnostic", "B");
    let c = graph.ensure_node("c", "domain_agnostic", "C");
    let d = graph.ensure_node("d", "domain_agnostic", "D");

    // Weak edge.
    graph
        .graph
        .add_edge(a, b, make_edge(CausalRelation::Supports, 0.05));
    // Unvalidated inferred.
    graph
        .graph
        .add_edge(c, d, make_inferred_edge(CausalRelation::Enabled, 0.9));

    let result = pruning::full_cleanup(&mut graph, 0.2);
    assert_eq!(result.edges_removed, 2);
}

// ─── Inference Scorer ────────────────────────────────────────────────────────

#[test]
fn compute_composite_returns_bounded_value() {
    let a = make_memory("s1", vec!["rust"]);
    let b = make_memory("s2", vec!["rust"]);
    let score = scorer::compute_composite(&a, &b);
    assert!((0.0..=1.0).contains(&score));
}

#[test]
fn compute_breakdown_has_all_strategies() {
    let a = make_memory("b1", vec!["test"]);
    let b = make_memory("b2", vec!["test"]);
    let breakdown = scorer::compute_breakdown(&a, &b, 0.3);
    assert_eq!(breakdown.strategy_scores.len(), 6); // 6 strategies
    assert!(breakdown.composite >= 0.0 && breakdown.composite <= 1.0);
}

#[test]
fn should_create_edge_respects_threshold() {
    let a = make_memory("t1", vec![]);
    let b = make_memory("t2", vec![]);
    // With threshold 0.0, should always create.
    assert!(scorer::should_create_edge(&a, &b, 0.0));
    // With threshold 1.0, should never create (unless perfect match).
    // Unrelated memories won't score 1.0.
    assert!(!scorer::should_create_edge(&a, &b, 1.0));
}

#[test]
fn strategies_total_weight_positive() {
    let total = strategies::total_weight();
    assert!(total > 0.0);
}

#[test]
fn all_strategies_have_names() {
    let strats = strategies::all_strategies();
    assert_eq!(strats.len(), 6);
    for s in &strats {
        assert!(!s.name.is_empty());
        assert!(s.weight > 0.0);
    }
}

// ─── Inference Engine ────────────────────────────────────────────────────────

#[test]
fn inference_engine_default_threshold() {
    let engine = InferenceEngine::new();
    assert_eq!(engine.threshold(), scorer::DEFAULT_EDGE_THRESHOLD);
}

#[test]
fn inference_engine_custom_threshold() {
    let engine = InferenceEngine::with_threshold(0.5);
    assert_eq!(engine.threshold(), 0.5);
}

#[test]
fn inference_engine_infer_returns_result() {
    let engine = InferenceEngine::new();
    let a = make_memory("ie1", vec!["rust"]);
    let b = make_memory("ie2", vec!["rust"]);
    let result = engine.infer(&a, &b);
    assert_eq!(result.source_id, "ie1");
    assert_eq!(result.target_id, "ie2");
    assert!(result.strength >= 0.0);
}

#[test]
fn inference_engine_batch_filters_self() {
    let engine = InferenceEngine::with_threshold(0.0);
    let source = make_memory("batch-src", vec!["test"]);
    let candidates = vec![
        make_memory("batch-src", vec!["test"]), // same ID — should be filtered
        make_memory("batch-c1", vec!["test"]),
    ];
    let results = engine.infer_batch(&source, &candidates);
    // Should not include self-match.
    assert!(results.iter().all(|r| r.target_id != "batch-src"));
}

// ─── Narrative Confidence ────────────────────────────────────────────────────

#[test]
fn chain_confidence_empty_is_zero() {
    assert_eq!(chain_confidence(&[], 1), 0.0);
}

#[test]
fn chain_confidence_single_edge() {
    let c = chain_confidence(&[0.8], 1);
    // 0.6 * 0.8 + 0.4 * 0.8 = 0.8, * 0.95^1 = 0.76
    assert!((c - 0.76).abs() < 1e-6);
}

#[test]
fn chain_confidence_depth_penalty() {
    let shallow = chain_confidence(&[0.8], 1);
    let deep = chain_confidence(&[0.8], 5);
    assert!(shallow > deep, "deeper chains should have lower confidence");
}

#[test]
fn confidence_level_classification() {
    assert_eq!(ConfidenceLevel::from_score(0.9), ConfidenceLevel::High);
    assert_eq!(ConfidenceLevel::from_score(0.6), ConfidenceLevel::Medium);
    assert_eq!(ConfidenceLevel::from_score(0.35), ConfidenceLevel::Low);
    assert_eq!(ConfidenceLevel::from_score(0.1), ConfidenceLevel::VeryLow);
}

#[test]
fn confidence_level_as_str() {
    assert_eq!(ConfidenceLevel::High.as_str(), "high");
    assert_eq!(ConfidenceLevel::Medium.as_str(), "medium");
    assert_eq!(ConfidenceLevel::Low.as_str(), "low");
    assert_eq!(ConfidenceLevel::VeryLow.as_str(), "very low");
}

// ─── Narrative Templates ─────────────────────────────────────────────────────

#[test]
fn template_render_all_relations() {
    for relation in CausalRelation::ALL {
        let rendered = templates::render(relation, "source-summary", "target-summary");
        assert!(!rendered.is_empty());
        assert!(
            rendered.contains("source-summary") || rendered.contains("target-summary"),
            "template for {relation:?} should contain placeholders"
        );
    }
}

#[test]
fn section_headers_cover_all_relations() {
    for relation in CausalRelation::ALL {
        let header = templates::section_header(relation);
        assert!(
            ["Origins", "Support", "Conflicts", "Effects"].contains(&header),
            "unexpected section header: {header}"
        );
    }
}

// ─── Narrative Builder ───────────────────────────────────────────────────────

#[test]
fn narrative_for_missing_node_returns_empty() {
    let graph = IndexedGraph::new();
    let narrative = builder::build_narrative(&graph, "nonexistent");
    assert_eq!(narrative.memory_id, "nonexistent");
    assert!(narrative.sections.is_empty());
    assert_eq!(narrative.confidence, 0.0);
}

#[test]
fn narrative_for_isolated_node() {
    let mut graph = IndexedGraph::new();
    graph.ensure_node("isolated", "domain_agnostic", "Isolated node");
    let narrative = builder::build_narrative(&graph, "isolated");
    assert_eq!(narrative.memory_id, "isolated");
    assert!(narrative.sections.is_empty());
    assert!(narrative.summary.contains("No causal relationships"));
}

#[test]
fn narrative_with_edges_has_sections() {
    let mut graph = IndexedGraph::new();
    let a = graph.ensure_node("origin", "domain_agnostic", "Origin memory");
    let b = graph.ensure_node("target", "domain_agnostic", "Target memory");
    graph
        .graph
        .add_edge(a, b, make_edge(CausalRelation::Caused, 0.9));

    let narrative = builder::build_narrative(&graph, "target");
    assert!(!narrative.sections.is_empty());
    assert!(!narrative.key_points.is_empty());
    assert!(narrative.confidence > 0.0);
}

// ─── Graph Sync Conversions ──────────────────────────────────────────────────

#[test]
fn to_storage_edge_and_back() {
    let weight = CausalEdgeWeight {
        relation: CausalRelation::DerivedFrom,
        strength: 0.75,
        evidence: vec![EdgeEvidence {
            description: "test evidence".to_string(),
            source: "unit-test".to_string(),
            timestamp: Utc::now(),
        }],
        inferred: false,
    };

    let storage_edge = sync::to_storage_edge("src", "tgt", &weight);
    assert_eq!(storage_edge.source_id, "src");
    assert_eq!(storage_edge.target_id, "tgt");
    assert_eq!(storage_edge.relation, "derived_from");
    assert_eq!(storage_edge.strength, 0.75);
    assert_eq!(storage_edge.evidence.len(), 1);

    let restored = sync::from_storage_edge(&storage_edge);
    assert_eq!(restored.relation, CausalRelation::DerivedFrom);
    assert_eq!(restored.strength, 0.75);
    assert_eq!(restored.evidence.len(), 1);
}

#[test]
fn from_storage_edge_unknown_relation_defaults_to_supports() {
    let edge = CausalEdge {
        source_id: "a".to_string(),
        target_id: "b".to_string(),
        relation: "unknown_relation".to_string(),
        strength: 0.5,
        evidence: vec![],
        source_agent: None,
    };
    let weight = sync::from_storage_edge(&edge);
    assert_eq!(weight.relation, CausalRelation::Supports);
}

// ─── CausalRelation Methods ─────────────────────────────────────────────────

#[test]
fn relation_count_is_8() {
    assert_eq!(CausalRelation::COUNT, 8);
    assert_eq!(CausalRelation::ALL.len(), 8);
}

#[test]
fn relation_min_evidence() {
    assert_eq!(CausalRelation::Caused.min_evidence(), 2);
    assert_eq!(CausalRelation::Prevented.min_evidence(), 2);
    assert_eq!(CausalRelation::Supports.min_evidence(), 1);
    assert_eq!(CausalRelation::Contradicts.min_evidence(), 1);
}

#[test]
fn relation_min_strength() {
    assert_eq!(CausalRelation::Caused.min_strength(), 0.5);
    assert_eq!(CausalRelation::Supports.min_strength(), 0.2);
    assert_eq!(CausalRelation::Supersedes.min_strength(), 0.6);
}

#[test]
fn relation_is_strong_dependency() {
    assert!(CausalRelation::Caused.is_strong_dependency());
    assert!(CausalRelation::Supersedes.is_strong_dependency());
    assert!(CausalRelation::DerivedFrom.is_strong_dependency());
    assert!(!CausalRelation::Supports.is_strong_dependency());
    assert!(!CausalRelation::Contradicts.is_strong_dependency());
}

#[test]
fn relation_from_str_name_all_variants() {
    for relation in CausalRelation::ALL {
        let name = relation.as_str();
        let parsed = CausalRelation::from_str_name(name);
        assert_eq!(parsed, Some(relation), "roundtrip failed for {name}");
    }
}

#[test]
fn relation_from_str_name_invalid() {
    assert_eq!(CausalRelation::from_str_name("bogus"), None);
}

#[test]
fn relation_display() {
    assert_eq!(format!("{}", CausalRelation::Caused), "caused");
    assert_eq!(format!("{}", CausalRelation::TriggeredBy), "triggered_by");
}

// ─── CausalEngine: traversal on empty graph ──────────────────────────────────

#[test]
fn engine_trace_origins_missing_node() {
    let engine = CausalEngine::new();
    let result = engine.trace_origins("nonexistent").unwrap();
    assert!(result.nodes.is_empty());
}

#[test]
fn engine_trace_effects_missing_node() {
    let engine = CausalEngine::new();
    let result = engine.trace_effects("nonexistent").unwrap();
    assert!(result.nodes.is_empty());
}

#[test]
fn engine_bidirectional_missing_node() {
    let engine = CausalEngine::new();
    let result = engine.bidirectional("nonexistent").unwrap();
    assert!(result.nodes.is_empty());
}

#[test]
fn engine_neighbors_missing_node() {
    let engine = CausalEngine::new();
    let result = engine.neighbors("nonexistent").unwrap();
    assert!(result.nodes.is_empty());
}

#[test]
fn engine_counterfactual_missing_node() {
    let engine = CausalEngine::new();
    let result = engine.counterfactual("nonexistent").unwrap();
    assert!(result.nodes.is_empty());
}

#[test]
fn engine_intervention_missing_node() {
    let engine = CausalEngine::new();
    let result = engine.intervention("nonexistent").unwrap();
    assert!(result.nodes.is_empty());
}

#[test]
fn engine_narrative_missing_node() {
    let engine = CausalEngine::new();
    let narrative = engine.narrative("nonexistent").unwrap();
    assert!(narrative.sections.is_empty());
}

#[test]
fn engine_stats_empty_graph() {
    let engine = CausalEngine::new();
    let (nodes, edges) = engine.stats().unwrap();
    assert_eq!(nodes, 0);
    assert_eq!(edges, 0);
}

#[test]
fn engine_prune_empty_graph() {
    let engine = CausalEngine::new();
    let result = engine.prune(0.2).unwrap();
    assert_eq!(result.edges_removed, 0);
    assert_eq!(result.nodes_removed, 0);
}

#[test]
fn engine_add_and_remove_edge() {
    let engine = CausalEngine::new();
    let a = make_memory("ea", vec![]);
    let b = make_memory("eb", vec![]);

    engine
        .add_edge(&a, &b, CausalRelation::Supports, 0.7, vec![], None)
        .unwrap();

    let (nodes, edges) = engine.stats().unwrap();
    assert_eq!(nodes, 2);
    assert_eq!(edges, 1);

    let removed = engine.remove_edge("ea", "eb", None).unwrap();
    assert!(removed);

    let (_, edges) = engine.stats().unwrap();
    assert_eq!(edges, 0);
}

#[test]
fn engine_infer_returns_result() {
    let engine = CausalEngine::new();
    let a = make_memory("inf-a", vec!["rust"]);
    let b = make_memory("inf-b", vec!["rust"]);
    let result = engine.infer(&a, &b);
    assert_eq!(result.source_id, "inf-a");
    assert_eq!(result.target_id, "inf-b");
}

#[test]
fn engine_with_config() {
    let config = cortex_causal::traversal::TraversalConfig {
        max_depth: 3,
        min_strength: 0.1,
        max_nodes: 50,
    };
    let engine = CausalEngine::with_config(0.5, config);
    let (nodes, edges) = engine.stats().unwrap();
    assert_eq!(nodes, 0);
    assert_eq!(edges, 0);
}

// ─── Inference Strategies: Entity Overlap ────────────────────────────────────

#[test]
fn entity_overlap_no_links() {
    let a = make_memory("eo1", vec![]);
    let b = make_memory("eo2", vec![]);
    let score = cortex_causal::inference::strategies::entity_overlap::score(&a, &b);
    assert_eq!(score, 0.0);
}

#[test]
fn entity_overlap_shared_files() {
    let mut a = make_memory("eo3", vec![]);
    a.linked_files = vec![cortex_core::memory::links::FileLink {
        file_path: "src/auth.rs".to_string(),
        line_start: None,
        line_end: None,
        content_hash: None,
    }];
    let mut b = make_memory("eo4", vec![]);
    b.linked_files = vec![cortex_core::memory::links::FileLink {
        file_path: "src/auth.rs".to_string(),
        line_start: None,
        line_end: None,
        content_hash: None,
    }];
    let score = cortex_causal::inference::strategies::entity_overlap::score(&a, &b);
    assert!(score > 0.0);
}

#[test]
fn entity_overlap_shared_functions() {
    let mut a = make_memory("eo5", vec![]);
    a.linked_functions = vec![cortex_core::memory::links::FunctionLink {
        function_name: "authenticate".to_string(),
        file_path: "src/auth.rs".to_string(),
        signature: None,
    }];
    let mut b = make_memory("eo6", vec![]);
    b.linked_functions = vec![cortex_core::memory::links::FunctionLink {
        function_name: "authenticate".to_string(),
        file_path: "src/auth.rs".to_string(),
        signature: None,
    }];
    let score = cortex_causal::inference::strategies::entity_overlap::score(&a, &b);
    assert!(score > 0.0);
}

#[test]
fn entity_overlap_shared_patterns() {
    let mut a = make_memory("eo7", vec![]);
    a.linked_patterns = vec![cortex_core::memory::links::PatternLink {
        pattern_id: "p1".to_string(),
        pattern_name: "singleton".to_string(),
    }];
    let mut b = make_memory("eo8", vec![]);
    b.linked_patterns = vec![cortex_core::memory::links::PatternLink {
        pattern_id: "p1".to_string(),
        pattern_name: "singleton".to_string(),
    }];
    let score = cortex_causal::inference::strategies::entity_overlap::score(&a, &b);
    assert!(score > 0.0);
}

// ─── Inference Strategies: File Co-occurrence ────────────────────────────────

#[test]
fn file_co_occurrence_no_files() {
    let a = make_memory("fc1", vec![]);
    let b = make_memory("fc2", vec![]);
    let score = cortex_causal::inference::strategies::file_co_occurrence::score(&a, &b);
    assert_eq!(score, 0.0);
}

#[test]
fn file_co_occurrence_shared_file() {
    let mut a = make_memory("fc3", vec![]);
    a.linked_files = vec![cortex_core::memory::links::FileLink {
        file_path: "src/main.rs".to_string(),
        line_start: None,
        line_end: None,
        content_hash: None,
    }];
    let mut b = make_memory("fc4", vec![]);
    b.linked_files = vec![cortex_core::memory::links::FileLink {
        file_path: "src/main.rs".to_string(),
        line_start: None,
        line_end: None,
        content_hash: None,
    }];
    let score = cortex_causal::inference::strategies::file_co_occurrence::score(&a, &b);
    assert!((score - 1.0).abs() < 0.01); // Perfect overlap.
}

// ─── Inference Strategies: Pattern Matching ──────────────────────────────────

#[test]
fn pattern_matching_no_patterns() {
    let a = make_memory("pm1", vec![]);
    let b = make_memory("pm2", vec![]);
    let score = cortex_causal::inference::strategies::pattern_matching::score(&a, &b);
    assert_eq!(score, 0.0);
}

#[test]
fn pattern_matching_shared_pattern() {
    let mut a = make_memory("pm3", vec![]);
    a.linked_patterns = vec![cortex_core::memory::links::PatternLink {
        pattern_id: "p1".to_string(),
        pattern_name: "observer".to_string(),
    }];
    let mut b = make_memory("pm4", vec![]);
    b.linked_patterns = vec![cortex_core::memory::links::PatternLink {
        pattern_id: "p1".to_string(),
        pattern_name: "observer".to_string(),
    }];
    let score = cortex_causal::inference::strategies::pattern_matching::score(&a, &b);
    assert!(score > 0.0);
}

#[test]
fn pattern_matching_multiple_shared_patterns_boost() {
    let mut a = make_memory("pm5", vec![]);
    a.linked_patterns = vec![
        cortex_core::memory::links::PatternLink {
            pattern_id: "p1".to_string(),
            pattern_name: "observer".to_string(),
        },
        cortex_core::memory::links::PatternLink {
            pattern_id: "p2".to_string(),
            pattern_name: "factory".to_string(),
        },
    ];
    let mut b = make_memory("pm6", vec![]);
    b.linked_patterns = vec![
        cortex_core::memory::links::PatternLink {
            pattern_id: "p1".to_string(),
            pattern_name: "observer".to_string(),
        },
        cortex_core::memory::links::PatternLink {
            pattern_id: "p2".to_string(),
            pattern_name: "factory".to_string(),
        },
    ];
    let score = cortex_causal::inference::strategies::pattern_matching::score(&a, &b);
    // Should be higher than single pattern due to multi-boost.
    assert!(score > 0.5);
}

// ─── Traversal: Neighbors ────────────────────────────────────────────────────

#[test]
fn traversal_neighbors_on_graph() {
    use cortex_causal::traversal::TraversalConfig;
    // Use with_config to set a low min_strength so edges are followed.
    let config = TraversalConfig {
        max_depth: 3,
        min_strength: 0.3,
        max_nodes: 50,
    };
    let engine = CausalEngine::with_config(0.1, config);

    let n1 = make_memory("n1", vec!["tag"]);
    let n2 = make_memory("n2", vec!["tag"]);
    let n3 = make_memory("n3", vec!["tag"]);

    engine
        .add_edge(&n1, &n2, CausalRelation::Caused, 0.8, vec![], None)
        .unwrap();
    engine
        .add_edge(&n3, &n1, CausalRelation::Supports, 0.7, vec![], None)
        .unwrap();

    let result = engine.neighbors("n1").unwrap();
    // n1 has outgoing to n2 and incoming from n3.
    assert!(!result.nodes.is_empty());
    assert_eq!(result.origin_id, "n1");
}

// ─── Traversal: Intervention ─────────────────────────────────────────────────

#[test]
fn traversal_intervention_analysis() {
    use cortex_causal::traversal::TraversalConfig;
    let config = TraversalConfig {
        max_depth: 5,
        min_strength: 0.3,
        max_nodes: 50,
    };
    let engine = CausalEngine::with_config(0.1, config);

    let i0 = make_memory("i0", vec!["tag"]);
    let i1 = make_memory("i1", vec!["tag"]);
    let i2 = make_memory("i2", vec!["tag"]);
    let i3 = make_memory("i3", vec!["tag"]);

    engine
        .add_edge(&i1, &i2, CausalRelation::Caused, 0.9, vec![], None)
        .unwrap();
    engine
        .add_edge(&i2, &i3, CausalRelation::Caused, 0.8, vec![], None)
        .unwrap();
    engine
        .add_edge(&i0, &i1, CausalRelation::Supports, 0.7, vec![], None)
        .unwrap();

    let result = engine.intervention("i1").unwrap();
    // Should include both upstream (i0) and downstream (i2, i3).
    assert!(result.nodes.len() >= 2);
    assert_eq!(result.origin_id, "i1");
}

// ─── Traversal: Trace Origins with edges ─────────────────────────────────────

#[test]
fn traversal_trace_origins_with_edges() {
    use cortex_causal::traversal::TraversalConfig;
    let config = TraversalConfig {
        max_depth: 5,
        min_strength: 0.2,
        max_nodes: 50,
    };
    let engine = CausalEngine::with_config(0.1, config);

    let a = make_memory("a", vec!["tag"]);
    let b = make_memory("b", vec!["tag"]);
    let c = make_memory("c", vec!["tag"]);

    engine
        .add_edge(&a, &b, CausalRelation::Caused, 0.9, vec![], None)
        .unwrap();
    engine
        .add_edge(&b, &c, CausalRelation::Enabled, 0.8, vec![], None)
        .unwrap();

    // Trace origins of c: should find b (and possibly a).
    let result = engine.trace_origins("c").unwrap();
    assert_eq!(result.origin_id, "c");
    assert!(!result.nodes.is_empty());
}

// ─── Traversal: Trace Effects with edges ─────────────────────────────────────

#[test]
fn traversal_trace_effects_with_edges() {
    use cortex_causal::traversal::TraversalConfig;
    let config = TraversalConfig {
        max_depth: 5,
        min_strength: 0.2,
        max_nodes: 50,
    };
    let engine = CausalEngine::with_config(0.1, config);

    let a = make_memory("a2", vec!["tag"]);
    let b = make_memory("b2", vec!["tag"]);
    let c = make_memory("c2", vec!["tag"]);

    engine
        .add_edge(&a, &b, CausalRelation::Caused, 0.9, vec![], None)
        .unwrap();
    engine
        .add_edge(&b, &c, CausalRelation::Enabled, 0.8, vec![], None)
        .unwrap();

    // Trace effects of a: should find b and c.
    let result = engine.trace_effects("a2").unwrap();
    assert_eq!(result.origin_id, "a2");
    assert!(!result.nodes.is_empty());
}

// ─── Traversal: Bidirectional with edges ─────────────────────────────────────

#[test]
fn traversal_bidirectional_with_edges() {
    use cortex_causal::traversal::TraversalConfig;
    let config = TraversalConfig {
        max_depth: 5,
        min_strength: 0.2,
        max_nodes: 50,
    };
    let engine = CausalEngine::with_config(0.1, config);

    let x = make_memory("x1", vec!["tag"]);
    let y = make_memory("y1", vec!["tag"]);
    let z = make_memory("z1", vec!["tag"]);

    engine
        .add_edge(&x, &y, CausalRelation::Caused, 0.9, vec![], None)
        .unwrap();
    engine
        .add_edge(&y, &z, CausalRelation::Enabled, 0.8, vec![], None)
        .unwrap();

    // Bidirectional from y: should find both x (origin) and z (effect).
    let result = engine.bidirectional("y1").unwrap();
    assert_eq!(result.origin_id, "y1");
    assert!(!result.nodes.is_empty());
}

// ─── Traversal: Counterfactual with edges ────────────────────────────────────

#[test]
fn traversal_counterfactual_with_edges() {
    use cortex_causal::traversal::TraversalConfig;
    let config = TraversalConfig {
        max_depth: 5,
        min_strength: 0.2,
        max_nodes: 50,
    };
    let engine = CausalEngine::with_config(0.1, config);

    let p = make_memory("p1", vec!["tag"]);
    let q = make_memory("q1", vec!["tag"]);

    engine
        .add_edge(&p, &q, CausalRelation::Caused, 0.9, vec![], None)
        .unwrap();

    let result = engine.counterfactual("p1").unwrap();
    assert_eq!(result.origin_id, "p1");
}

// ─── GraphManager: add_node, get_edges, from_graph ───────────────────────────

#[test]
fn graph_manager_add_node() {
    let gm = cortex_causal::GraphManager::new();
    let added = gm.add_node("mem1", "semantic", "A memory").unwrap();
    assert!(added);
    // Adding same node again returns false.
    let added2 = gm.add_node("mem1", "semantic", "A memory").unwrap();
    assert!(!added2);
    assert_eq!(gm.node_count().unwrap(), 1);
}

#[test]
fn graph_manager_get_edges() {
    let gm = cortex_causal::GraphManager::new();
    let weight = CausalEdgeWeight {
        relation: CausalRelation::Caused,
        strength: 0.9,
        evidence: vec![],
        inferred: false,
    };
    gm.add_edge("src", "tgt", "semantic", "semantic", weight)
        .unwrap();

    let edges = gm.get_edges("src").unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].0, "src");
    assert_eq!(edges[0].1, "tgt");
    assert_eq!(edges[0].2.relation, CausalRelation::Caused);

    // Also check incoming edges from target's perspective.
    let edges_tgt = gm.get_edges("tgt").unwrap();
    assert_eq!(edges_tgt.len(), 1);
    assert_eq!(edges_tgt[0].0, "src");
    assert_eq!(edges_tgt[0].1, "tgt");
}

#[test]
fn graph_manager_get_edges_missing_node() {
    let gm = cortex_causal::GraphManager::new();
    let edges = gm.get_edges("nonexistent").unwrap();
    assert!(edges.is_empty());
}

#[test]
fn graph_manager_from_graph() {
    let mut ig = IndexedGraph::new();
    ig.ensure_node("n1", "semantic", "Node 1");
    ig.ensure_node("n2", "semantic", "Node 2");
    let gm = cortex_causal::GraphManager::from_graph(ig);
    assert_eq!(gm.node_count().unwrap(), 2);
}

#[test]
fn graph_manager_clone_shares_state() {
    let gm = cortex_causal::GraphManager::new();
    gm.add_node("shared", "semantic", "Shared node").unwrap();
    let gm2 = gm.clone();
    assert_eq!(gm2.node_count().unwrap(), 1);
}

#[test]
fn graph_manager_remove_edge_missing() {
    let gm = cortex_causal::GraphManager::new();
    // Remove from nonexistent nodes.
    let removed = gm.remove_edge("a", "b").unwrap();
    assert!(!removed);
}

// ─── DAG Enforcement ─────────────────────────────────────────────────────────

#[test]
fn dag_enforcement_rejects_cycle() {
    let engine = CausalEngine::new();
    let a = make_memory("cyc_a", vec![]);
    let b = make_memory("cyc_b", vec![]);
    let c = make_memory("cyc_c", vec![]);

    engine
        .add_edge(&a, &b, CausalRelation::Caused, 0.9, vec![], None)
        .unwrap();
    engine
        .add_edge(&b, &c, CausalRelation::Caused, 0.8, vec![], None)
        .unwrap();
    // c -> a would create a cycle.
    let result = engine.add_edge(&c, &a, CausalRelation::Caused, 0.7, vec![], None);
    assert!(result.is_err());
}

#[test]
fn dag_enforcement_self_loop_rejected() {
    let gm = cortex_causal::GraphManager::new();
    let weight = make_edge(CausalRelation::Caused, 0.9);
    // Self-loop: same source and target.
    let result = gm.add_edge("self", "self", "semantic", "semantic", weight);
    assert!(result.is_err());
}

#[test]
fn dag_enforcement_find_cycles_empty() {
    use cortex_causal::graph::dag_enforcement;
    let ig = IndexedGraph::new();
    let cycles = dag_enforcement::find_cycles(&ig);
    assert!(cycles.is_empty());
}

// ─── IndexedGraph: remove_node ───────────────────────────────────────────────

#[test]
fn indexed_graph_remove_node() {
    let mut ig = IndexedGraph::new();
    ig.ensure_node("rm1", "semantic", "To remove");
    assert_eq!(ig.node_count(), 1);
    let removed = ig.remove_node("rm1");
    assert!(removed);
    assert_eq!(ig.node_count(), 0);
    // Removing again returns false.
    let removed2 = ig.remove_node("rm1");
    assert!(!removed2);
}

// ─── Engine: infer_and_connect ───────────────────────────────────────────────

#[test]
fn engine_infer_and_connect() {
    let engine = CausalEngine::with_config(0.01, cortex_causal::TraversalConfig::default());
    let source = make_memory("inf_src", vec!["rust", "async"]);
    let c1 = make_memory("inf_c1", vec!["rust", "async"]);
    let c2 = make_memory("inf_c2", vec!["python", "ml"]);

    let results = engine.infer_and_connect(&source, &[c1, c2], None).unwrap();
    // Should have results for candidates (excluding self).
    assert!(!results.is_empty());
    // At least one edge should have been added to the graph.
    let (nodes, _edges) = engine.stats().unwrap();
    assert!(nodes >= 1);
}

// ─── Engine: add_edge with evidence ──────────────────────────────────────────

#[test]
fn engine_add_edge_with_evidence() {
    let engine = CausalEngine::new();
    let a = make_memory("ev_a", vec![]);
    let b = make_memory("ev_b", vec![]);

    let evidence = vec![
        EdgeEvidence {
            description: "Observed in logs".to_string(),
            source: "log_analysis".to_string(),
            timestamp: Utc::now(),
        },
        EdgeEvidence {
            description: "User confirmed".to_string(),
            source: "user_feedback".to_string(),
            timestamp: Utc::now(),
        },
    ];

    engine
        .add_edge(&a, &b, CausalRelation::Caused, 0.9, evidence, None)
        .unwrap();
    let (_, edge_count) = engine.stats().unwrap();
    assert_eq!(edge_count, 1);
}

// ─── Engine: narrative with edges ────────────────────────────────────────────

#[test]
fn engine_narrative_with_edges() {
    let engine = CausalEngine::new();
    let a = make_memory("narr_a", vec![]);
    let b = make_memory("narr_b", vec![]);

    engine
        .add_edge(&a, &b, CausalRelation::Caused, 0.9, vec![], None)
        .unwrap();

    let narrative = engine.narrative("narr_a").unwrap();
    // Narrative for a node with edges should have sections.
    assert_eq!(narrative.memory_id, "narr_a");
}

// ─── Inference: suggest_relation coverage ────────────────────────────────────

#[test]
fn inference_supersedes_relation() {
    let mut source = make_memory("sup_src", vec![]);
    source.supersedes = Some("sup_tgt".to_string());
    let target = make_memory("sup_tgt", vec![]);

    let engine = InferenceEngine::new();
    let result = engine.infer(&source, &target);
    assert_eq!(result.suggested_relation, CausalRelation::Supersedes);
}

#[test]
fn inference_triggered_by_close_time() {
    use chrono::Duration;
    let mut source = make_memory("trig_src", vec![]);
    let mut target = make_memory("trig_tgt", vec![]);
    // Source created 60 seconds after target, different type.
    target.transaction_time = Utc::now() - Duration::seconds(60);
    source.transaction_time = Utc::now();
    source.memory_type = MemoryType::Episodic;
    target.memory_type = MemoryType::Semantic;

    let engine = InferenceEngine::new();
    let result = engine.infer(&source, &target);
    assert_eq!(result.suggested_relation, CausalRelation::TriggeredBy);
}

#[test]
fn inference_derived_from_same_type() {
    use chrono::Duration;
    let mut source = make_memory("der_src", vec![]);
    let mut target = make_memory("der_tgt", vec![]);
    // Source created after target, same type.
    target.transaction_time = Utc::now() - Duration::seconds(600);
    source.transaction_time = Utc::now();

    let engine = InferenceEngine::new();
    let result = engine.infer(&source, &target);
    assert_eq!(result.suggested_relation, CausalRelation::DerivedFrom);
}

// ─── Inference: batch with threshold filtering ───────────────────────────────

#[test]
fn inference_batch_high_threshold_filters_all() {
    let engine = InferenceEngine::with_threshold(1.0);
    let source = make_memory("batch_src", vec!["a"]);
    let c1 = make_memory("batch_c1", vec!["b"]);
    let c2 = make_memory("batch_c2", vec!["c"]);

    let results = engine.infer_batch(&source, &[c1, c2]);
    // With threshold 1.0, nothing should pass.
    assert!(results.is_empty());
}

#[test]
fn inference_engine_threshold_getter() {
    let engine = InferenceEngine::with_threshold(0.42);
    assert!((engine.threshold() - 0.42).abs() < f64::EPSILON);
}

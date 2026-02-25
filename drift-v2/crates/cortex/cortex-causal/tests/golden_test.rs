//! Golden dataset tests for cortex-causal (T14-INT-09).
//!
//! Loads each of the 5 causal golden files, builds graphs,
//! runs traversal/narrative, and verifies output matches expected results.

use cortex_causal::graph::stable_graph::EdgeEvidence;
use cortex_causal::relations::CausalRelation;
use cortex_causal::CausalEngine;
use cortex_core::memory::{BaseMemory, Confidence, Importance, MemoryType, TypedContent};
use serde_json::Value;
use test_fixtures::load_fixture_value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_memory(id: &str, summary: &str) -> BaseMemory {
    let content = TypedContent::Core(cortex_core::memory::types::CoreContent {
        project_name: String::new(),
        description: summary.to_string(),
        metadata: serde_json::Value::Null,
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: content.clone(),
        summary: summary.to_string(),
        transaction_time: chrono::Utc::now(),
        valid_time: chrono::Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::High,
        last_accessed: chrono::Utc::now(),
        access_count: 1,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

fn parse_relation(s: &str) -> CausalRelation {
    match s {
        "caused" => CausalRelation::Caused,
        "enabled" => CausalRelation::Enabled,
        "prevented" => CausalRelation::Prevented,
        "contradicts" => CausalRelation::Contradicts,
        "supersedes" => CausalRelation::Supersedes,
        "supports" => CausalRelation::Supports,
        "derived_from" => CausalRelation::DerivedFrom,
        "triggered_by" => CausalRelation::TriggeredBy,
        _ => CausalRelation::Caused,
    }
}

fn parse_evidence(edge: &Value) -> Vec<EdgeEvidence> {
    edge["evidence"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|e| EdgeEvidence {
                    description: e["description"].as_str().unwrap_or("").to_string(),
                    source: e["source"].as_str().unwrap_or("").to_string(),
                    timestamp: e["timestamp"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or_else(chrono::Utc::now),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn add_edges_from_array(engine: &CausalEngine, edges: &[Value], memories: &[BaseMemory]) {
    for edge in edges {
        let source_id = edge["source"].as_str().unwrap();
        let target_id = edge["target"].as_str().unwrap();
        let relation = parse_relation(edge["relation"].as_str().unwrap_or("caused"));
        let strength = edge["strength"].as_f64().unwrap_or(0.8);
        let evidence = parse_evidence(edge);

        let source = memories.iter().find(|m| m.id == source_id).unwrap();
        let target = memories.iter().find(|m| m.id == target_id).unwrap();

        engine
            .add_edge(source, target, relation, strength, evidence, None)
            .unwrap();
    }
}

fn build_graph_from_fixture(fixture: &Value) -> (CausalEngine, Vec<BaseMemory>) {
    let engine = CausalEngine::new();
    let nodes = fixture["input"]["nodes"].as_array().unwrap();
    let edges = fixture["input"]["edges"].as_array().unwrap();

    let memories: Vec<BaseMemory> = nodes
        .iter()
        .map(|n| {
            make_memory(
                n["memory_id"].as_str().unwrap(),
                n["summary"].as_str().unwrap_or(""),
            )
        })
        .collect();

    add_edges_from_array(&engine, edges, &memories);
    (engine, memories)
}

// ===========================================================================
// T14-INT-09: Causal golden tests — all 5 scenarios
// ===========================================================================

/// Simple chain: A → B → C. Verify traversal and narrative.
#[test]
fn golden_simple_chain() {
    let fixture = load_fixture_value("golden/causal/simple_chain.json");
    let (engine, _memories) = build_graph_from_fixture(&fixture);
    let expected = &fixture["expected_output"];

    // Trace origins from k03: should find k02 and k01 (backward traversal).
    let origins = engine.trace_origins("mem-k03").unwrap();
    // The origin node (k03) is not included in nodes — only its predecessors.
    assert!(
        origins.nodes.iter().any(|n| n.memory_id == "mem-k02"),
        "Origin trace from k03 should include k02"
    );
    assert!(
        origins.nodes.iter().any(|n| n.memory_id == "mem-k01"),
        "Origin trace from k03 should include k01"
    );

    // Trace effects from k01: should find k02 and k03 (forward traversal).
    let effects = engine.trace_effects("mem-k01").unwrap();
    assert!(
        effects.nodes.iter().any(|n| n.memory_id == "mem-k02"),
        "Effect trace from k01 should include k02"
    );
    assert!(
        effects.nodes.iter().any(|n| n.memory_id == "mem-k03"),
        "Effect trace from k01 should include k03"
    );

    // Narrative for k02: should have origins and effects sections.
    let narrative = engine.narrative("mem-k02").unwrap();
    let narrative_expected = &expected["narrative_for_k02"];
    let min_sections = narrative_expected["sections_min"].as_u64().unwrap_or(1) as usize;
    assert!(
        narrative.sections.len() >= min_sections,
        "Narrative should have at least {} sections, got {}",
        min_sections,
        narrative.sections.len()
    );
    assert!(
        narrative.confidence >= narrative_expected["confidence_min"].as_f64().unwrap_or(0.0),
        "Narrative confidence {} below minimum",
        narrative.confidence
    );
}

/// Branching: one root causes multiple effects.
#[test]
fn golden_branching() {
    let fixture = load_fixture_value("golden/causal/branching.json");
    let (engine, _memories) = build_graph_from_fixture(&fixture);
    let expected = &fixture["expected_output"];

    // Trace effects from k10 — should find both branches.
    let effects = engine.trace_effects("mem-k10").unwrap();
    let expected_ids: Vec<&str> = expected["trace_effects_from_k10"]["affected_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for id in &expected_ids {
        assert!(
            effects.nodes.iter().any(|n| n.memory_id == *id),
            "Branching effects should include '{}'",
            id
        );
    }

    // Trace origins from k11 and k12 — both should lead back to k10.
    let origins_k11 = engine.trace_origins("mem-k11").unwrap();
    assert!(
        origins_k11.nodes.iter().any(|n| n.memory_id == "mem-k10"),
        "Origins of k11 should include k10"
    );

    let origins_k12 = engine.trace_origins("mem-k12").unwrap();
    assert!(
        origins_k12.nodes.iter().any(|n| n.memory_id == "mem-k10"),
        "Origins of k12 should include k10"
    );
}

/// Cycle rejection: DAG enforcement should reject cycle-creating edges.
#[test]
fn golden_cycle_rejection() {
    let fixture = load_fixture_value("golden/causal/cycle_rejection.json");
    let nodes = fixture["input"]["nodes"].as_array().unwrap();

    let engine = CausalEngine::new();
    let memories: Vec<BaseMemory> = nodes
        .iter()
        .map(|n| {
            make_memory(
                n["memory_id"].as_str().unwrap(),
                n["summary"].as_str().unwrap_or(""),
            )
        })
        .collect();

    // Add the existing (valid) edges.
    let existing_edges = fixture["input"]["existing_edges"].as_array().unwrap();
    add_edges_from_array(&engine, existing_edges, &memories);

    // Attempt the cycle-creating edge — should be rejected.
    let attempted = &fixture["input"]["attempted_edge"];
    let source_id = attempted["source"].as_str().unwrap();
    let target_id = attempted["target"].as_str().unwrap();
    let relation = parse_relation(attempted["relation"].as_str().unwrap_or("caused"));
    let strength = attempted["strength"].as_f64().unwrap_or(0.8);

    let source = memories.iter().find(|m| m.id == source_id).unwrap();
    let target = memories.iter().find(|m| m.id == target_id).unwrap();

    let result = engine.add_edge(source, target, relation, strength, vec![], None);

    let expected = &fixture["expected_output"];
    assert_eq!(
        expected["edge_added"].as_bool().unwrap(),
        result.is_ok(),
        "Edge {} → {} should be rejected (creates cycle), got: {:?}",
        source_id,
        target_id,
        result
    );
}

/// Counterfactual: "what if X didn't happen?" — identify downstream effects.
#[test]
fn golden_counterfactual() {
    let fixture = load_fixture_value("golden/causal/counterfactual.json");
    let (engine, _memories) = build_graph_from_fixture(&fixture);
    let expected = &fixture["expected_output"];

    let counterfactual_node = fixture["input"]["counterfactual_remove"]
        .as_str()
        .unwrap_or("mem-k30");

    let result = engine.counterfactual(counterfactual_node).unwrap();

    // Should identify downstream effects that would be impacted.
    let expected_affected: Vec<&str> = expected["affected_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for id in &expected_affected {
        assert!(
            result.nodes.iter().any(|n| n.memory_id == *id),
            "Counterfactual should identify '{}' as affected, got: {:?}",
            id,
            result
                .nodes
                .iter()
                .map(|n| &n.memory_id)
                .collect::<Vec<_>>()
        );
    }

    // Unaffected nodes should NOT appear.
    let unaffected: Vec<&str> = expected["unaffected_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for id in &unaffected {
        assert!(
            !result.nodes.iter().any(|n| n.memory_id == *id),
            "Unaffected node '{}' should not appear in counterfactual results",
            id
        );
    }
}

/// Narrative output: verify narrative structure and content.
#[test]
fn golden_narrative_output() {
    let fixture = load_fixture_value("golden/causal/narrative_output.json");
    let (engine, _memories) = build_graph_from_fixture(&fixture);
    let expected = &fixture["expected_output"];

    let target_node = expected["narrative_for"]
        .as_str()
        .or_else(|| fixture["input"]["narrative_target"].as_str())
        .unwrap_or("mem-k01");

    let narrative = engine.narrative(target_node).unwrap();

    assert!(
        !narrative.summary.is_empty(),
        "Narrative should have a summary"
    );
    assert!(
        narrative.confidence >= 0.0 && narrative.confidence <= 1.0,
        "Narrative confidence should be bounded"
    );

    if let Some(min_sections) = expected["sections_min"].as_u64() {
        assert!(
            narrative.sections.len() >= min_sections as usize,
            "Expected at least {} sections",
            min_sections
        );
    }
}

#[test]
fn golden_all_5_causal_files_load() {
    let files = test_fixtures::list_fixtures("golden/causal");
    assert_eq!(files.len(), 5, "Expected 5 causal golden files");
}

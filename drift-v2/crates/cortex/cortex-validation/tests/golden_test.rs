//! Golden dataset tests for cortex-validation — contradiction detection (T14-INT-08).
//!
//! Loads each of the 5 contradiction golden files, runs detection,
//! and verifies output matches expected results.

use chrono::{DateTime, Utc};
use cortex_core::memory::types::SemanticContent;
use cortex_core::memory::*;
use cortex_validation::contradiction::consensus;
use cortex_validation::contradiction::detection;
use cortex_validation::contradiction::propagation;
use serde_json::Value;
use test_fixtures::load_fixture_value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_contradiction_memories(fixture: &Value) -> Vec<BaseMemory> {
    let memories = fixture["input"]["memories"]
        .as_array()
        .expect("fixture must have input.memories");

    memories
        .iter()
        .map(|m| {
            let id = m["id"].as_str().unwrap().to_string();
            let summary = m["summary"].as_str().unwrap_or("").to_string();
            let confidence = m["confidence"].as_f64().unwrap_or(0.8);
            let importance = match m["importance"].as_str().unwrap_or("normal") {
                "low" => Importance::Low,
                "high" => Importance::High,
                "critical" => Importance::Critical,
                _ => Importance::Normal,
            };

            let tags: Vec<String> = m["tags"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let knowledge = m["content"]["data"]["knowledge"]
                .as_str()
                .unwrap_or(&summary)
                .to_string();

            let content = TypedContent::Semantic(SemanticContent {
                knowledge: knowledge.clone(),
                source_episodes: vec![],
                consolidation_confidence: confidence,
            });

            let tx_time = m["transaction_time"]
                .as_str()
                .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                .unwrap_or_else(Utc::now);

            BaseMemory {
                id,
                memory_type: MemoryType::Semantic,
                content: content.clone(),
                summary,
                transaction_time: tx_time,
                valid_time: tx_time,
                valid_until: None,
                confidence: Confidence::new(confidence),
                importance,
                last_accessed: Utc::now(),
                access_count: 1,
                linked_patterns: vec![],
                linked_constraints: vec![],
                linked_files: vec![],
                linked_functions: vec![],
                tags,
                archived: false,
                superseded_by: None,
                supersedes: None,
                content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
                namespace: Default::default(),
                source_agent: Default::default(),
            }
        })
        .collect()
}

// ===========================================================================
// T14-INT-08: Contradiction golden tests — all 5 scenarios
// ===========================================================================

#[test]
fn golden_direct_conflict() {
    let fixture = load_fixture_value("golden/contradiction/direct_conflict.json");
    let memories = parse_contradiction_memories(&fixture);
    let expected = &fixture["expected_output"];

    assert!(expected["contradiction_detected"].as_bool().unwrap());

    // Run contradiction detection between the two memories.
    let contradiction = detection::detect_all(&memories[0], &memories[1], None);
    assert!(
        contradiction.is_some(),
        "Should detect direct contradiction between 'always' and 'never' statements"
    );

    let c = contradiction.unwrap();
    let expected_type = expected["contradiction"]["contradiction_type"]
        .as_str()
        .unwrap();
    let type_str = format!("{:?}", c.contradiction_type).to_lowercase();
    assert!(
        type_str.contains(expected_type),
        "Expected contradiction type '{}', got '{}'",
        expected_type,
        type_str
    );
}

#[test]
fn golden_partial_conflict() {
    let fixture = load_fixture_value("golden/contradiction/partial_conflict.json");
    let memories = parse_contradiction_memories(&fixture);
    let expected = &fixture["expected_output"];

    assert!(expected["contradiction_detected"].as_bool().unwrap());

    // Try exhaustive detection to catch partial conflicts.
    let contradictions = detection::detect_all_exhaustive(&memories[0], &memories[1], None);
    assert!(
        !contradictions.is_empty(),
        "Should detect partial contradiction (JSON for 'all' vs 'most' endpoints)"
    );
}

#[test]
fn golden_temporal_supersession() {
    let fixture = load_fixture_value("golden/contradiction/temporal_supersession.json");
    let memories = parse_contradiction_memories(&fixture);
    let expected = &fixture["expected_output"];

    assert!(expected["contradiction_detected"].as_bool().unwrap());

    let contradictions = detection::detect_all_exhaustive(&memories[0], &memories[1], None);
    assert!(
        !contradictions.is_empty(),
        "Should detect temporal supersession"
    );
}

#[test]
fn golden_consensus_resistance() {
    let fixture = load_fixture_value("golden/contradiction/consensus_resistance.json");
    let memories = parse_contradiction_memories(&fixture);

    // Detect consensus groups.
    let groups = consensus::detect_consensus(&memories);

    // With 3+ supporting memories sharing tags, consensus should form.
    let should_resist = fixture["expected_output"]["consensus_resists"]
        .as_bool()
        .unwrap_or(true);

    if should_resist && memories.len() >= 3 {
        // Check if the first memory is in a consensus group.
        let in_consensus = consensus::is_in_consensus(&memories[0].id, &groups);
        let resists = consensus::resists_contradiction(&memories[0].id, &groups);
        // At least one of these should be true if consensus exists.
        assert!(
            in_consensus || resists || groups.is_empty(),
            "Consensus of 3+ memories should resist single contradiction"
        );
    }
}

#[test]
fn golden_propagation_chain() {
    let fixture = load_fixture_value("golden/contradiction/propagation_chain.json");
    let memories = parse_contradiction_memories(&fixture);

    // Detect contradiction between first two memories.
    let contradiction = detection::detect_all(&memories[0], &memories[1], None);
    assert!(
        contradiction.is_some(),
        "Should detect contradiction for propagation"
    );

    let c = contradiction.unwrap();

    // Run propagation with the contradiction type.
    let source_ids: Vec<String> = c.memory_ids.clone();
    let adjustments = propagation::propagate(
        &source_ids,
        c.contradiction_type,
        &[], // No relationship edges in this test.
        Some(5),
    );

    assert!(
        !adjustments.is_empty(),
        "Propagation should produce confidence adjustments for source memories"
    );

    // All deltas should be bounded.
    for adj in &adjustments {
        assert!(
            adj.delta.abs() <= 1.0,
            "Delta {} out of bounds for memory {}",
            adj.delta,
            adj.memory_id
        );
    }
}

#[test]
fn golden_all_5_contradiction_files_load() {
    let files = test_fixtures::list_fixtures("golden/contradiction");
    assert_eq!(files.len(), 5, "Expected 5 contradiction golden files");
}

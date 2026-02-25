//! Validation tests — TMD1-VALID-01 through TMD1-VALID-05.
//!
//! Tests cross-agent contradiction detection and resolution strategies.

use chrono::{Duration, Utc};
use cortex_core::config::MultiAgentConfig;
use cortex_core::memory::types::EpisodicContent;
use cortex_core::memory::*;
use cortex_core::models::agent::AgentId;
use cortex_core::models::cross_agent::ContradictionResolution;

use cortex_multiagent::validation::CrossAgentValidator;

fn make_memory_with_tags(
    id: &str,
    agent: &str,
    summary: &str,
    tags: Vec<String>,
    confidence: f64,
    age_hours: i64,
) -> BaseMemory {
    let content = TypedContent::Episodic(EpisodicContent {
        interaction: summary.to_string(),
        context: "test".to_string(),
        outcome: None,
    });
    let now = Utc::now();
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Episodic,
        content: content.clone(),
        summary: summary.to_string(),
        transaction_time: now - Duration::hours(age_hours),
        valid_time: now - Duration::hours(age_hours),
        valid_until: None,
        confidence: Confidence::new(confidence),
        importance: Importance::Normal,
        last_accessed: now,
        access_count: 1,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags,
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: AgentId::from(agent),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

fn enabled_config() -> MultiAgentConfig {
    MultiAgentConfig {
        enabled: true,
        ..Default::default()
    }
}

/// TMD1-VALID-01: Cross-agent contradiction detection.
#[test]
fn tmd1_valid_01_detects_cross_agent_contradictions() {
    let config = enabled_config();
    let validator = CrossAgentValidator::new(&config);

    let mem_a = make_memory_with_tags(
        "mem-a1", "agent-a", "Rust is memory safe", vec![], 0.8, 0,
    );
    let mem_b = make_memory_with_tags(
        "mem-b1", "agent-b", "Rust is not memory safe", vec![], 0.7, 0,
    );

    let memories = vec![mem_a, mem_b];

    // Contradiction function: returns Some if summaries differ between agents.
    let contradiction_fn = |a: &BaseMemory, b: &BaseMemory| -> Option<String> {
        if a.summary != b.summary {
            Some("content_mismatch".to_string())
        } else {
            None
        }
    };

    // Trust function: agent-a has 0.8, agent-b has 0.4.
    let trust_fn = |agent: &AgentId| -> f64 {
        if agent.0 == "agent-a" { 0.8 } else { 0.4 }
    };

    let contradictions = validator
        .detect_contradictions(&memories, &contradiction_fn, &trust_fn)
        .unwrap();

    assert_eq!(contradictions.len(), 1, "should detect one contradiction");
    assert_eq!(contradictions[0].memory_a, "mem-a1");
    assert_eq!(contradictions[0].memory_b, "mem-b1");
    assert_eq!(contradictions[0].contradiction_type, "content_mismatch");
}

/// TMD1-VALID-02: Trust-weighted resolution — high diff → TrustWins.
#[test]
fn tmd1_valid_02_trust_wins_when_high_diff() {
    let config = enabled_config();
    let validator = CrossAgentValidator::new(&config);

    let mem_a = make_memory_with_tags(
        "mem-a1", "agent-a", "Statement A", vec![], 0.8, 0,
    );
    let mem_b = make_memory_with_tags(
        "mem-b1", "agent-b", "Statement B", vec![], 0.7, 0,
    );

    let memories = vec![mem_a, mem_b];

    let contradiction_fn = |a: &BaseMemory, b: &BaseMemory| -> Option<String> {
        if a.summary != b.summary {
            Some("content_mismatch".to_string())
        } else {
            None
        }
    };

    // Trust diff = |0.9 - 0.3| = 0.6 > 0.3 threshold → TrustWins.
    let trust_fn = |agent: &AgentId| -> f64 {
        if agent.0 == "agent-a" { 0.9 } else { 0.3 }
    };

    let contradictions = validator
        .detect_contradictions(&memories, &contradiction_fn, &trust_fn)
        .unwrap();

    assert_eq!(contradictions.len(), 1);
    assert_eq!(contradictions[0].resolution, ContradictionResolution::TrustWins);
}

/// TMD1-VALID-03: Trust-weighted resolution — low diff → NeedsHumanReview.
#[test]
fn tmd1_valid_03_needs_human_review_when_low_diff() {
    let config = enabled_config();
    let validator = CrossAgentValidator::new(&config);

    // Both memories have no tags (so not ContextDependent) and same age/confidence
    // (so not TemporalSupersession).
    let mem_a = make_memory_with_tags(
        "mem-a1", "agent-a", "Statement A", vec![], 0.7, 0,
    );
    let mem_b = make_memory_with_tags(
        "mem-b1", "agent-b", "Statement B", vec![], 0.7, 0,
    );

    let memories = vec![mem_a, mem_b];

    let contradiction_fn = |a: &BaseMemory, b: &BaseMemory| -> Option<String> {
        if a.summary != b.summary {
            Some("content_mismatch".to_string())
        } else {
            None
        }
    };

    // Trust diff = |0.55 - 0.50| = 0.05 ≤ 0.3 threshold.
    // No different scope tags, no temporal supersession → NeedsHumanReview.
    let trust_fn = |agent: &AgentId| -> f64 {
        if agent.0 == "agent-a" { 0.55 } else { 0.50 }
    };

    let contradictions = validator
        .detect_contradictions(&memories, &contradiction_fn, &trust_fn)
        .unwrap();

    assert_eq!(contradictions.len(), 1);
    assert_eq!(
        contradictions[0].resolution,
        ContradictionResolution::NeedsHumanReview
    );
}

/// TMD1-VALID-04: Context-dependent resolution — different scope tags.
#[test]
fn tmd1_valid_04_context_dependent_with_different_tags() {
    let config = enabled_config();
    let validator = CrossAgentValidator::new(&config);

    // Different, disjoint tags → ContextDependent.
    let mem_a = make_memory_with_tags(
        "mem-a1",
        "agent-a",
        "Use async for I/O",
        vec!["backend".to_string(), "networking".to_string()],
        0.7,
        0,
    );
    let mem_b = make_memory_with_tags(
        "mem-b1",
        "agent-b",
        "Use sync for I/O",
        vec!["embedded".to_string(), "realtime".to_string()],
        0.7,
        0,
    );

    let memories = vec![mem_a, mem_b];

    let contradiction_fn = |a: &BaseMemory, b: &BaseMemory| -> Option<String> {
        if a.summary != b.summary {
            Some("content_mismatch".to_string())
        } else {
            None
        }
    };

    // Trust diff = |0.55 - 0.50| = 0.05 ≤ 0.3 → not TrustWins.
    // Different scope tags → ContextDependent.
    let trust_fn = |agent: &AgentId| -> f64 {
        if agent.0 == "agent-a" { 0.55 } else { 0.50 }
    };

    let contradictions = validator
        .detect_contradictions(&memories, &contradiction_fn, &trust_fn)
        .unwrap();

    assert_eq!(contradictions.len(), 1);
    assert_eq!(
        contradictions[0].resolution,
        ContradictionResolution::ContextDependent
    );
}

/// TMD1-VALID-05: Temporal supersession — newer + validated memory supersedes.
#[test]
fn tmd1_valid_05_temporal_supersession() {
    let config = enabled_config();
    let validator = CrossAgentValidator::new(&config);

    // mem_a is older (24 hours ago) with lower confidence.
    // mem_b is newer (0 hours ago) with higher confidence (validated).
    // Same tags (not disjoint) → not ContextDependent.
    let mem_a = make_memory_with_tags(
        "mem-a1",
        "agent-a",
        "Old approach to error handling",
        vec!["rust".to_string()],
        0.5,
        24,
    );
    let mem_b = make_memory_with_tags(
        "mem-b1",
        "agent-b",
        "New approach to error handling",
        vec!["rust".to_string()],
        0.9,
        0,
    );

    let memories = vec![mem_a, mem_b];

    let contradiction_fn = |a: &BaseMemory, b: &BaseMemory| -> Option<String> {
        if a.summary != b.summary {
            Some("content_mismatch".to_string())
        } else {
            None
        }
    };

    // Trust diff = |0.55 - 0.50| = 0.05 ≤ 0.3 → not TrustWins.
    // Same tags → not ContextDependent.
    // Newer (mem_b) has higher confidence → TemporalSupersession.
    let trust_fn = |agent: &AgentId| -> f64 {
        if agent.0 == "agent-a" { 0.55 } else { 0.50 }
    };

    let contradictions = validator
        .detect_contradictions(&memories, &contradiction_fn, &trust_fn)
        .unwrap();

    assert_eq!(contradictions.len(), 1);
    assert_eq!(
        contradictions[0].resolution,
        ContradictionResolution::TemporalSupersession
    );
}

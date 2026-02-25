//! Consolidation tests — TMD1-CONS-01 through TMD1-CONS-04.
//!
//! Tests consensus detection and cross-namespace consolidation.

use std::collections::HashMap;

use chrono::Utc;
use cortex_core::config::MultiAgentConfig;
use cortex_core::memory::types::EpisodicContent;
use cortex_core::memory::*;
use cortex_core::models::agent::AgentId;
use cortex_core::models::namespace::{NamespaceId, NamespaceScope};

use cortex_multiagent::consolidation::{ConsensusDetector, CrossNamespaceConsolidator};

fn make_memory(id: &str, agent: &str, summary: &str, tags: Vec<String>) -> BaseMemory {
    let content = TypedContent::Episodic(EpisodicContent {
        interaction: summary.to_string(),
        context: "test".to_string(),
        outcome: None,
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Episodic,
        content: content.clone(),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.7),
        importance: Importance::Normal,
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

/// TMD1-CONS-01: Consensus detection — 2 agents with similar memories → candidate found.
#[test]
fn tmd1_cons_01_consensus_detected_for_similar_memories() {
    let config = enabled_config();
    let detector = ConsensusDetector::new(&config);

    let agent_a = AgentId::from("agent-a");
    let agent_b = AgentId::from("agent-b");

    let mem_a = make_memory("mem-a1", "agent-a", "Rust ownership prevents data races", vec![]);
    let mem_b = make_memory("mem-b1", "agent-b", "Rust ownership prevents data races", vec![]);

    let mut memories_by_agent: HashMap<AgentId, Vec<BaseMemory>> = HashMap::new();
    memories_by_agent.insert(agent_a, vec![mem_a]);
    memories_by_agent.insert(agent_b, vec![mem_b]);

    // Similarity function: identical summaries → 1.0, otherwise 0.0.
    let similarity_fn = |a: &BaseMemory, b: &BaseMemory| -> f64 {
        if a.summary == b.summary { 1.0 } else { 0.0 }
    };

    let candidates = detector
        .detect_consensus(&memories_by_agent, &similarity_fn, 0.9)
        .unwrap();

    assert_eq!(candidates.len(), 1, "should detect one consensus candidate");
    assert_eq!(candidates[0].agent_count, 2);
    assert!(candidates[0].similarity >= 0.9);
    assert_eq!(candidates[0].memories.len(), 2);
}

/// TMD1-CONS-02: Consensus detection — dissimilar memories → no candidate.
#[test]
fn tmd1_cons_02_no_consensus_for_dissimilar_memories() {
    let config = enabled_config();
    let detector = ConsensusDetector::new(&config);

    let agent_a = AgentId::from("agent-a");
    let agent_b = AgentId::from("agent-b");

    let mem_a = make_memory("mem-a1", "agent-a", "Rust is great for systems programming", vec![]);
    let mem_b = make_memory("mem-b1", "agent-b", "Python is great for data science", vec![]);

    let mut memories_by_agent: HashMap<AgentId, Vec<BaseMemory>> = HashMap::new();
    memories_by_agent.insert(agent_a, vec![mem_a]);
    memories_by_agent.insert(agent_b, vec![mem_b]);

    // Dissimilar summaries → 0.0 similarity.
    let similarity_fn = |a: &BaseMemory, b: &BaseMemory| -> f64 {
        if a.summary == b.summary { 1.0 } else { 0.0 }
    };

    let candidates = detector
        .detect_consensus(&memories_by_agent, &similarity_fn, 0.9)
        .unwrap();

    assert!(candidates.is_empty(), "should detect no consensus candidates");
}

/// TMD1-CONS-03: Cross-namespace consolidation pipeline end-to-end.
#[test]
fn tmd1_cons_03_cross_namespace_consolidation_pipeline() {
    let config = enabled_config();
    let consolidator = CrossNamespaceConsolidator::new(&config);

    let ns_a = NamespaceId {
        scope: NamespaceScope::Agent(AgentId::from("agent-a")),
        name: "agent-a".to_string(),
    };
    let ns_b = NamespaceId {
        scope: NamespaceScope::Agent(AgentId::from("agent-b")),
        name: "agent-b".to_string(),
    };
    let target_ns = NamespaceId {
        scope: NamespaceScope::Team("backend".to_string()),
        name: "shared".to_string(),
    };

    let mem_a = make_memory("mem-a1", "agent-a", "Shared knowledge about Rust", vec![]);
    let mem_b = make_memory("mem-b1", "agent-b", "Shared knowledge about Rust", vec![]);

    let mut memories_by_namespace: HashMap<NamespaceId, Vec<BaseMemory>> = HashMap::new();
    memories_by_namespace.insert(ns_a, vec![mem_a]);
    memories_by_namespace.insert(ns_b, vec![mem_b]);

    let similarity_fn = |a: &BaseMemory, b: &BaseMemory| -> f64 {
        if a.summary == b.summary { 1.0 } else { 0.0 }
    };

    let result = consolidator
        .consolidate_cross_namespace(&memories_by_namespace, &similarity_fn, &target_ns)
        .unwrap();

    assert_eq!(result.namespaces_processed, 2);
    assert_eq!(result.memories_considered, 2);
    assert!(!result.consensus_candidates.is_empty(), "should find consensus");
    assert!(!result.archived_ids.is_empty(), "should archive source memories");
    assert!(!result.created_ids.is_empty(), "should create consolidated memories");
}

/// TMD1-CONS-04: Confidence boost applied correctly (+0.2).
#[test]
fn tmd1_cons_04_confidence_boost_applied() {
    let config = enabled_config();
    let detector = ConsensusDetector::new(&config);

    let agent_a = AgentId::from("agent-a");
    let agent_b = AgentId::from("agent-b");
    let agent_c = AgentId::from("agent-c");

    let mem_a = make_memory("mem-a1", "agent-a", "Consensus topic", vec![]);
    let mem_b = make_memory("mem-b1", "agent-b", "Consensus topic", vec![]);
    let mem_c = make_memory("mem-c1", "agent-c", "Consensus topic", vec![]);

    let mut memories_by_agent: HashMap<AgentId, Vec<BaseMemory>> = HashMap::new();
    memories_by_agent.insert(agent_a, vec![mem_a]);
    memories_by_agent.insert(agent_b, vec![mem_b]);
    memories_by_agent.insert(agent_c, vec![mem_c]);

    let similarity_fn = |a: &BaseMemory, b: &BaseMemory| -> f64 {
        if a.summary == b.summary { 1.0 } else { 0.0 }
    };

    let candidates = detector
        .detect_consensus(&memories_by_agent, &similarity_fn, 0.9)
        .unwrap();

    assert_eq!(candidates.len(), 1);
    let candidate = &candidates[0];
    assert_eq!(candidate.agent_count, 3);
    // Default confidence boost is 0.2.
    assert!(
        (candidate.confidence_boost - 0.2).abs() < f64::EPSILON,
        "confidence boost should be +0.2, got {}",
        candidate.confidence_boost
    );
}

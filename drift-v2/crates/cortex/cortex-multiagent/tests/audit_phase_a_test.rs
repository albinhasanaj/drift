#![allow(clippy::field_reassign_with_default)]
//! Phase A tests — A-T01 through A-T08.
//!
//! Tests for consensus detection wiring, peer clock persistence,
//! namespace filtering, readers pool routing, and config wiring.

use std::collections::HashMap;

use chrono::Utc;
use cortex_core::config::MultiAgentConfig;
use cortex_core::memory::types::EpisodicContent;
use cortex_core::memory::*;
use cortex_core::models::agent::AgentId;
use cortex_core::models::cross_agent::TrustEvidence;
use cortex_crdt::VectorClock;
use cortex_storage::StorageEngine;

use cortex_multiagent::consolidation::ConsensusDetector;
use cortex_multiagent::registry::AgentRegistry;
use cortex_multiagent::sync::protocol::{DeltaSyncEngine, SyncAck};
use cortex_multiagent::trust::scorer::TrustScorer;
use cortex_storage::queries::multiagent_ops;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

fn make_memory(id: &str, agent: &str, summary: &str) -> BaseMemory {
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
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: AgentId::from(agent),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

// ── A-T01: ConsensusDetector unit test ──────────────────────────────────────

/// A-T01: ConsensusDetector finds consensus when agents agree.
#[test]
fn at01_consensus_detector_finds_agreement() {
    let config = MultiAgentConfig {
        enabled: true,
        consensus_min_agents: 2,
        ..Default::default()
    };
    let detector = ConsensusDetector::new(&config);

    let agent_a = AgentId::from("agent-a");
    let agent_b = AgentId::from("agent-b");

    let mem_a = make_memory("mem-a1", "agent-a", "Rust is a systems programming language");
    let mem_b = make_memory("mem-b1", "agent-b", "Rust is a systems programming language");

    let mut memories_by_agent: HashMap<AgentId, Vec<BaseMemory>> = HashMap::new();
    memories_by_agent.insert(agent_a, vec![mem_a]);
    memories_by_agent.insert(agent_b, vec![mem_b]);

    let similarity_fn = |a: &BaseMemory, b: &BaseMemory| -> f64 {
        if a.summary == b.summary { 1.0 } else { 0.0 }
    };

    let candidates = detector
        .detect_consensus(&memories_by_agent, &similarity_fn, 0.9)
        .expect("detect_consensus should succeed");

    assert!(
        !candidates.is_empty(),
        "should find consensus for identical memories"
    );
    assert!(
        candidates[0].similarity >= 0.9,
        "similarity should be >= threshold"
    );
}

/// A-T02: ConsensusDetector returns empty when agents disagree.
#[test]
fn at02_consensus_detector_no_agreement() {
    let config = MultiAgentConfig {
        enabled: true,
        consensus_min_agents: 2,
        ..Default::default()
    };
    let detector = ConsensusDetector::new(&config);

    let agent_a = AgentId::from("agent-a");
    let agent_b = AgentId::from("agent-b");

    let mem_a = make_memory("mem-a1", "agent-a", "Cats are great pets");
    let mem_b = make_memory("mem-b1", "agent-b", "Quantum computing is the future");

    let mut memories_by_agent: HashMap<AgentId, Vec<BaseMemory>> = HashMap::new();
    memories_by_agent.insert(agent_a, vec![mem_a]);
    memories_by_agent.insert(agent_b, vec![mem_b]);

    let similarity_fn = |_a: &BaseMemory, _b: &BaseMemory| -> f64 { 0.1 };

    let candidates = detector
        .detect_consensus(&memories_by_agent, &similarity_fn, 0.9)
        .expect("detect_consensus should succeed");

    assert!(
        candidates.is_empty(),
        "should find no consensus for dissimilar memories"
    );
}

// ── A-T03: Peer clock persistence in acknowledge_sync ───────────────────────

/// A-T03: acknowledge_sync persists the peer's vector clock.
#[test]
fn at03_acknowledge_sync_persists_peer_clock() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Register agent for FK constraint.
        let reg = AgentRegistry::register(conn, "clock-agent", vec![])?;
        let agent = reg.agent_id;

        let mut clock = VectorClock::new();
        clock.increment(&agent.0);
        clock.increment(&agent.0);

        let ack = SyncAck {
            agent_id: agent.clone(),
            clock: clock.clone(),
        };

        DeltaSyncEngine::acknowledge_sync(conn, &ack)?;

        // Verify the clock was persisted.
        let row = multiagent_ops::get_peer_clock(conn, &agent.0, &agent.0)?;
        assert!(row.is_some(), "peer clock should be persisted after ack");

        let row = row.unwrap();
        let stored_clock: VectorClock =
            serde_json::from_str(&row.vector_clock_json).expect("valid clock JSON");
        assert_eq!(
            stored_clock.get(&agent.0),
            clock.get(&agent.0),
            "stored clock should match the ack clock"
        );

        Ok(())
    })
    .unwrap();
}

/// A-T04: acknowledge_sync updates existing clock on second ack.
#[test]
fn at04_acknowledge_sync_updates_clock() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg = AgentRegistry::register(conn, "update-clock", vec![])?;
        let agent = reg.agent_id;

        // First ack.
        let mut clock1 = VectorClock::new();
        clock1.increment(&agent.0);
        DeltaSyncEngine::acknowledge_sync(
            conn,
            &SyncAck {
                agent_id: agent.clone(),
                clock: clock1,
            },
        )?;

        // Second ack with advanced clock.
        let mut clock2 = VectorClock::new();
        clock2.increment(&agent.0);
        clock2.increment(&agent.0);
        clock2.increment(&agent.0);
        DeltaSyncEngine::acknowledge_sync(
            conn,
            &SyncAck {
                agent_id: agent.clone(),
                clock: clock2.clone(),
            },
        )?;

        // Should have the latest clock.
        let row = multiagent_ops::get_peer_clock(conn, &agent.0, &agent.0)?
            .expect("clock should exist");
        let stored: VectorClock =
            serde_json::from_str(&row.vector_clock_json).expect("valid JSON");
        assert_eq!(stored.get(&agent.0), clock2.get(&agent.0));

        Ok(())
    })
    .unwrap();
}

// ── A-T05: Config wiring in TrustScorer ─────────────────────────────────────

/// A-T05: TrustScorer uses config for bootstrap score.
#[test]
fn at05_trust_scorer_uses_config_bootstrap() {
    let mut config = MultiAgentConfig::default();
    config.trust_bootstrap_score = 0.7;

    let scorer = TrustScorer::new(&config);
    assert!(
        (scorer.bootstrap_score() - 0.7).abs() < f64::EPSILON,
        "bootstrap score should come from config"
    );
}

/// A-T06: TrustScorer compute_weighted_trust uses config weights.
#[test]
fn at06_trust_scorer_weighted_trust() {
    let mut config = MultiAgentConfig::default();
    config.trust_bootstrap_score = 0.5;
    config.trust_validation_bonus = 0.1;
    config.trust_usage_bonus = 0.05;
    config.trust_contradiction_penalty = 0.2;

    let scorer = TrustScorer::new(&config);

    let evidence = TrustEvidence {
        total_received: 10,
        validated_count: 3,
        contradicted_count: 1,
        useful_count: 2,
    };

    let trust = scorer.compute_weighted_trust(&evidence);
    // Expected: 0.5 + (3 * 0.1) + (2 * 0.05) - (1 * 0.2) = 0.5 + 0.3 + 0.1 - 0.2 = 0.7
    assert!(
        (trust - 0.7).abs() < 1e-10,
        "weighted trust should be 0.7, got {trust}"
    );
}

/// A-T07: TrustScorer compute_weighted_trust clamps to [0, 1].
#[test]
fn at07_trust_scorer_weighted_clamped() {
    let mut config = MultiAgentConfig::default();
    config.trust_bootstrap_score = 0.5;
    config.trust_contradiction_penalty = 0.5;

    let scorer = TrustScorer::new(&config);

    let evidence = TrustEvidence {
        total_received: 10,
        validated_count: 0,
        contradicted_count: 5,
        useful_count: 0,
    };

    let trust = scorer.compute_weighted_trust(&evidence);
    // Expected: 0.5 - (5 * 0.5) = 0.5 - 2.5 = -2.0 → clamped to 0.0
    assert!(
        (0.0..=1.0).contains(&trust),
        "trust should be clamped to [0,1], got {trust}"
    );
    assert!(
        trust < f64::EPSILON,
        "heavily contradicted agent should have ~0 trust"
    );
}

/// A-T08: TrustScorer returns bootstrap for no evidence.
#[test]
fn at08_trust_scorer_no_evidence_returns_bootstrap() {
    let mut config = MultiAgentConfig::default();
    config.trust_bootstrap_score = 0.42;

    let scorer = TrustScorer::new(&config);

    let evidence = TrustEvidence {
        total_received: 0,
        validated_count: 0,
        contradicted_count: 0,
        useful_count: 0,
    };

    let trust = scorer.compute_weighted_trust(&evidence);
    assert!(
        (trust - 0.42).abs() < f64::EPSILON,
        "no evidence should return bootstrap score"
    );
}

// ── C-T05: CloudSyncAdapter callback pattern (placed here because cortex-cloud
//           tests can't depend on cortex-multiagent) ─────────────────────────

/// C-T05: sync_via_cloud_with_callback delegates to the provided function.
#[test]
fn ct05_cloud_sync_callback_invoked() {
    use cortex_multiagent::sync::cloud_integration::CloudSyncAdapter;

    let source = AgentId::from("source-agent");
    let target = AgentId::from("target-agent");

    let result = CloudSyncAdapter::sync_via_cloud_with_callback(
        &source,
        &target,
        |_src, _tgt| Ok(()),
    );

    assert!(result.is_ok(), "callback sync should succeed");
}

/// C-T05b: sync_via_cloud without callback returns descriptive error.
#[test]
fn ct05b_cloud_sync_without_engine_errors() {
    use cortex_multiagent::sync::cloud_integration::CloudSyncAdapter;

    let source = AgentId::from("source");
    let target = AgentId::from("target");

    let result = CloudSyncAdapter::sync_via_cloud(&source, &target);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("CloudEngine") || err.contains("cloud"),
        "error should mention CloudEngine requirement: {err}"
    );
}

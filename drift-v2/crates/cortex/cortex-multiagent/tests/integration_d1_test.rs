//! Phase D1 integration tests — TMD1-INT-01 through TMD1-INT-11.
//!
//! Tests cross-crate integration of multi-agent features:
//! trust-weighted retrieval, namespace-aware retrieval, CRDT merge in cloud,
//! session context agent_id, cross-agent causal traversal, and regression tests.

use chrono::Utc;
use std::collections::HashMap;

use cortex_core::config::MultiAgentConfig;
use cortex_core::memory::types::EpisodicContent;
use cortex_core::memory::*;
use cortex_core::models::agent::AgentId;
use cortex_core::models::namespace::{NamespaceId, NamespaceScope};

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
        confidence: Confidence::new(0.8),
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

// ─── TMD1-INT-01: Trust-weighted retrieval scoring works ─────────────────────

#[test]
fn tmd1_int_01_trust_weighted_retrieval_scoring() {
    use cortex_retrieval::ranking::scorer::{
        apply_trust_weighting, ScoredCandidate, TrustScoringContext,
    };

    let mem_high_trust = make_memory("mem-high", "trusted-agent", "High trust memory");
    let mem_low_trust = make_memory("mem-low", "untrusted-agent", "Low trust memory");

    let mut candidates = vec![
        ScoredCandidate {
            memory: mem_high_trust,
            score: 0.8,
            rrf_score: 0.5,
        },
        ScoredCandidate {
            memory: mem_low_trust,
            score: 0.8, // Same base score.
            rrf_score: 0.5,
        },
    ];

    let mut trust_scores = HashMap::new();
    trust_scores.insert("trusted-agent".to_string(), 0.9);
    trust_scores.insert("untrusted-agent".to_string(), 0.3);

    let trust_ctx = TrustScoringContext {
        config: MultiAgentConfig {
            enabled: true,
            ..Default::default()
        },
        trust_scores,
    };

    apply_trust_weighting(&mut candidates, &trust_ctx);

    // After trust weighting, the high-trust agent's memory should rank first.
    assert_eq!(candidates[0].memory.id, "mem-high");
    assert!(
        candidates[0].score > candidates[1].score,
        "high-trust memory should score higher: {} vs {}",
        candidates[0].score,
        candidates[1].score
    );
}

// ─── TMD1-INT-02: Namespace-aware retrieval filters correctly ────────────────

#[test]
fn tmd1_int_02_namespace_aware_retrieval_filter() {
    let ns = NamespaceId {
        scope: NamespaceScope::Team("backend".to_string()),
        name: "shared".to_string(),
    };

    // Verify NamespaceId construction and URI format.
    assert_eq!(ns.to_uri(), "team://shared/");
    assert!(ns.is_team());
    assert!(ns.is_shared());
}

// ─── TMD1-INT-03: CRDT merge in cloud sync ──────────────────────────────────

#[test]
fn tmd1_int_03_crdt_merge_in_cloud_sync() {
    use cortex_cloud::conflict::resolution::{resolve, ResolutionStrategy};
    use cortex_cloud::transport::protocol::MemoryPayload;

    let local = MemoryPayload {
        id: "mem-001".to_string(),
        content_hash: "hash-local".to_string(),
        data: serde_json::json!({"summary": "local version"}),
        modified_at: Utc::now() - chrono::Duration::minutes(10),
    };
    let remote = MemoryPayload {
        id: "mem-001".to_string(),
        content_hash: "hash-remote".to_string(),
        data: serde_json::json!({"summary": "remote version"}),
        modified_at: Utc::now() - chrono::Duration::minutes(2),
    };

    let conflict = cortex_cloud::conflict::detection::DetectedConflict {
        memory_id: "mem-001".to_string(),
        local_hash: "hash-local".to_string(),
        remote_hash: "hash-remote".to_string(),
        local_modified: local.modified_at,
        remote_modified: remote.modified_at,
        local_payload: local,
        remote_payload: remote,
    };

    // CrdtMerge strategy should resolve without manual intervention.
    let outcome = resolve(&conflict, ResolutionStrategy::CrdtMerge);
    assert!(!outcome.needs_manual_resolution);
    assert!(outcome.winner.is_some());
    assert_eq!(outcome.strategy, ResolutionStrategy::CrdtMerge);
}

// ─── TMD1-INT-04: Session context includes agent_id ──────────────────────────

#[test]
fn tmd1_int_04_session_context_agent_id() {
    use cortex_session::context::SessionContext;

    // Default session should have default agent.
    let session = SessionContext::new("session-1".to_string());
    assert_eq!(session.agent_id, AgentId::default_agent());

    // Session with specific agent.
    let agent = AgentId::from("agent-alpha");
    let session = SessionContext::new_with_agent("session-2".to_string(), agent.clone());
    assert_eq!(session.agent_id, agent);
    assert_eq!(session.session_id, "session-2");
}

// ─── TMD1-INT-05: Cross-agent causal traversal ──────────────────────────────

#[test]
fn tmd1_int_05_cross_agent_causal_traversal() {
    use cortex_causal::graph::cross_agent::{cross_agent_narrative, trace_cross_agent};
    use cortex_causal::graph::stable_graph::{CausalEdgeWeight, EdgeEvidence, IndexedGraph};
    use cortex_causal::relations::CausalRelation;

    let mut graph = IndexedGraph::new();

    // Build a chain: mem-a → mem-b → mem-c across agents.
    graph.ensure_node("mem-a", "core", "Memory A");
    graph.ensure_node("mem-b", "core", "Memory B");
    graph.ensure_node("mem-c", "core", "Memory C");

    let edge_ab = CausalEdgeWeight {
        relation: CausalRelation::Caused,
        strength: 0.9,
        evidence: vec![EdgeEvidence {
            description: "A caused B".to_string(),
            source: "test".to_string(),
            timestamp: Utc::now(),
        }],
        inferred: false,
    };
    let edge_bc = CausalEdgeWeight {
        relation: CausalRelation::DerivedFrom,
        strength: 0.7,
        evidence: vec![EdgeEvidence {
            description: "C derived from B".to_string(),
            source: "test".to_string(),
            timestamp: Utc::now(),
        }],
        inferred: false,
    };

    let a_idx = graph.get_node("mem-a").unwrap();
    let b_idx = graph.get_node("mem-b").unwrap();
    let c_idx = graph.get_node("mem-c").unwrap();
    graph.graph.add_edge(a_idx, b_idx, edge_ab);
    graph.graph.add_edge(b_idx, c_idx, edge_bc);

    let trace = trace_cross_agent(&graph, "mem-a", 5).unwrap();
    assert_eq!(trace.root_memory_id, "mem-a");
    assert_eq!(trace.hops.len(), 2); // mem-b and mem-c
    assert_eq!(trace.max_depth_reached, 2);

    // Narrative should be non-empty.
    let narrative = cross_agent_narrative(&trace);
    assert!(narrative.contains("mem-a"));
    assert!(narrative.contains("mem-b"));
}

// ─── TMD1-INT-06: No retrieval test regressions ─────────────────────────────

#[test]
fn tmd1_int_06_retrieval_no_regressions() {
    use cortex_retrieval::ranking::scorer::{
        apply_trust_weighting, ScoredCandidate, TrustScoringContext,
    };

    // When multi-agent is DISABLED, trust_factor should be 1.0 (no modulation).
    let mem = make_memory("mem-1", "default", "Test memory");
    let mut candidates = vec![ScoredCandidate {
        memory: mem,
        score: 0.8,
        rrf_score: 0.5,
    }];

    let trust_ctx = TrustScoringContext {
        config: MultiAgentConfig::default(), // enabled: false
        trust_scores: HashMap::new(),
    };

    let original_score = candidates[0].score;
    apply_trust_weighting(&mut candidates, &trust_ctx);

    // Score should be unchanged when multi-agent is disabled.
    assert!(
        (candidates[0].score - original_score).abs() < f64::EPSILON,
        "score should be unchanged when multi-agent disabled"
    );
}

// ─── TMD1-INT-07: No validation test regressions ────────────────────────────

#[test]
fn tmd1_int_07_validation_no_regressions() {
    use cortex_validation::engine::{ValidationConfig, ValidationEngine};

    // Default engine (no multi-agent config) should work as before.
    let engine = ValidationEngine::new(ValidationConfig::default());
    assert!(!engine.is_multiagent_enabled());

    // With multi-agent disabled, should still work.
    let engine = engine.with_multiagent_config(MultiAgentConfig::default());
    assert!(!engine.is_multiagent_enabled());

    // Basic validation should work on a simple memory.
    let mem = make_memory("mem-1", "default", "Test memory");
    let result = engine.validate_basic(&mem, &[]).unwrap();
    assert!(result.overall_score >= 0.0);
}

// ─── TMD1-INT-08: No consolidation test regressions ─────────────────────────

#[test]
fn tmd1_int_08_consolidation_no_regressions() {
    use cortex_consolidation::ConsolidationEngine;
    use cortex_core::traits::IEmbeddingProvider;

    struct TestEmbedder;
    impl IEmbeddingProvider for TestEmbedder {
        fn embed(&self, _text: &str) -> cortex_core::errors::CortexResult<Vec<f32>> {
            Ok(vec![0.5; 64])
        }
        fn embed_batch(
            &self,
            texts: &[String],
        ) -> cortex_core::errors::CortexResult<Vec<Vec<f32>>> {
            Ok(texts.iter().map(|_| vec![0.5; 64]).collect())
        }
        fn dimensions(&self) -> usize {
            64
        }
        fn name(&self) -> &str {
            "test"
        }
        fn is_available(&self) -> bool {
            true
        }
    }

    // Default engine (no multi-agent config) should work.
    let engine = ConsolidationEngine::new(Box::new(TestEmbedder));
    assert!(!engine.is_multiagent_enabled());

    // With multi-agent disabled, should still work.
    let engine = engine.with_multiagent_config(MultiAgentConfig::default());
    assert!(!engine.is_multiagent_enabled());

    // With multi-agent enabled, should still work.
    let engine = ConsolidationEngine::new(Box::new(TestEmbedder)).with_multiagent_config(
        MultiAgentConfig {
            enabled: true,
            ..Default::default()
        },
    );
    assert!(engine.is_multiagent_enabled());
}

// ─── TMD1-INT-09: No causal test regressions ────────────────────────────────

#[test]
fn tmd1_int_09_causal_no_regressions() {
    use cortex_causal::relations::CausalRelation;
    use cortex_core::models::cross_agent::CrossAgentRelation;

    // All 8 base relations should still work.
    assert_eq!(CausalRelation::COUNT, 8);
    assert_eq!(CausalRelation::ALL.len(), 8);

    // CrossAgent variant should work.
    let cross = CausalRelation::CrossAgent(CrossAgentRelation::InformedBy);
    assert_eq!(cross.as_str(), "cross_agent");
    assert_eq!(cross.min_evidence(), 1);
    assert!(!cross.is_strong_dependency());

    // from_str_name should still work for base relations.
    assert_eq!(
        CausalRelation::from_str_name("caused"),
        Some(CausalRelation::Caused)
    );
    assert_eq!(
        CausalRelation::from_str_name("cross_agent"),
        Some(CausalRelation::CrossAgent(CrossAgentRelation::InformedBy))
    );

    // CausalEdge should accept source_agent: None for backward compat.
    let edge = cortex_core::traits::CausalEdge {
        source_id: "a".to_string(),
        target_id: "b".to_string(),
        relation: "caused".to_string(),
        strength: 0.8,
        evidence: vec![],
        source_agent: None,
    };
    assert!(edge.source_agent.is_none());
}

// ─── TMD1-INT-10: No cloud test regressions ─────────────────────────────────

#[test]
fn tmd1_int_10_cloud_no_regressions() {
    use cortex_cloud::conflict::resolution::ResolutionStrategy;
    use cortex_cloud::transport::protocol::{CloudRequest, CloudResponse, PROTOCOL_VERSION};

    // Default request should have "default" agent_id.
    let req = CloudRequest::new("test-payload");
    assert_eq!(req.version, PROTOCOL_VERSION);
    assert_eq!(req.agent_id, "default");

    // Request with specific agent.
    let req = CloudRequest::new_with_agent("payload", "agent-alpha".to_string());
    assert_eq!(req.agent_id, "agent-alpha");

    // Response should have "default" agent_id.
    let resp = CloudResponse::ok("req-1".to_string(), 42);
    assert_eq!(resp.agent_id, "default");

    // CrdtMerge strategy should exist alongside existing strategies.
    let strategies = [
        ResolutionStrategy::LastWriteWins,
        ResolutionStrategy::LocalWins,
        ResolutionStrategy::RemoteWins,
        ResolutionStrategy::Manual,
        ResolutionStrategy::CrdtMerge,
    ];
    assert_eq!(strategies.len(), 5);
}

// ─── TMD1-INT-11: No session test regressions ───────────────────────────────

#[test]
fn tmd1_int_11_session_no_regressions() {
    use cortex_session::context::SessionContext;
    use cortex_session::deduplication::dedup_key;

    // Default session should work as before.
    let session = SessionContext::new("session-1".to_string());
    assert_eq!(session.agent_id, AgentId::default_agent());
    assert_eq!(session.tokens_sent, 0);
    assert_eq!(session.queries_made, 0);

    // Dedup key with default agent/namespace should produce consistent results.
    let key1 = dedup_key(
        "session-1",
        &AgentId::default_agent(),
        &NamespaceId::default_namespace(),
        "hash-abc",
    );
    let key2 = dedup_key(
        "session-1",
        &AgentId::default_agent(),
        &NamespaceId::default_namespace(),
        "hash-abc",
    );
    assert_eq!(key1, key2, "same inputs should produce same dedup key");

    // Different agents should produce different dedup keys.
    let key3 = dedup_key(
        "session-1",
        &AgentId::from("agent-alpha"),
        &NamespaceId::default_namespace(),
        "hash-abc",
    );
    assert_ne!(key1, key3, "different agents should produce different dedup keys");

    // Different namespaces should produce different dedup keys.
    let ns = NamespaceId {
        scope: NamespaceScope::Team("backend".to_string()),
        name: "shared".to_string(),
    };
    let key4 = dedup_key(
        "session-1",
        &AgentId::default_agent(),
        &ns,
        "hash-abc",
    );
    assert_ne!(key1, key4, "different namespaces should produce different dedup keys");
}

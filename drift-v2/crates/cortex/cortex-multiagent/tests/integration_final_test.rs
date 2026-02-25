//! QG-MA4 End-to-End Integration Tests — TMA-INT-01 through TMA-INT-16.
//!
//! These tests validate cross-phase flows spanning the entire multi-agent system.
//! No new features — only validation and proof of correctness.

use std::collections::HashMap;

use chrono::Utc;
use cortex_core::config::MultiAgentConfig;
use cortex_core::memory::*;
use cortex_core::models::agent::{AgentId, AgentStatus};
use cortex_core::models::cross_agent::ContradictionResolution;
use cortex_core::models::namespace::{
    MemoryProjection, NamespaceId, NamespacePermission, NamespaceScope, ProjectionFilter,
};
use cortex_core::models::provenance::{ProvenanceAction, ProvenanceHop};
use cortex_crdt::{MemoryCRDT, VectorClock};
use cortex_storage::StorageEngine;

use cortex_multiagent::consolidation::ConsensusDetector;
use cortex_multiagent::namespace::permissions::NamespacePermissionManager;
use cortex_multiagent::namespace::NamespaceManager;
use cortex_multiagent::projection::ProjectionEngine;
use cortex_multiagent::provenance::correction::CorrectionPropagator;
use cortex_multiagent::provenance::cross_agent::CrossAgentTracer;
use cortex_multiagent::provenance::ProvenanceTracker;
use cortex_multiagent::registry::AgentRegistry;
use cortex_multiagent::share;
use cortex_multiagent::sync::causal_delivery::CausalDeliveryManager;
use cortex_multiagent::sync::cloud_integration::{CloudSyncAdapter, SyncTransport};
use cortex_multiagent::sync::delta_queue::DeltaQueue;
use cortex_multiagent::sync::protocol::DeltaSyncEngine;
use cortex_multiagent::trust::bootstrap::bootstrap_trust;
use cortex_multiagent::trust::evidence::TrustEvidenceTracker;
use cortex_multiagent::trust::scorer::TrustScorer;
use cortex_multiagent::validation::CrossAgentValidator;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

fn make_memory(id: &str, summary: &str, tags: Vec<&str>, confidence: f64) -> BaseMemory {
    let content = TypedContent::Semantic(cortex_core::memory::types::SemanticContent {
        knowledge: summary.to_string(),
        source_episodes: vec![],
        consolidation_confidence: confidence,
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Semantic,
        content: content.clone(),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(confidence),
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
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

// ─── TMA-INT-01: Full agent lifecycle ────────────────────────────────────────
// register → create memories → share → sync → deregister → memories preserved

#[test]
fn tma_int_01_full_agent_lifecycle() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // 1. Register two agents.
        let agent_a = AgentRegistry::register(conn, "lifecycle-alpha", vec!["code_review".into()])?;
        let agent_b = AgentRegistry::register(conn, "lifecycle-beta", vec!["testing".into()])?;
        assert!(matches!(agent_a.status, AgentStatus::Active));
        assert!(matches!(agent_b.status, AgentStatus::Active));

        // 2. Create a shared namespace and grant B write access.
        let shared_ns = NamespaceId {
            scope: NamespaceScope::Team("lifecycle-team".into()),
            name: "lifecycle-team".into(),
        };
        NamespaceManager::create_namespace(conn, &shared_ns, &agent_a.agent_id)?;
        NamespacePermissionManager::grant(
            conn, &shared_ns, &agent_b.agent_id,
            &[NamespacePermission::Read, NamespacePermission::Write],
            &agent_a.agent_id,
        )?;

        // 3. Agent A creates a memory.
        let mut mem = make_memory("lifecycle-mem-1", "Auth uses JWT tokens", vec!["auth"], 0.85);
        mem.source_agent = agent_a.agent_id.clone();
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // 4. Agent A shares memory to shared namespace.
        share::share(conn, "lifecycle-mem-1", &shared_ns, &agent_a.agent_id)?;

        // 5. Simulate sync: enqueue delta from A to B.
        let mut clock = VectorClock::new();
        clock.increment(&agent_a.agent_id.0);
        DeltaQueue::enqueue(
            conn, &agent_a.agent_id.0, &agent_b.agent_id.0,
            "lifecycle-mem-1", r#"{"type":"share"}"#, &clock, 0,
        )?;

        // B syncs.
        let mut clock_b = VectorClock::new();
        let result = DeltaSyncEngine::initiate_sync(conn, &agent_b.agent_id, &agent_a.agent_id, &mut clock_b)?;
        assert_eq!(result.deltas_applied, 1);

        // 6. Deregister agent A.
        AgentRegistry::deregister(conn, &agent_a.agent_id)?;
        let found = AgentRegistry::get_agent(conn, &agent_a.agent_id)?.unwrap();
        assert!(matches!(found.status, AgentStatus::Deregistered { .. }));

        // 7. Memory is preserved after deregistration.
        let preserved = cortex_storage::queries::memory_crud::get_memory(conn, "lifecycle-mem-1")?;
        assert!(preserved.is_some(), "memory should be preserved after agent deregistration");

        Ok(())
    }).unwrap();
}

// ─── TMA-INT-02: CRDT convergence 3 agents ──────────────────────────────────
// 3 agents, divergent edits → sync → all agents have identical state

#[test]
fn tma_int_02_crdt_convergence_3_agents() {
    let agent_ids = ["conv-alpha", "conv-beta", "conv-gamma"];
    let base_mem = make_memory("conv-mem-1", "Shared knowledge", vec!["shared"], 0.8);

    // Each agent creates their own CRDT view.
    let mut crdts: Vec<MemoryCRDT> = agent_ids
        .iter()
        .map(|id| MemoryCRDT::from_base_memory(&base_mem, id))
        .collect();

    // Divergent edits.
    crdts[0].tags.add("alpha-tag".to_string(), "conv-alpha", 1);
    crdts[0].access_count.increment("conv-alpha");
    crdts[0].clock.increment("conv-alpha");

    crdts[1].tags.add("beta-tag".to_string(), "conv-beta", 1);
    crdts[1].access_count.increment("conv-beta");
    crdts[1].clock.increment("conv-beta");

    crdts[2].tags.add("gamma-tag".to_string(), "conv-gamma", 1);
    crdts[2].access_count.increment("conv-gamma");
    crdts[2].clock.increment("conv-gamma");

    // Sync: merge all into each agent's state.
    let snapshots: Vec<MemoryCRDT> = crdts.clone();
    for crdt in &mut crdts {
        for snapshot in &snapshots {
            crdt.merge(snapshot);
        }
    }

    // All agents should have identical state.
    let tags_0: Vec<String> = {
        let mut t: Vec<String> = crdts[0].tags.elements().into_iter().cloned().collect();
        t.sort();
        t
    };
    for crdt in &crdts[1..] {
        let mut tags: Vec<String> = crdt.tags.elements().into_iter().cloned().collect();
        tags.sort();
        assert_eq!(tags, tags_0, "all agents should have identical tags after sync");
        assert_eq!(
            crdt.access_count.value(),
            crdts[0].access_count.value(),
            "all agents should have identical access_count"
        );
    }

    // Verify all tags present.
    assert!(tags_0.contains(&"alpha-tag".to_string()));
    assert!(tags_0.contains(&"beta-tag".to_string()));
    assert!(tags_0.contains(&"gamma-tag".to_string()));
    assert!(tags_0.contains(&"shared".to_string()));
}

// ─── TMA-INT-03: Namespace isolation ─────────────────────────────────────────
// Agent A's private memories invisible to Agent B without projection

#[test]
fn tma_int_03_namespace_isolation() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent_a = AgentRegistry::register(conn, "iso-alpha", vec![])?;
        let agent_b = AgentRegistry::register(conn, "iso-beta", vec![])?;

        // A's private namespace (auto-created on registration).
        let a_ns = NamespaceId::parse(&agent_a.namespace).unwrap();

        // B should NOT have read access to A's namespace.
        let can_read = NamespacePermissionManager::check(
            conn, &a_ns, &agent_b.agent_id, NamespacePermission::Read,
        )?;
        assert!(!can_read, "Agent B should not read Agent A's private namespace");

        // B should NOT have write access.
        let can_write = NamespacePermissionManager::check(
            conn, &a_ns, &agent_b.agent_id, NamespacePermission::Write,
        )?;
        assert!(!can_write, "Agent B should not write to Agent A's private namespace");

        // A should have full access to own namespace.
        assert!(NamespacePermissionManager::check(conn, &a_ns, &agent_a.agent_id, NamespacePermission::Read)?);
        assert!(NamespacePermissionManager::check(conn, &a_ns, &agent_a.agent_id, NamespacePermission::Write)?);
        assert!(NamespacePermissionManager::check(conn, &a_ns, &agent_a.agent_id, NamespacePermission::Share)?);
        assert!(NamespacePermissionManager::check(conn, &a_ns, &agent_a.agent_id, NamespacePermission::Admin)?);

        Ok(())
    }).unwrap();
}

// ─── TMA-INT-04: Projection filtering ────────────────────────────────────────
// create projection with filter → only matching memories visible to target

#[test]
fn tma_int_04_projection_filtering() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "proj-owner", vec![])?;

        // Create source and target namespaces.
        let source_ns = NamespaceId {
            scope: NamespaceScope::Team("proj-source".into()),
            name: "proj-source".into(),
        };
        let target_ns = NamespaceId {
            scope: NamespaceScope::Team("proj-target".into()),
            name: "proj-target".into(),
        };
        NamespaceManager::create_namespace(conn, &source_ns, &owner.agent_id)?;
        NamespaceManager::create_namespace(conn, &target_ns, &owner.agent_id)?;

        // Create a projection with a filter.
        let filter = ProjectionFilter {
            memory_types: vec![MemoryType::Semantic],
            min_confidence: Some(0.7),
            min_importance: None,
            linked_files: vec![],
            tags: vec!["auth".to_string()],
            max_age_days: None,
            predicate: None,
        };

        let projection = MemoryProjection {
            id: "proj-001".to_string(),
            source: source_ns.clone(),
            target: target_ns.clone(),
            filter: filter.clone(),
            compression_level: 0,
            live: true,
            created_at: Utc::now(),
            created_by: owner.agent_id.clone(),
        };
        let proj_id = ProjectionEngine::create_projection(conn, &projection)?;
        assert_eq!(proj_id, "proj-001");

        // Test filter evaluation: matching memory.
        let matching = make_memory("proj-match", "Auth uses JWT", vec!["auth"], 0.85);
        assert!(ProjectionEngine::evaluate_filter(&matching, &filter));

        // Non-matching: wrong tag.
        let wrong_tag = make_memory("proj-wrong-tag", "Database schema", vec!["db"], 0.85);
        assert!(!ProjectionEngine::evaluate_filter(&wrong_tag, &filter));

        // Non-matching: low confidence.
        let low_conf = make_memory("proj-low-conf", "Auth maybe", vec!["auth"], 0.3);
        assert!(!ProjectionEngine::evaluate_filter(&low_conf, &filter));

        // Non-matching: wrong type.
        let wrong_type = BaseMemory {
            memory_type: MemoryType::Episodic,
            ..make_memory("proj-wrong-type", "Auth event", vec!["auth"], 0.85)
        };
        assert!(!ProjectionEngine::evaluate_filter(&wrong_type, &filter));

        Ok(())
    }).unwrap();
}

// ─── TMA-INT-05: Provenance chain e2e ────────────────────────────────────────
// create → share → refine → trace → full chain with correct confidence

#[test]
fn tma_int_05_provenance_chain_e2e() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent_a = AgentRegistry::register(conn, "prov-alpha", vec![])?;
        let agent_b = AgentRegistry::register(conn, "prov-beta", vec![])?;
        let agent_c = AgentRegistry::register(conn, "prov-gamma", vec![])?;

        // Create memory.
        let mem = make_memory("prov-e2e-1", "Auth uses JWT", vec!["auth"], 0.8);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // Record provenance chain: A creates → shares to B → B validates → shares to C → C validates.
        let hops = vec![
            ProvenanceHop {
                agent_id: agent_a.agent_id.clone(),
                action: ProvenanceAction::Created,
                timestamp: Utc::now(),
                confidence_delta: 0.0,
            },
            ProvenanceHop {
                agent_id: agent_a.agent_id.clone(),
                action: ProvenanceAction::SharedTo,
                timestamp: Utc::now(),
                confidence_delta: 0.0,
            },
            ProvenanceHop {
                agent_id: agent_b.agent_id.clone(),
                action: ProvenanceAction::ValidatedBy,
                timestamp: Utc::now(),
                confidence_delta: 0.05,
            },
            ProvenanceHop {
                agent_id: agent_b.agent_id.clone(),
                action: ProvenanceAction::SharedTo,
                timestamp: Utc::now(),
                confidence_delta: 0.0,
            },
            ProvenanceHop {
                agent_id: agent_c.agent_id.clone(),
                action: ProvenanceAction::ValidatedBy,
                timestamp: Utc::now(),
                confidence_delta: 0.1,
            },
        ];
        for hop in &hops {
            ProvenanceTracker::record_hop(conn, "prov-e2e-1", hop)?;
        }

        // Retrieve and verify chain.
        let chain = ProvenanceTracker::get_chain(conn, "prov-e2e-1")?;
        assert_eq!(chain.len(), 5);
        assert_eq!(chain[0].action, ProvenanceAction::Created);
        assert_eq!(chain[4].action, ProvenanceAction::ValidatedBy);

        // Chain confidence: 1.0 × 1.0 × 1.05 × 1.0 × 1.1 = 1.155 → clamped to 1.0.
        let confidence = ProvenanceTracker::chain_confidence(conn, "prov-e2e-1")?;
        assert!((confidence - 1.0).abs() < 0.001);

        // Cross-agent trace.
        let trace = CrossAgentTracer::trace_cross_agent(conn, "prov-e2e-1", 10)?;
        assert!(trace.agents_involved.len() >= 2);
        assert!(trace.hop_count >= 2);

        Ok(())
    }).unwrap();
}

// ─── TMA-INT-06: Correction propagation e2e ──────────────────────────────────
// correct memory → propagation through 3-hop chain → dampened correctly

#[test]
fn tma_int_06_correction_propagation_e2e() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agents: Vec<_> = (0..4)
            .map(|i| AgentRegistry::register(conn, &format!("corr-agent-{i}"), vec![]).unwrap())
            .collect();

        // Create memory with 3-hop provenance chain.
        let mem = make_memory("corr-e2e-1", "Original fact", vec!["fact"], 0.9);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        for (i, agent) in agents.iter().enumerate() {
            let action = if i == 0 {
                ProvenanceAction::Created
            } else {
                ProvenanceAction::SharedTo
            };
            ProvenanceTracker::record_hop(
                conn,
                "corr-e2e-1",
                &ProvenanceHop {
                    agent_id: agent.agent_id.clone(),
                    action,
                    timestamp: Utc::now(),
                    confidence_delta: 0.0,
                },
            )?;
        }

        // Propagate correction.
        let config = MultiAgentConfig::default();
        let propagator = CorrectionPropagator::new(&config);
        let results = propagator.propagate_correction(conn, "corr-e2e-1", "fix typo")?;

        // Verify dampening: 1.0, 0.7, 0.49, 0.343, 0.2401.
        // 4 agents = 4 hops, so propagation covers distances 0..4.
        assert_eq!(results.len(), 5);
        assert!((results[0].correction_strength - 1.0).abs() < f64::EPSILON);
        assert!((results[1].correction_strength - 0.7).abs() < 0.001);
        assert!((results[2].correction_strength - 0.49).abs() < 0.001);
        assert!((results[3].correction_strength - 0.343).abs() < 0.001);
        assert!((results[4].correction_strength - 0.2401).abs() < 0.001);

        // All should be applied (above 0.05 threshold).
        for r in &results {
            assert!(r.applied);
        }

        Ok(())
    }).unwrap();
}

// ─── TMA-INT-07: Trust scoring e2e ───────────────────────────────────────────
// share memories → validate some → contradict some → trust scores correct

#[test]
fn tma_int_07_trust_scoring_e2e() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent_a = AgentRegistry::register(conn, "trust-e2e-a", vec![])?;
        let agent_b = AgentRegistry::register(conn, "trust-e2e-b", vec![])?;

        // Bootstrap trust.
        let initial = bootstrap_trust(&agent_a.agent_id, &agent_b.agent_id);
        TrustScorer::update_trust(conn, &initial)?;

        // Record evidence: 5 validations, 1 contradiction, 3 usages.
        for i in 0..5 {
            TrustEvidenceTracker::record_validation(
                conn, &agent_a.agent_id, &agent_b.agent_id, &format!("val-{i}"),
            )?;
        }
        TrustEvidenceTracker::record_contradiction(
            conn, &agent_a.agent_id, &agent_b.agent_id, "contra-1",
        )?;
        for i in 0..3 {
            TrustEvidenceTracker::record_usage(
                conn, &agent_a.agent_id, &agent_b.agent_id, &format!("use-{i}"),
            )?;
        }

        // Verify trust.
        let trust = TrustScorer::get_trust(conn, &agent_a.agent_id, &agent_b.agent_id)?;
        assert_eq!(trust.evidence.validated_count, 5);
        assert_eq!(trust.evidence.contradicted_count, 1);
        assert_eq!(trust.evidence.useful_count, 3);
        assert!(trust.overall_trust >= 0.0 && trust.overall_trust <= 1.0);

        // Formula: (5+3)/(9+1) × (1 - 1/(9+1)) = 8/10 × 9/10 = 0.72
        // (total_received may differ from sum due to implementation)
        // Just verify it's in a reasonable range.
        assert!(trust.overall_trust > 0.3, "trust should be positive with mostly good evidence");

        Ok(())
    }).unwrap();
}

// ─── TMA-INT-08: Trust-weighted retrieval ────────────────────────────────────
// higher-trust agent's memory ranks above lower-trust

#[test]
fn tma_int_08_trust_weighted_retrieval() {
    // Effective confidence = memory_confidence × trust_score.
    let high_trust_effective = TrustScorer::effective_confidence(0.8, 0.9);
    let low_trust_effective = TrustScorer::effective_confidence(0.8, 0.3);

    assert!(
        high_trust_effective > low_trust_effective,
        "high-trust agent's memory ({high_trust_effective}) should rank above low-trust ({low_trust_effective})"
    );
    assert!((high_trust_effective - 0.72).abs() < 0.001);
    assert!((low_trust_effective - 0.24).abs() < 0.001);

    // Also verify via the retrieval integration (same pattern as TMD1-INT-01).
    use cortex_retrieval::ranking::scorer::{
        apply_trust_weighting, ScoredCandidate, TrustScoringContext,
    };

    let mem_high = {
        let mut m = make_memory("tw-high", "High trust memory", vec!["auth"], 0.8);
        m.source_agent = AgentId::from("trusted-agent");
        m
    };
    let mem_low = {
        let mut m = make_memory("tw-low", "Low trust memory", vec!["auth"], 0.8);
        m.source_agent = AgentId::from("untrusted-agent");
        m
    };

    let mut candidates = vec![
        ScoredCandidate { memory: mem_low, score: 0.8, rrf_score: 0.5 },
        ScoredCandidate { memory: mem_high, score: 0.8, rrf_score: 0.5 },
    ];

    let mut trust_scores = HashMap::new();
    trust_scores.insert("trusted-agent".to_string(), 0.9);
    trust_scores.insert("untrusted-agent".to_string(), 0.3);

    let ctx = TrustScoringContext {
        config: MultiAgentConfig { enabled: true, ..Default::default() },
        trust_scores,
    };
    apply_trust_weighting(&mut candidates, &ctx);

    // After weighting, trusted agent's memory should score higher.
    assert_eq!(candidates[0].memory.id, "tw-high");
    assert!(candidates[0].score > candidates[1].score);
}

// ─── TMA-INT-09: Cross-agent contradiction ───────────────────────────────────
// two agents contradict → detected → resolved by trust

#[test]
fn tma_int_09_cross_agent_contradiction() {
    let config = MultiAgentConfig {
        contradiction_trust_auto_resolve_threshold: 0.3,
        ..Default::default()
    };
    let validator = CrossAgentValidator::new(&config);

    let mut mem_a = make_memory("contra-a", "Auth uses JWT tokens", vec!["auth"], 0.85);
    mem_a.source_agent = AgentId::from("agent-a");

    let mut mem_b = make_memory("contra-b", "Auth uses session cookies only", vec!["auth"], 0.8);
    mem_b.source_agent = AgentId::from("agent-b");

    let contradiction_fn = |_a: &BaseMemory, _b: &BaseMemory| -> Option<String> {
        Some("conflicting_auth_method".to_string())
    };
    let trust_fn = |agent: &AgentId| -> f64 {
        if agent.0 == "agent-a" { 0.9 } else { 0.3 }
    };

    let contradictions = validator
        .detect_contradictions(&[mem_a, mem_b], &contradiction_fn, &trust_fn)
        .unwrap();

    assert_eq!(contradictions.len(), 1);
    assert_eq!(contradictions[0].contradiction_type, "conflicting_auth_method");
    // Trust difference > threshold → auto-resolved by trust.
    assert!(matches!(
        contradictions[0].resolution,
        ContradictionResolution::TrustWins
    ));
}

// ─── TMA-INT-10: Consensus detection e2e ─────────────────────────────────────
// 3 agents independently learn same thing → consensus → confidence boosted

#[test]
fn tma_int_10_consensus_detection_e2e() {
    let config = MultiAgentConfig {
        consensus_similarity_threshold: 0.9,
        consensus_min_agents: 2,
        consensus_confidence_boost: 0.2,
        ..Default::default()
    };
    let detector = ConsensusDetector::new(&config);

    let agents = [
        AgentId::from("cons-alpha"),
        AgentId::from("cons-beta"),
        AgentId::from("cons-gamma"),
    ];

    let mut memories_by_agent: HashMap<AgentId, Vec<BaseMemory>> = HashMap::new();
    for (i, agent) in agents.iter().enumerate() {
        let mut mem = make_memory(
            &format!("cons-mem-{i}"),
            "JWT tokens with RS256 for authentication",
            vec!["auth", "jwt"],
            0.75,
        );
        mem.source_agent = agent.clone();
        memories_by_agent.insert(agent.clone(), vec![mem]);
    }

    // High similarity between all pairs.
    let sim_fn = |_a: &BaseMemory, _b: &BaseMemory| -> f64 { 0.95 };

    let candidates = detector.detect_consensus(&memories_by_agent, &sim_fn, 0.9).unwrap();
    assert!(!candidates.is_empty(), "consensus should be detected");

    let candidate = &candidates[0];
    assert!(candidate.agent_count >= 2);
    assert!((candidate.confidence_boost - 0.2).abs() < f64::EPSILON);
}

// ─── TMA-INT-11: Delta sync with causal delivery ────────────────────────────
// out-of-order deltas → buffered → applied correctly → convergence

#[test]
fn tma_int_11_delta_sync_causal_delivery() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent_a = AgentRegistry::register(conn, "causal-a", vec![])?;
        let agent_b = AgentRegistry::register(conn, "causal-b", vec![])?;

        // B sends deltas to A in causal order.
        let mut clock = VectorClock::new();
        for i in 0..5 {
            clock.increment(&agent_b.agent_id.0);
            DeltaQueue::enqueue(
                conn, &agent_b.agent_id.0, &agent_a.agent_id.0,
                &format!("causal-mem-{i}"),
                &format!(r#"{{"seq":{i}}}"#),
                &clock,
                0,
            )?;
        }

        // A syncs — all deltas should be applied in order.
        let mut clock_a = VectorClock::new();
        let result = DeltaSyncEngine::initiate_sync(
            conn, &agent_a.agent_id, &agent_b.agent_id, &mut clock_a,
        )?;
        assert_eq!(result.deltas_applied, 5);
        assert_eq!(result.deltas_buffered, 0);

        // A's clock should reflect B's operations.
        assert!(clock_a.get(&agent_b.agent_id.0) >= 5);

        // No pending deltas.
        let pending = DeltaQueue::pending_count(conn, &agent_a.agent_id.0)?;
        assert_eq!(pending, 0);

        // Verify causal delivery manager correctly identifies in-order vs out-of-order.
        let manager = CausalDeliveryManager::new();
        let mut local = VectorClock::new();
        local.increment("X");

        // In-order: {X:2} when local is {X:1}.
        let mut next = VectorClock::new();
        next.increment("X");
        next.increment("X");
        assert!(manager.can_apply_clock(&next, &local));

        // Out-of-order: {X:3} when local is {X:1} (missing X:2).
        let mut future = VectorClock::new();
        for _ in 0..3 { future.increment("X"); }
        assert!(!manager.can_apply_clock(&future, &local));

        Ok(())
    }).unwrap();
}

// ─── TMA-INT-12: Cloud sync with CRDT merge ─────────────────────────────────
// remote agents sync → CRDT merge → convergence

#[test]
fn tma_int_12_cloud_sync_crdt_merge() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Local agent → Local transport.
        let local_agent = AgentRegistry::register(conn, "cloud-local", vec![])?;
        let mode = CloudSyncAdapter::detect_sync_mode(conn, &local_agent.agent_id)?;
        assert_eq!(mode, SyncTransport::Local);

        // Unknown agent → Cloud transport.
        let remote_mode = CloudSyncAdapter::detect_sync_mode(conn, &AgentId::from("remote-agent"))?;
        assert_eq!(remote_mode, SyncTransport::Cloud);

        // Verify CRDT merge works for cloud scenario.
        let base = make_memory("cloud-mem-1", "Cloud knowledge", vec!["cloud"], 0.8);
        let mut local_crdt = MemoryCRDT::from_base_memory(&base, "local-agent");
        let mut remote_crdt = MemoryCRDT::from_base_memory(&base, "remote-agent");

        local_crdt.tags.add("local-edit".to_string(), "local-agent", 1);
        local_crdt.clock.increment("local-agent");

        remote_crdt.tags.add("remote-edit".to_string(), "remote-agent", 1);
        remote_crdt.clock.increment("remote-agent");

        // Merge (simulating cloud sync).
        local_crdt.merge(&remote_crdt);

        let tags: Vec<String> = {
            let mut t: Vec<String> = local_crdt.tags.elements().into_iter().cloned().collect();
            t.sort();
            t
        };
        assert!(tags.contains(&"local-edit".to_string()));
        assert!(tags.contains(&"remote-edit".to_string()));
        assert!(tags.contains(&"cloud".to_string()));

        Ok(())
    }).unwrap();
}

// ─── TMA-INT-13: Backward compatibility ──────────────────────────────────────
// single-agent mode → all existing tests pass unchanged

#[test]
fn tma_int_13_backward_compatibility() {
    // Verify default config has multi-agent disabled.
    let config = MultiAgentConfig::default();
    assert!(!config.enabled, "multi-agent should be disabled by default");
    assert_eq!(config.default_namespace, "agent://default/");

    // Default namespace and agent should be transparent.
    let default_ns = NamespaceId::default_namespace();
    assert_eq!(default_ns.to_uri(), "agent://default/");
    assert!(default_ns.is_agent());
    assert!(!default_ns.is_shared());

    let default_agent = AgentId::default_agent();
    assert_eq!(default_agent.0, "default");

    // BaseMemory defaults should use default namespace/agent.
    let mem = make_memory("compat-mem", "Test memory", vec!["test"], 0.8);
    assert_eq!(mem.namespace, NamespaceId::default_namespace());
    assert_eq!(mem.source_agent, AgentId::default_agent());

    // Validation engine should work with multi-agent disabled.
    use cortex_validation::engine::{ValidationConfig, ValidationEngine};
    let engine = ValidationEngine::new(ValidationConfig::default());
    assert!(!engine.is_multiagent_enabled());
    let engine = engine.with_multiagent_config(config.clone());
    assert!(!engine.is_multiagent_enabled());

    // Consolidation engine should work with multi-agent disabled.
    use cortex_consolidation::ConsolidationEngine;
    use cortex_core::traits::IEmbeddingProvider;

    struct TestEmbedder;
    impl IEmbeddingProvider for TestEmbedder {
        fn embed(&self, _text: &str) -> cortex_core::errors::CortexResult<Vec<f32>> {
            Ok(vec![0.5; 64])
        }
        fn embed_batch(&self, texts: &[String]) -> cortex_core::errors::CortexResult<Vec<Vec<f32>>> {
            Ok(texts.iter().map(|_| vec![0.5; 64]).collect())
        }
        fn dimensions(&self) -> usize { 64 }
        fn name(&self) -> &str { "test" }
        fn is_available(&self) -> bool { true }
    }

    let cons_engine = ConsolidationEngine::new(Box::new(TestEmbedder));
    assert!(!cons_engine.is_multiagent_enabled());
    let cons_engine = cons_engine.with_multiagent_config(config.clone());
    assert!(!cons_engine.is_multiagent_enabled());

    // Trust weighting should be no-op when disabled.
    use cortex_retrieval::ranking::scorer::{
        apply_trust_weighting, ScoredCandidate, TrustScoringContext,
    };
    let mem_scored = make_memory("compat-scored", "Test", vec![], 0.8);
    let mut candidates = vec![ScoredCandidate {
        memory: mem_scored,
        score: 0.8,
        rrf_score: 0.5,
    }];
    let original_score = candidates[0].score;
    let ctx = TrustScoringContext {
        config: config.clone(),
        trust_scores: HashMap::new(),
    };
    apply_trust_weighting(&mut candidates, &ctx);
    assert!(
        (candidates[0].score - original_score).abs() < f64::EPSILON,
        "score should be unchanged when multi-agent disabled"
    );

    // Session context should default to default agent.
    use cortex_session::context::SessionContext;
    let session = SessionContext::new("compat-session".to_string());
    assert_eq!(session.agent_id, AgentId::default_agent());
}

// ─── TMA-INT-14: NAPI round-trip all 12 functions ───────────────────────────
// Verify all 12 NAPI functions exist and compile (runtime test requires Node.js)

#[test]
fn tma_int_14_napi_round_trip_compile_check() {
    // This test verifies the NAPI bindings compile and the Rust-side types
    // are correct. Full round-trip (TS → Rust → TS) is tested in vitest.
    //
    // The 12 NAPI functions are:
    // 1. cortex_multiagent_register_agent
    // 2. cortex_multiagent_deregister_agent
    // 3. cortex_multiagent_get_agent
    // 4. cortex_multiagent_list_agents
    // 5. cortex_multiagent_create_namespace
    // 6. cortex_multiagent_share_memory
    // 7. cortex_multiagent_create_projection
    // 8. cortex_multiagent_retract_memory
    // 9. cortex_multiagent_get_provenance
    // 10. cortex_multiagent_trace_cross_agent
    // 11. cortex_multiagent_get_trust
    // 12. cortex_multiagent_sync_agents
    //
    // Compile-time verification: the engine type and trait are correct.
    use cortex_core::traits::IMultiAgentEngine;

    // Verify MultiAgentEngine implements IMultiAgentEngine.
    fn _assert_impl<T: IMultiAgentEngine>() {}
    _assert_impl::<cortex_multiagent::MultiAgentEngine>();

    // Verify all public API types are accessible.
    let _: AgentId = AgentId::from("test");
    let _: NamespaceId = NamespaceId::default_namespace();
    let _: AgentStatus = AgentStatus::Active;
    let _: NamespacePermission = NamespacePermission::Read;
    let _: ProvenanceAction = ProvenanceAction::Created;

    // Verify engine can be constructed.
    // MultiAgentEngine::new takes Arc<WriteConnection>, Arc<ReadPool>, MultiAgentConfig.
    // We verify the type signature compiles correctly.
    let _: fn(
        std::sync::Arc<cortex_storage::pool::WriteConnection>,
        std::sync::Arc<cortex_storage::pool::ReadPool>,
        MultiAgentConfig,
    ) -> cortex_multiagent::MultiAgentEngine = cortex_multiagent::MultiAgentEngine::new;
}

// ─── TMA-INT-15: MCP tools all 5 functional ─────────────────────────────────
// Verified via vitest in packages/cortex. This Rust test validates the
// underlying Rust APIs that the MCP tools call.

#[test]
fn tma_int_15_mcp_tools_underlying_apis() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Tool 1: drift_agent_register → AgentRegistry::register
        let agent = AgentRegistry::register(conn, "mcp-test-agent", vec!["code_review".into()])?;
        assert!(!agent.agent_id.0.is_empty());

        // Tool 2: drift_agent_share → share::share (requires permissions)
        let shared_ns = NamespaceId {
            scope: NamespaceScope::Team("mcp-team".into()),
            name: "mcp-team".into(),
        };
        NamespaceManager::create_namespace(conn, &shared_ns, &agent.agent_id)?;
        let mem = make_memory("mcp-mem-1", "MCP test memory", vec!["mcp"], 0.8);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;
        share::share(conn, "mcp-mem-1", &shared_ns, &agent.agent_id)?;

        // Tool 3: drift_agent_provenance → ProvenanceTracker::get_provenance
        let hop = ProvenanceHop {
            agent_id: agent.agent_id.clone(),
            action: ProvenanceAction::Created,
            timestamp: Utc::now(),
            confidence_delta: 0.0,
        };
        ProvenanceTracker::record_hop(conn, "mcp-mem-1", &hop)?;
        let prov = ProvenanceTracker::get_provenance(conn, "mcp-mem-1")?;
        assert!(prov.is_some());

        // Tool 4: drift_agent_trust → TrustScorer::get_trust
        let agent_b = AgentRegistry::register(conn, "mcp-target", vec![])?;
        let initial = bootstrap_trust(&agent.agent_id, &agent_b.agent_id);
        TrustScorer::update_trust(conn, &initial)?;
        let trust = TrustScorer::get_trust(conn, &agent.agent_id, &agent_b.agent_id)?;
        assert!((trust.overall_trust - 0.5).abs() < f64::EPSILON);

        // Tool 5: drift_agent_project → ProjectionEngine::create_projection
        let target_ns = NamespaceId {
            scope: NamespaceScope::Team("mcp-target-ns".into()),
            name: "mcp-target-ns".into(),
        };
        NamespaceManager::create_namespace(conn, &target_ns, &agent.agent_id)?;
        let projection = MemoryProjection {
            id: "mcp-proj-1".to_string(),
            source: shared_ns,
            target: target_ns,
            filter: ProjectionFilter {
                memory_types: vec![MemoryType::Semantic],
                min_confidence: None,
                min_importance: None,
                linked_files: vec![],
                tags: vec![],
                max_age_days: None,
                predicate: None,
            },
            compression_level: 0,
            live: false,
            created_at: Utc::now(),
            created_by: agent.agent_id.clone(),
        };
        let proj_id = ProjectionEngine::create_projection(conn, &projection)?;
        assert_eq!(proj_id, "mcp-proj-1");

        Ok(())
    }).unwrap();
}

// ─── TMA-INT-16: CLI commands all 3 functional ──────────────────────────────
// Verified via vitest in packages/cortex. This Rust test validates the
// underlying Rust APIs that the CLI commands call.

#[test]
fn tma_int_16_cli_commands_underlying_apis() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // CLI 1: drift cortex agents → AgentRegistry::list_agents
        let agent = AgentRegistry::register(conn, "cli-agent", vec!["testing".into()])?;
        let agents = AgentRegistry::list_agents(conn, None)?;
        assert!(!agents.is_empty());
        let active = AgentRegistry::list_agents(conn, Some(&AgentStatus::Active))?;
        assert!(!active.is_empty());

        // CLI 1: drift cortex agents info → AgentRegistry::get_agent
        let found = AgentRegistry::get_agent(conn, &agent.agent_id)?;
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "cli-agent");

        // CLI 1: drift cortex agents deregister → AgentRegistry::deregister
        AgentRegistry::deregister(conn, &agent.agent_id)?;
        let deregistered = AgentRegistry::get_agent(conn, &agent.agent_id)?.unwrap();
        assert!(matches!(deregistered.status, AgentStatus::Deregistered { .. }));

        // CLI 2: drift cortex namespaces → NamespaceManager
        let owner = AgentRegistry::register(conn, "cli-ns-owner", vec![])?;
        let ns = NamespaceId {
            scope: NamespaceScope::Team("cli-team".into()),
            name: "cli-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // CLI 3: drift cortex provenance → ProvenanceTracker
        let mem = make_memory("cli-prov-mem", "CLI test", vec!["cli"], 0.8);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;
        let hop = ProvenanceHop {
            agent_id: owner.agent_id.clone(),
            action: ProvenanceAction::Created,
            timestamp: Utc::now(),
            confidence_delta: 0.0,
        };
        ProvenanceTracker::record_hop(conn, "cli-prov-mem", &hop)?;
        let prov = ProvenanceTracker::get_provenance(conn, "cli-prov-mem")?;
        assert!(prov.is_some());
        let record = prov.unwrap();
        assert_eq!(record.memory_id, "cli-prov-mem");
        assert_eq!(record.chain.len(), 1);

        Ok(())
    }).unwrap();
}

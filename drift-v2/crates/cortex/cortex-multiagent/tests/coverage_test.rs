//! Public API surface coverage tests for cortex-multiagent (PMF-TEST-01).
//!
//! Ensures all public API surface is exercised. Follows the pattern from
//! cortex-causal/tests/coverage_test.rs.

use std::collections::HashMap;

use chrono::Utc;
use cortex_core::config::MultiAgentConfig;
use cortex_core::memory::*;
use cortex_core::models::agent::{AgentId, AgentStatus};
use cortex_core::models::cross_agent::{AgentTrust, ContradictionResolution, TrustEvidence};
use cortex_core::models::namespace::{
    NamespaceId, NamespacePermission, NamespaceScope, ProjectionFilter,
};
use cortex_core::models::provenance::{ProvenanceAction, ProvenanceHop};
use cortex_crdt::VectorClock;
use cortex_storage::StorageEngine;

use cortex_multiagent::consolidation::ConsensusDetector;
use cortex_multiagent::namespace::addressing;
use cortex_multiagent::namespace::permissions::NamespacePermissionManager;
use cortex_multiagent::namespace::NamespaceManager;
use cortex_multiagent::projection::ProjectionEngine;
use cortex_multiagent::provenance::correction::CorrectionPropagator;
use cortex_multiagent::provenance::ProvenanceTracker;
use cortex_multiagent::registry::AgentRegistry;
use cortex_multiagent::share;
use cortex_multiagent::sync::causal_delivery::CausalDeliveryManager;
use cortex_multiagent::sync::cloud_integration::{CloudSyncAdapter, SyncTransport};
use cortex_multiagent::sync::delta_queue::DeltaQueue;
use cortex_multiagent::trust::bootstrap::{bootstrap_from_parent, bootstrap_trust};
use cortex_multiagent::trust::decay::apply_trust_decay;
use cortex_multiagent::trust::evidence::TrustEvidenceTracker;
use cortex_multiagent::trust::scorer::TrustScorer;
use cortex_multiagent::validation::CrossAgentValidator;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

fn make_memory(id: &str, summary: &str) -> BaseMemory {
    let content = TypedContent::Semantic(cortex_core::memory::types::SemanticContent {
        knowledge: summary.to_string(),
        source_episodes: vec![],
        consolidation_confidence: 0.8,
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Semantic,
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
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}


// ─── Registry Coverage ───────────────────────────────────────────────────────

#[test]
fn cov_registry_register_and_get() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg = AgentRegistry::register(conn, "cov-agent", vec!["code_review".into()])?;
        assert!(!reg.agent_id.0.is_empty());
        assert_eq!(reg.name, "cov-agent");
        assert_eq!(reg.capabilities, vec!["code_review"]);
        assert!(matches!(reg.status, AgentStatus::Active));

        let found = AgentRegistry::get_agent(conn, &reg.agent_id)?.unwrap();
        assert_eq!(found.agent_id, reg.agent_id);
        Ok(())
    }).unwrap();
}

#[test]
fn cov_registry_list_agents() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        AgentRegistry::register(conn, "list-a", vec![])?;
        AgentRegistry::register(conn, "list-b", vec![])?;
        let all = AgentRegistry::list_agents(conn, None)?;
        assert!(all.len() >= 2);
        let active = AgentRegistry::list_agents(conn, Some(&AgentStatus::Active))?;
        assert!(active.len() >= 2);
        Ok(())
    }).unwrap();
}

#[test]
fn cov_registry_deregister() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg = AgentRegistry::register(conn, "dereg-agent", vec![])?;
        AgentRegistry::deregister(conn, &reg.agent_id)?;
        let found = AgentRegistry::get_agent(conn, &reg.agent_id)?.unwrap();
        assert!(matches!(found.status, AgentStatus::Deregistered { .. }));
        Ok(())
    }).unwrap();
}

#[test]
fn cov_registry_mark_idle() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg = AgentRegistry::register(conn, "idle-agent", vec![])?;
        AgentRegistry::mark_idle(conn, &reg.agent_id)?;
        let found = AgentRegistry::get_agent(conn, &reg.agent_id)?.unwrap();
        assert!(matches!(found.status, AgentStatus::Idle { .. }));
        Ok(())
    }).unwrap();
}

#[test]
fn cov_registry_update_last_active() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg = AgentRegistry::register(conn, "active-agent", vec![])?;
        AgentRegistry::update_last_active(conn, &reg.agent_id)?;
        Ok(())
    }).unwrap();
}

#[test]
fn cov_registry_empty_name_rejected() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let result = AgentRegistry::register(conn, "", vec![]);
        assert!(result.is_err());
        Ok(())
    }).unwrap();
}

// ─── Namespace Coverage ──────────────────────────────────────────────────────

#[test]
fn cov_namespace_addressing_parse_all_scopes() {
    let agent = addressing::parse("agent://myagent/").unwrap();
    assert!(addressing::is_agent(&agent));
    assert!(!addressing::is_shared(&agent));

    let team = addressing::parse("team://backend/").unwrap();
    assert!(addressing::is_team(&team));
    assert!(addressing::is_shared(&team));

    let project = addressing::parse("project://cortex/").unwrap();
    assert!(addressing::is_project(&project));
    assert!(addressing::is_shared(&project));
}

#[test]
fn cov_namespace_addressing_default() {
    let ns = addressing::default_namespace();
    assert_eq!(addressing::to_uri(&ns), "agent://default/");
}

#[test]
fn cov_namespace_addressing_invalid_uri() {
    assert!(addressing::parse("invalid").is_err());
    assert!(addressing::parse("unknown://test/").is_err());
    assert!(addressing::parse("agent:///").is_err());
}

#[test]
fn cov_namespace_manager_crud() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "ns-owner", vec![])?;
        let ns = NamespaceId {
            scope: NamespaceScope::Team("test-team".into()),
            name: "test-team".into(),
        };
        let created = NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;
        assert_eq!(created.to_uri(), "team://test-team/");
        Ok(())
    }).unwrap();
}

#[test]
fn cov_namespace_permissions_grant_revoke() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "perm-owner", vec![])?;
        let guest = AgentRegistry::register(conn, "perm-guest", vec![])?;
        let ns = NamespaceId {
            scope: NamespaceScope::Team("perm-team".into()),
            name: "perm-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        NamespacePermissionManager::grant(
            conn, &ns, &guest.agent_id,
            &[NamespacePermission::Read],
            &owner.agent_id,
        )?;
        assert!(NamespacePermissionManager::check(conn, &ns, &guest.agent_id, NamespacePermission::Read)?);

        NamespacePermissionManager::revoke(conn, &ns, &guest.agent_id, &[NamespacePermission::Read], &owner.agent_id)?;
        assert!(!NamespacePermissionManager::check(conn, &ns, &guest.agent_id, NamespacePermission::Read)?);
        Ok(())
    }).unwrap();
}

// ─── Projection Coverage ─────────────────────────────────────────────────────

#[test]
fn cov_projection_filter_evaluation() {
    let mem = make_memory("filter-mem", "test memory");
    let filter = ProjectionFilter {
        memory_types: vec![MemoryType::Semantic],
        min_confidence: Some(0.5),
        min_importance: None,
        linked_files: vec![],
        tags: vec!["test".to_string()],
        max_age_days: None,
        predicate: None,
    };
    assert!(ProjectionEngine::evaluate_filter(&mem, &filter));

    let filter_no_match = ProjectionFilter {
        memory_types: vec![MemoryType::Episodic],
        ..filter.clone()
    };
    assert!(!ProjectionEngine::evaluate_filter(&mem, &filter_no_match));
}

// ─── Trust Coverage ──────────────────────────────────────────────────────────

#[test]
fn cov_trust_bootstrap_new_agent() {
    let trust = bootstrap_trust(&AgentId::from("a"), &AgentId::from("b"));
    assert!((trust.overall_trust - 0.5).abs() < f64::EPSILON);
    assert_eq!(trust.evidence.total_received, 0);
}

#[test]
fn cov_trust_bootstrap_from_parent() {
    let parent = AgentTrust {
        agent_id: AgentId::from("observer"),
        target_agent: AgentId::from("parent"),
        overall_trust: 0.8,
        domain_trust: {
            let mut m = HashMap::new();
            m.insert("code".to_string(), 0.9);
            m
        },
        evidence: TrustEvidence {
            validated_count: 10,
            contradicted_count: 0,
            useful_count: 5,
            total_received: 15,
        },
        last_updated: Utc::now(),
    };
    let spawned = bootstrap_from_parent(&parent, &AgentId::from("child"), 0.8);
    assert!((spawned.overall_trust - 0.64).abs() < 0.001);
    assert!((spawned.domain_trust["code"] - 0.72).abs() < 0.001);
    assert_eq!(spawned.evidence.total_received, 0);
}

#[test]
fn cov_trust_compute_overall() {
    let evidence = TrustEvidence {
        validated_count: 10,
        contradicted_count: 2,
        useful_count: 3,
        total_received: 20,
    };
    let trust = TrustScorer::compute_overall_trust(&evidence);
    assert!((0.0..=1.0).contains(&trust));
}

#[test]
fn cov_trust_decay_toward_neutral() {
    let mut trust = AgentTrust {
        agent_id: AgentId::from("a"),
        target_agent: AgentId::from("b"),
        overall_trust: 0.9,
        domain_trust: Default::default(),
        evidence: TrustEvidence::default(),
        last_updated: Utc::now(),
    };
    apply_trust_decay(&mut trust, 100.0, 0.99);
    assert!(trust.overall_trust < 0.9);
    assert!(trust.overall_trust > 0.5);
}

#[test]
fn cov_trust_decay_low_trust_increases() {
    let mut trust = AgentTrust {
        agent_id: AgentId::from("a"),
        target_agent: AgentId::from("b"),
        overall_trust: 0.1,
        domain_trust: Default::default(),
        evidence: TrustEvidence::default(),
        last_updated: Utc::now(),
    };
    apply_trust_decay(&mut trust, 100.0, 0.99);
    assert!(trust.overall_trust > 0.1);
    assert!(trust.overall_trust < 0.5);
}

#[test]
fn cov_trust_evidence_record_and_get() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let a = AgentRegistry::register(conn, "ev-a", vec![])?;
        let b = AgentRegistry::register(conn, "ev-b", vec![])?;
        let initial = bootstrap_trust(&a.agent_id, &b.agent_id);
        TrustScorer::update_trust(conn, &initial)?;

        TrustEvidenceTracker::record_validation(conn, &a.agent_id, &b.agent_id, "mem-1")?;
        TrustEvidenceTracker::record_contradiction(conn, &a.agent_id, &b.agent_id, "mem-2")?;
        TrustEvidenceTracker::record_usage(conn, &a.agent_id, &b.agent_id, "mem-3")?;

        let trust = TrustScorer::get_trust(conn, &a.agent_id, &b.agent_id)?;
        assert!(trust.evidence.validated_count >= 1);
        assert!(trust.evidence.contradicted_count >= 1);
        assert!(trust.evidence.useful_count >= 1);
        Ok(())
    }).unwrap();
}

// ─── Provenance Coverage ─────────────────────────────────────────────────────

#[test]
fn cov_provenance_record_and_chain() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "prov-agent", vec![])?;
        let mem = make_memory("prov-mem", "test provenance");
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        let hop = ProvenanceHop {
            agent_id: agent.agent_id.clone(),
            action: ProvenanceAction::Created,
            timestamp: Utc::now(),
            confidence_delta: 0.0,
        };
        ProvenanceTracker::record_hop(conn, "prov-mem", &hop)?;

        let chain = ProvenanceTracker::get_chain(conn, "prov-mem")?;
        assert_eq!(chain.len(), 1);

        let confidence = ProvenanceTracker::chain_confidence(conn, "prov-mem")?;
        assert!((confidence - 1.0).abs() < 0.001);
        Ok(())
    }).unwrap();
}

#[test]
fn cov_provenance_correction_strength() {
    let config = MultiAgentConfig::default();
    let propagator = CorrectionPropagator::new(&config);
    assert!((propagator.correction_strength(0) - 1.0).abs() < f64::EPSILON);
    assert!((propagator.correction_strength(1) - 0.7).abs() < 0.001);
    assert!((propagator.correction_strength(2) - 0.49).abs() < 0.001);
}

// ─── Sync Coverage ───────────────────────────────────────────────────────────

#[test]
fn cov_causal_delivery_manager() {
    let manager = CausalDeliveryManager::new();
    let mut local = VectorClock::new();
    local.increment("A");

    // In-order delta: can apply ({A:2} when local is {A:1}).
    let mut delta_clock = VectorClock::new();
    delta_clock.increment("A");
    delta_clock.increment("A");
    assert!(manager.can_apply_clock(&delta_clock, &local));

    // Out-of-order: cannot apply ({A:3} when local is {A:1}, missing A:2).
    let mut future_clock = VectorClock::new();
    future_clock.increment("A");
    future_clock.increment("A");
    future_clock.increment("A");
    assert!(!manager.can_apply_clock(&future_clock, &local));
}

#[test]
fn cov_delta_queue_enqueue_dequeue() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let a = AgentRegistry::register(conn, "dq-a", vec![])?;
        let b = AgentRegistry::register(conn, "dq-b", vec![])?;
        let clock = VectorClock::new();

        DeltaQueue::enqueue(conn, &a.agent_id.0, &b.agent_id.0, "mem-1", "{}", &clock, 0)?;
        let pending = DeltaQueue::pending_count(conn, &b.agent_id.0)?;
        assert!(pending >= 1);

        let deltas = DeltaQueue::dequeue(conn, &b.agent_id.0, 10)?;
        assert!(!deltas.is_empty());
        Ok(())
    }).unwrap();
}

#[test]
fn cov_cloud_sync_detect_mode() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "cloud-agent", vec![])?;
        let mode = CloudSyncAdapter::detect_sync_mode(conn, &agent.agent_id)?;
        assert!(matches!(mode, SyncTransport::Local));
        Ok(())
    }).unwrap();
}

// ─── Validation Coverage ─────────────────────────────────────────────────────

#[test]
fn cov_validation_contradiction_detection() {
    let config = MultiAgentConfig::default();
    let validator = CrossAgentValidator::new(&config);

    let mut mem_a = make_memory("val-a", "Auth uses JWT");
    mem_a.source_agent = AgentId::from("agent-a");
    let mut mem_b = make_memory("val-b", "Auth uses session cookies");
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
    assert!(matches!(
        contradictions[0].resolution,
        ContradictionResolution::TrustWins
    ));
}

// ─── Consensus Coverage ──────────────────────────────────────────────────────

#[test]
fn cov_consensus_not_enough_agents() {
    let config = MultiAgentConfig {
        consensus_min_agents: 3,
        ..Default::default()
    };
    let detector = ConsensusDetector::new(&config);

    let mut memories: HashMap<AgentId, Vec<BaseMemory>> = HashMap::new();
    memories.insert(AgentId::from("a"), vec![make_memory("m1", "test")]);

    let sim_fn = |_a: &BaseMemory, _b: &BaseMemory| -> f64 { 1.0 };
    let candidates = detector.detect_consensus(&memories, &sim_fn, 0.9).unwrap();
    assert!(candidates.is_empty());
}

// ─── Share Coverage ──────────────────────────────────────────────────────────

#[test]
fn cov_share_permission_denied() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "share-owner", vec![])?;
        let guest = AgentRegistry::register(conn, "share-guest", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("share-team".into()),
            name: "share-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Guest has no write permission → share should fail.
        let result = share::share(conn, "some-mem", &ns, &guest.agent_id);
        assert!(result.is_err());
        Ok(())
    }).unwrap();
}

// ─── MultiAgentConfig Coverage ───────────────────────────────────────────────

#[test]
fn cov_config_defaults() {
    let config = MultiAgentConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.default_namespace, "agent://default/");
    assert!((config.trust_bootstrap_score - 0.5).abs() < f64::EPSILON);
    assert!((config.correction_dampening_factor - 0.7).abs() < f64::EPSILON);
    assert!((config.correction_min_threshold - 0.05).abs() < f64::EPSILON);
    assert!((config.consensus_similarity_threshold - 0.9).abs() < f64::EPSILON);
    assert_eq!(config.consensus_min_agents, 2);
    assert!((config.consensus_confidence_boost - 0.2).abs() < f64::EPSILON);
    assert!((config.contradiction_trust_auto_resolve_threshold - 0.3).abs() < f64::EPSILON);
}

// ─── TrustEvidence Coverage ──────────────────────────────────────────────────

#[test]
fn cov_trust_evidence_compute_trust() {
    let evidence = TrustEvidence {
        validated_count: 0,
        contradicted_count: 0,
        useful_count: 0,
        total_received: 0,
    };
    let trust = evidence.compute_trust();
    assert!((trust - 0.0).abs() < f64::EPSILON);

    let evidence2 = TrustEvidence {
        validated_count: 10,
        contradicted_count: 0,
        useful_count: 0,
        total_received: 10,
    };
    let trust2 = evidence2.compute_trust();
    assert!(trust2 > 0.0 && trust2 <= 1.0);
}

// ─── VectorClock Coverage ────────────────────────────────────────────────────

#[test]
fn cov_vector_clock_operations() {
    let mut a = VectorClock::new();
    let mut b = VectorClock::new();

    a.increment("agent-1");
    a.increment("agent-1");
    b.increment("agent-2");

    assert!(a.get("agent-1") == 2);
    assert!(b.get("agent-2") == 1);
    assert!(a.concurrent_with(&b));

    let mut merged = a.clone();
    merged.merge(&b);
    assert!(merged.get("agent-1") == 2);
    assert!(merged.get("agent-2") == 1);
}

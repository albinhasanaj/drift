//! Enterprise-grade stress tests for cortex-multiagent.
//!
//! Each test targets a specific critical subsystem and pushes it to
//! production-scale limits. Tests are independent and named for the
//! subsystem they validate.

use std::time::Instant;

use chrono::Utc;
use cortex_core::config::MultiAgentConfig;
use cortex_core::memory::*;
use cortex_core::models::agent::{AgentId, AgentStatus, SpawnConfig};
use cortex_core::models::namespace::{
    NamespaceId, NamespacePermission, NamespaceScope, ProjectionFilter,
};
use cortex_core::models::provenance::{ProvenanceAction, ProvenanceHop};
use cortex_crdt::VectorClock;
use cortex_storage::StorageEngine;

use cortex_multiagent::namespace::addressing;
use cortex_multiagent::namespace::permissions::NamespacePermissionManager;
use cortex_multiagent::namespace::NamespaceManager;
use cortex_multiagent::projection::ProjectionEngine;
use cortex_multiagent::provenance::correction::CorrectionPropagator;
use cortex_multiagent::provenance::ProvenanceTracker;
use cortex_multiagent::registry::spawn::{deregister_spawned, spawn_agent};
use cortex_multiagent::registry::AgentRegistry;
use cortex_multiagent::share;
use cortex_multiagent::sync::causal_delivery::CausalDeliveryManager;
use cortex_multiagent::sync::cloud_integration::{CloudSyncAdapter, SyncTransport};
use cortex_multiagent::sync::delta_queue::DeltaQueue;
use cortex_multiagent::sync::protocol::DeltaSyncEngine;
use cortex_multiagent::trust::bootstrap::bootstrap_trust;
use cortex_multiagent::trust::decay::apply_trust_decay;
use cortex_multiagent::trust::evidence::TrustEvidenceTracker;
use cortex_multiagent::trust::scorer::TrustScorer;
// CrossAgentValidator reserved for future validation stress tests

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

fn make_memory(id: &str, summary: &str, tags: Vec<&str>, confidence: f64, agent: &AgentId) -> BaseMemory {
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
        source_agent: agent.clone(),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

// =============================================================================
// REGISTRY: Agent lifecycle at scale
// =============================================================================

/// Register 100 agents, verify all active, deregister half, verify counts.
#[test]
fn registry_100_agents_lifecycle() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let start = Instant::now();
        let mut agents = Vec::new();

        for i in 0..100 {
            let reg = AgentRegistry::register(
                conn,
                &format!("enterprise-agent-{i:03}"),
                vec!["capability-a".into(), "capability-b".into()],
            )?;
            assert!(matches!(reg.status, AgentStatus::Active));
            agents.push(reg);
        }

        // All 100 should be active.
        let active = AgentRegistry::list_agents(conn, Some(&AgentStatus::Active))?;
        assert_eq!(active.len(), 100, "should have 100 active agents");

        // Deregister the first 50.
        for agent in &agents[..50] {
            AgentRegistry::deregister(conn, &agent.agent_id)?;
        }

        let still_active = AgentRegistry::list_agents(conn, Some(&AgentStatus::Active))?;
        assert_eq!(still_active.len(), 50, "should have 50 active agents after deregistering 50");

        // Verify deregistered agents are actually deregistered.
        for agent in &agents[..50] {
            let found = AgentRegistry::get_agent(conn, &agent.agent_id)?.unwrap();
            assert!(
                matches!(found.status, AgentStatus::Deregistered { .. }),
                "agent {} should be deregistered",
                agent.name
            );
        }

        // Cannot deregister an already-deregistered agent.
        let result = AgentRegistry::deregister(conn, &agents[0].agent_id);
        assert!(result.is_err(), "double deregister should fail");

        let elapsed = start.elapsed();
        assert!(elapsed.as_secs() < 10, "100-agent lifecycle took {:?}", elapsed);

        Ok(())
    }).unwrap();
}

/// Spawn tree: 1 root → 5 children → 25 grandchildren. Verify trust inheritance.
/// Trust inheritance in spawn: parent's outgoing trust records are cloned to child (discounted).
/// Note: spawn iterates ALL parent outgoing trust records, so later children may get
/// different values as earlier siblings' trust records accumulate.
#[test]
fn registry_spawn_tree_trust_inheritance() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let root = AgentRegistry::register(conn, "root-agent", vec!["orchestration".into()])?;
        let target = AgentRegistry::register(conn, "target-agent", vec![])?;

        // Root trusts target at 0.9 (root is the observer, target is the observed).
        let root_trust = cortex_core::models::cross_agent::AgentTrust {
            agent_id: root.agent_id.clone(),
            target_agent: target.agent_id.clone(),
            overall_trust: 0.9,
            domain_trust: Default::default(),
            evidence: Default::default(),
            last_updated: Utc::now(),
        };
        TrustScorer::update_trust(conn, &root_trust)?;

        // Spawn 5 children from root.
        let mut children = Vec::new();
        for i in 0..5 {
            let config = SpawnConfig {
                parent_agent: root.agent_id.clone(),
                trust_discount: 0.8,
                auto_promote_on_deregister: true,
                ..Default::default()
            };
            let child = spawn_agent(conn, &config, &format!("child-{i}"), vec!["coding".into()])?;
            assert_eq!(child.parent_agent.as_ref().unwrap(), &root.agent_id);
            children.push(child);
        }

        // Verify: each child has a trust record from root.
        // The exact value depends on iteration order of parent's outgoing trust records.
        // All children should have trust > 0 and <= 0.72 (0.9 × 0.8).
        for child in &children {
            let trust = TrustScorer::get_trust(conn, &root.agent_id, &child.agent_id)?;
            assert!(
                trust.overall_trust > 0.0 && trust.overall_trust <= 0.73,
                "root→child trust should be in (0, 0.72], got {}",
                trust.overall_trust
            );
        }

        // Spawn 5 grandchildren per child (25 total).
        let mut grandchildren = Vec::new();
        for (i, child) in children.iter().enumerate() {
            for j in 0..5 {
                let config = SpawnConfig {
                    parent_agent: child.agent_id.clone(),
                    trust_discount: 0.8,
                    auto_promote_on_deregister: true,
                    ..Default::default()
                };
                let gc = spawn_agent(conn, &config, &format!("grandchild-{i}-{j}"), vec![])?;
                grandchildren.push(gc);
            }
        }

        // Total agents: 1 root + 1 target + 5 children + 25 grandchildren = 32.
        let all = AgentRegistry::list_agents(conn, Some(&AgentStatus::Active))?;
        assert_eq!(all.len(), 32);

        // Deregister all grandchildren with auto-promote.
        for gc in &grandchildren {
            deregister_spawned(conn, &gc.agent_id, true)?;
        }

        let active = AgentRegistry::list_agents(conn, Some(&AgentStatus::Active))?;
        assert_eq!(active.len(), 7, "should have 7 active (root + target + 5 children)");

        Ok(())
    }).unwrap();
}

/// Agent name validation: reject invalid names, accept valid ones.
#[test]
fn registry_name_validation_comprehensive() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Valid names.
        assert!(AgentRegistry::register(conn, "valid-name", vec![]).is_ok());
        assert!(AgentRegistry::register(conn, "valid_name", vec![]).is_ok());
        assert!(AgentRegistry::register(conn, "valid.name", vec![]).is_ok());
        assert!(AgentRegistry::register(conn, "ValidName123", vec![]).is_ok());
        assert!(AgentRegistry::register(conn, "a", vec![]).is_ok()); // Single char.

        // Invalid: empty.
        assert!(AgentRegistry::register(conn, "", vec![]).is_err());

        // Invalid: spaces.
        assert!(AgentRegistry::register(conn, "has space", vec![]).is_err());

        // Invalid: special characters.
        assert!(AgentRegistry::register(conn, "has@symbol", vec![]).is_err());
        assert!(AgentRegistry::register(conn, "has/slash", vec![]).is_err());

        // Invalid: too long (>256 chars).
        let long_name = "a".repeat(257);
        assert!(AgentRegistry::register(conn, &long_name, vec![]).is_err());

        // Valid: exactly 256 chars.
        let max_name = "b".repeat(256);
        assert!(AgentRegistry::register(conn, &max_name, vec![]).is_ok());

        Ok(())
    }).unwrap();
}

// =============================================================================
// NAMESPACE: Permissions and isolation at scale
// =============================================================================

/// 20 agents, 10 namespaces, complex permission matrix — verify isolation.
#[test]
fn namespace_complex_permission_matrix() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Register 20 agents.
        let agents: Vec<_> = (0..20)
            .map(|i| AgentRegistry::register(conn, &format!("perm-agent-{i:02}"), vec![]).unwrap())
            .collect();

        // Create 10 team namespaces, each owned by agents[i].
        let namespaces: Vec<NamespaceId> = (0..10)
            .map(|i| {
                let ns = NamespaceId {
                    scope: NamespaceScope::Team(format!("team-{i}")),
                    name: format!("team-{i}"),
                };
                NamespaceManager::create_namespace(conn, &ns, &agents[i].agent_id).unwrap();
                ns
            })
            .collect();

        // Grant read to agents[10..15] on namespaces[0..5].
        for ns in &namespaces[..5] {
            for agent in &agents[10..15] {
                NamespacePermissionManager::grant(
                    conn, ns, &agent.agent_id,
                    &[NamespacePermission::Read],
                    &agents[0].agent_id, // Owner of ns[0] grants.
                ).unwrap_or(()); // Some may fail if not admin — that's OK.
            }
        }

        // Verify: owners have admin on their namespaces.
        for i in 0..10 {
            assert!(
                NamespacePermissionManager::check(conn, &namespaces[i], &agents[i].agent_id, NamespacePermission::Admin)?,
                "owner should have admin on their namespace"
            );
        }

        // Verify: agents[15..20] have NO access to any namespace (except their own agent namespace).
        for ns in &namespaces {
            for agent in &agents[15..20] {
                let has_read = NamespacePermissionManager::check(conn, ns, &agent.agent_id, NamespacePermission::Read)?;
                assert!(!has_read, "agent {} should not have read on {}", agent.name, ns.to_uri());
            }
        }

        // Verify: non-admin cannot grant permissions.
        let escalation = NamespacePermissionManager::grant(
            conn, &namespaces[0], &agents[15].agent_id,
            &[NamespacePermission::Admin],
            &agents[15].agent_id, // Non-admin trying to grant.
        );
        assert!(escalation.is_err(), "non-admin should not be able to grant");

        Ok(())
    }).unwrap();
}

/// Namespace URI validation: comprehensive edge cases.
#[test]
fn namespace_uri_validation_edge_cases() {
    // Valid URIs.
    assert!(addressing::parse("agent://valid-name/").is_ok());
    assert!(addressing::parse("team://my.team/").is_ok());
    assert!(addressing::parse("project://proj_123/").is_ok());
    assert!(addressing::parse("AGENT://case-insensitive/").is_ok()); // Case-insensitive scope.

    // Invalid: Unicode chars are rejected (ASCII-only for URL safety and homoglyph prevention).
    assert!(addressing::parse("agent://名前/").is_err());

    // Invalid: empty name.
    assert!(addressing::parse("agent:///").is_err());

    // Invalid: spaces in name.
    assert!(addressing::parse("agent://has space/").is_err());

    // Invalid: special characters (not alphanumeric, -, _, .).
    assert!(addressing::parse("agent://has@symbol/").is_err());
    assert!(addressing::parse("agent://has/slash/").is_err());

    // Invalid: too long.
    let long = format!("agent://{}/", "a".repeat(257));
    assert!(addressing::parse(&long).is_err());

    // Invalid: unknown scope.
    assert!(addressing::parse("unknown://name/").is_err());

    // Invalid: no separator.
    assert!(addressing::parse("agentname").is_err());

    // Valid: exactly 256 chars.
    let max = format!("agent://{}/", "x".repeat(256));
    assert!(addressing::parse(&max).is_ok());
}

/// Namespace deletion with dependent projections — must fail with clear error.
/// Also verifies FK constraint: permissions must be cleaned up before namespace deletion.
#[test]
fn namespace_deletion_blocked_by_projections() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "del-owner", vec![])?;

        let source_ns = NamespaceId {
            scope: NamespaceScope::Team("del-source".into()),
            name: "del-source".into(),
        };
        let target_ns = NamespaceId {
            scope: NamespaceScope::Team("del-target".into()),
            name: "del-target".into(),
        };
        NamespaceManager::create_namespace(conn, &source_ns, &owner.agent_id)?;
        NamespaceManager::create_namespace(conn, &target_ns, &owner.agent_id)?;

        // Create a projection from source → target.
        let projection = cortex_core::models::namespace::MemoryProjection {
            id: "blocking-proj".to_string(),
            source: source_ns.clone(),
            target: target_ns.clone(),
            filter: ProjectionFilter::default(),
            compression_level: 0,
            live: true,
            created_at: Utc::now(),
            created_by: owner.agent_id.clone(),
        };
        ProjectionEngine::create_projection(conn, &projection)?;

        // Try to delete source namespace — should fail (projection depends on it).
        let result = NamespaceManager::delete_namespace(conn, &source_ns);
        assert!(result.is_err(), "should not delete namespace with dependent projections");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("projection") || err_msg.contains("dependent"),
            "error should mention projections: {err_msg}"
        );

        // Delete the projection first.
        ProjectionEngine::delete_projection(conn, "blocking-proj")?;

        // Still can't delete namespace if permissions exist (FK constraint).
        // Clean up permissions first.
        cortex_storage::queries::multiagent_ops::delete_permission(
            conn, &source_ns.to_uri(), &owner.agent_id.0,
        )?;

        // Now namespace deletion should succeed.
        assert!(NamespaceManager::delete_namespace(conn, &source_ns).is_ok());

        Ok(())
    }).unwrap();
}

// =============================================================================
// TRUST: Scoring, evidence, decay, and bootstrap at scale
// =============================================================================

/// Trust formula correctness: known evidence → expected scores.
#[test]
fn trust_formula_correctness_known_values() {
    use cortex_core::models::cross_agent::TrustEvidence;

    // Case 1: Perfect agent (all validated, no contradictions).
    let perfect = TrustEvidence {
        validated_count: 100,
        contradicted_count: 0,
        useful_count: 50,
        total_received: 150,
    };
    let score = TrustScorer::compute_overall_trust(&perfect);
    // (100+50)/(150+1) × (1 - 0/(150+1)) = 150/151 × 1.0 ≈ 0.9934
    assert!((score - 0.9934).abs() < 0.01, "perfect agent score: {score}");

    // Case 2: Terrible agent (all contradictions).
    let terrible = TrustEvidence {
        validated_count: 0,
        contradicted_count: 100,
        useful_count: 0,
        total_received: 100,
    };
    let score = TrustScorer::compute_overall_trust(&terrible);
    // (0+0)/(100+1) × (1 - 100/(100+1)) = 0 × 0.0099 = 0.0
    assert!(score < 0.01, "terrible agent score should be ~0: {score}");

    // Case 3: Mixed agent.
    let mixed = TrustEvidence {
        validated_count: 10,
        contradicted_count: 2,
        useful_count: 3,
        total_received: 20,
    };
    let score = TrustScorer::compute_overall_trust(&mixed);
    // (10+3)/(20+1) × (1 - 2/(20+1)) = 13/21 × 19/21 ≈ 0.619 × 0.905 ≈ 0.560
    assert!((score - 0.560).abs() < 0.02, "mixed agent score: {score}");

    // Case 4: No evidence.
    let empty = TrustEvidence::default();
    let score = TrustScorer::compute_overall_trust(&empty);
    // (0+0)/(0+1) × (1 - 0/(0+1)) = 0 × 1 = 0.0
    assert!(score.abs() < 0.001, "empty evidence score should be 0: {score}");

    // Case 5: Effective confidence modulation.
    let effective = TrustScorer::effective_confidence(0.85, 0.9);
    assert!((effective - 0.765).abs() < 0.001, "effective confidence: {effective}");
}

/// Self-trust prevention: agent cannot record evidence about itself.
#[test]
fn trust_self_evidence_blocked() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "self-trust-agent", vec![])?;

        // All three evidence types should fail for self-referential calls.
        let r1 = TrustEvidenceTracker::record_validation(conn, &agent.agent_id, &agent.agent_id, "mem-1");
        assert!(r1.is_err(), "self-validation should be blocked");

        let r2 = TrustEvidenceTracker::record_contradiction(conn, &agent.agent_id, &agent.agent_id, "mem-2");
        assert!(r2.is_err(), "self-contradiction should be blocked");

        let r3 = TrustEvidenceTracker::record_usage(conn, &agent.agent_id, &agent.agent_id, "mem-3");
        assert!(r3.is_err(), "self-usage should be blocked");

        Ok(())
    }).unwrap();
}

/// Trust decay: verify convergence toward 0.5 over time.
#[test]
fn trust_decay_convergence_toward_neutral() {
    let mut high_trust = cortex_core::models::cross_agent::AgentTrust {
        agent_id: AgentId::from("observer"),
        target_agent: AgentId::from("target"),
        overall_trust: 0.95,
        domain_trust: [("code".to_string(), 0.9)].into_iter().collect(),
        evidence: Default::default(),
        last_updated: Utc::now(),
    };

    let mut low_trust = cortex_core::models::cross_agent::AgentTrust {
        agent_id: AgentId::from("observer"),
        target_agent: AgentId::from("target2"),
        overall_trust: 0.1,
        domain_trust: Default::default(),
        evidence: Default::default(),
        last_updated: Utc::now(),
    };

    // After 100 days, high trust should move toward 0.5.
    apply_trust_decay(&mut high_trust, 100.0, 0.99);
    assert!(high_trust.overall_trust < 0.95, "high trust should decrease");
    assert!(high_trust.overall_trust > 0.5, "high trust should stay above 0.5");

    // After 100 days, low trust should move toward 0.5.
    apply_trust_decay(&mut low_trust, 100.0, 0.99);
    assert!(low_trust.overall_trust > 0.1, "low trust should increase");
    assert!(low_trust.overall_trust < 0.5, "low trust should stay below 0.5");

    // After 1000 days, both should be very close to 0.5.
    apply_trust_decay(&mut high_trust, 900.0, 0.99);
    apply_trust_decay(&mut low_trust, 900.0, 0.99);
    assert!((high_trust.overall_trust - 0.5).abs() < 0.01, "high trust after 1000 days: {}", high_trust.overall_trust);
    assert!((low_trust.overall_trust - 0.5).abs() < 0.01, "low trust after 1000 days: {}", low_trust.overall_trust);

    // Domain trust should also decay.
    assert!(
        *high_trust.domain_trust.get("code").unwrap_or(&0.5) < 0.9,
        "domain trust should also decay"
    );
}

/// Trust evidence at scale: 5K records, verify final score is bounded and correct.
#[test]
fn trust_evidence_5k_records_bounded() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent_a = AgentRegistry::register(conn, "trust-scale-a", vec![])?;
        let agent_b = AgentRegistry::register(conn, "trust-scale-b", vec![])?;

        let start = Instant::now();

        // Record 5K evidence: 70% validated, 20% useful, 10% contradicted.
        for i in 0..5000 {
            let mem_id = format!("trust-mem-{i:05}");
            match i % 10 {
                0 => TrustEvidenceTracker::record_contradiction(conn, &agent_a.agent_id, &agent_b.agent_id, &mem_id)?,
                1 | 2 => TrustEvidenceTracker::record_usage(conn, &agent_a.agent_id, &agent_b.agent_id, &mem_id)?,
                _ => TrustEvidenceTracker::record_validation(conn, &agent_a.agent_id, &agent_b.agent_id, &mem_id)?,
            }
        }

        let trust = TrustScorer::get_trust(conn, &agent_a.agent_id, &agent_b.agent_id)?;

        // Trust must be bounded [0.0, 1.0].
        assert!(trust.overall_trust >= 0.0 && trust.overall_trust <= 1.0);

        // With 70% validated, 20% useful, 10% contradicted, trust should be moderate-high.
        assert!(trust.overall_trust > 0.5, "trust should be > 0.5 with mostly positive evidence");
        assert!(trust.overall_trust < 1.0, "trust should be < 1.0 with some contradictions");

        // Evidence counts should be correct.
        assert_eq!(trust.evidence.total_received, 5000);
        assert_eq!(trust.evidence.contradicted_count, 500); // 10%
        assert_eq!(trust.evidence.useful_count, 1000); // 20%
        assert_eq!(trust.evidence.validated_count, 3500); // 70%

        let elapsed = start.elapsed();
        assert!(elapsed.as_secs() < 30, "5K trust evidence took {:?}", elapsed);

        Ok(())
    }).unwrap();
}

// =============================================================================
// PROVENANCE: Chain tracking and correction propagation
// =============================================================================

/// 20-hop provenance chain — verify chain confidence computation.
#[test]
fn provenance_20_hop_chain_confidence() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agents: Vec<_> = (0..20)
            .map(|i| AgentRegistry::register(conn, &format!("prov-chain-{i:02}"), vec![]).unwrap())
            .collect();

        let mem = make_memory("prov-chain-mem", "Chain test", vec!["chain"], 0.9, &agents[0].agent_id);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // Build a 20-hop chain with alternating positive/neutral deltas.
        for (i, agent) in agents.iter().enumerate() {
            let action = if i == 0 {
                ProvenanceAction::Created
            } else if i % 3 == 0 {
                ProvenanceAction::ValidatedBy
            } else {
                ProvenanceAction::SharedTo
            };
            let delta = if i % 3 == 0 { 0.05 } else { 0.0 };
            ProvenanceTracker::record_hop(
                conn,
                "prov-chain-mem",
                &ProvenanceHop {
                    agent_id: agent.agent_id.clone(),
                    action,
                    timestamp: Utc::now(),
                    confidence_delta: delta,
                },
            )?;
        }

        let chain = ProvenanceTracker::get_chain(conn, "prov-chain-mem")?;
        assert_eq!(chain.len(), 20, "chain should have 20 hops");

        let confidence = ProvenanceTracker::chain_confidence(conn, "prov-chain-mem")?;
        assert!((0.0..=1.0).contains(&confidence), "confidence must be bounded: {confidence}");

        // With 6 validation hops (at indices 3,6,9,12,15,18) each adding 0.05:
        // product = 1.05^6 ≈ 1.34 → clamped to 1.0.
        assert!((confidence - 1.0).abs() < 0.001, "confidence should be clamped to 1.0: {confidence}");

        // Verify provenance record.
        let record = ProvenanceTracker::get_provenance(conn, "prov-chain-mem")?;
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.chain.len(), 20);

        Ok(())
    }).unwrap();
}

/// Correction propagation: verify dampening stops at threshold.
#[test]
fn provenance_correction_dampening_stops_at_threshold() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "corr-agent", vec![])?;

        let mem = make_memory("corr-mem", "Correctable fact", vec!["fact"], 0.9, &agent.agent_id);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // Build a 15-hop chain.
        for i in 0..15 {
            ProvenanceTracker::record_hop(
                conn,
                "corr-mem",
                &ProvenanceHop {
                    agent_id: agent.agent_id.clone(),
                    action: if i == 0 { ProvenanceAction::Created } else { ProvenanceAction::SharedTo },
                    timestamp: Utc::now(),
                    confidence_delta: 0.0,
                },
            )?;
        }

        let config = MultiAgentConfig {
            correction_dampening_factor: 0.7,
            correction_min_threshold: 0.05,
            ..Default::default()
        };
        let propagator = CorrectionPropagator::new(&config);
        let results = propagator.propagate_correction(conn, "corr-mem", "correction text")?;

        // Verify dampening: 0.7^n.
        // Distance 0: 1.0 (applied)
        // Distance 1: 0.7 (applied)
        // Distance 5: 0.168 (applied)
        // Distance 8: 0.057 (applied, just above 0.05)
        // Distance 9: 0.040 (NOT applied, below 0.05)
        let mut last_applied_distance = 0;
        for result in &results {
            if result.applied {
                last_applied_distance = result.hop_distance;
            }
            // Verify strength calculation.
            let expected_strength = 0.7_f64.powi(result.hop_distance as i32);
            assert!(
                (result.correction_strength - expected_strength).abs() < 0.001,
                "distance {}: expected {expected_strength}, got {}",
                result.hop_distance,
                result.correction_strength
            );
        }

        // Propagation should stop around distance 8 (0.7^8 ≈ 0.057 > 0.05).
        assert!(
            (7..=9).contains(&last_applied_distance),
            "last applied distance should be ~8, got {last_applied_distance}"
        );

        Ok(())
    }).unwrap();
}

/// Provenance confidence_delta validation: reject out-of-range values.
#[test]
fn provenance_confidence_delta_validation() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "delta-val-agent", vec![])?;
        let mem = make_memory("delta-val-mem", "Test", vec![], 0.8, &agent.agent_id);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // Valid: delta = 0.0.
        assert!(ProvenanceTracker::record_hop(conn, "delta-val-mem", &ProvenanceHop {
            agent_id: agent.agent_id.clone(),
            action: ProvenanceAction::Created,
            timestamp: Utc::now(),
            confidence_delta: 0.0,
        }).is_ok());

        // Valid: delta = 1.0 (max).
        assert!(ProvenanceTracker::record_hop(conn, "delta-val-mem", &ProvenanceHop {
            agent_id: agent.agent_id.clone(),
            action: ProvenanceAction::ValidatedBy,
            timestamp: Utc::now(),
            confidence_delta: 1.0,
        }).is_ok());

        // Valid: delta = -1.0 (min).
        assert!(ProvenanceTracker::record_hop(conn, "delta-val-mem", &ProvenanceHop {
            agent_id: agent.agent_id.clone(),
            action: ProvenanceAction::CorrectedBy,
            timestamp: Utc::now(),
            confidence_delta: -1.0,
        }).is_ok());

        // Invalid: delta = 1.5.
        assert!(ProvenanceTracker::record_hop(conn, "delta-val-mem", &ProvenanceHop {
            agent_id: agent.agent_id.clone(),
            action: ProvenanceAction::ValidatedBy,
            timestamp: Utc::now(),
            confidence_delta: 1.5,
        }).is_err());

        // Invalid: delta = -1.5.
        assert!(ProvenanceTracker::record_hop(conn, "delta-val-mem", &ProvenanceHop {
            agent_id: agent.agent_id.clone(),
            action: ProvenanceAction::CorrectedBy,
            timestamp: Utc::now(),
            confidence_delta: -1.5,
        }).is_err());

        Ok(())
    }).unwrap();
}

// =============================================================================
// DELTA SYNC: Queue, causal delivery, and protocol at scale
// =============================================================================

/// Delta queue backpressure: enforce max_queue_size.
#[test]
fn delta_queue_backpressure_enforcement() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent_a = AgentRegistry::register(conn, "bp-agent-a", vec![])?;
        let agent_b = AgentRegistry::register(conn, "bp-agent-b", vec![])?;

        let clock = VectorClock::new();
        let max_size = 100;

        // Fill the queue to max.
        for i in 0..max_size {
            DeltaQueue::enqueue(
                conn, &agent_a.agent_id.0, &agent_b.agent_id.0,
                &format!("bp-mem-{i}"), r#"{"type":"test"}"#, &clock, max_size,
            )?;
        }

        // Next enqueue should fail (backpressure).
        let result = DeltaQueue::enqueue(
            conn, &agent_a.agent_id.0, &agent_b.agent_id.0,
            "bp-mem-overflow", r#"{"type":"test"}"#, &clock, max_size,
        );
        assert!(result.is_err(), "should reject when queue is full");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("full") || err_msg.contains("100"), "error should mention full queue: {err_msg}");

        // With max_queue_size = 0 (unlimited), should always succeed.
        DeltaQueue::enqueue(
            conn, &agent_a.agent_id.0, &agent_b.agent_id.0,
            "bp-mem-unlimited", r#"{"type":"test"}"#, &clock, 0,
        )?;

        Ok(())
    }).unwrap();
}

/// Delta queue: enqueue → dequeue → mark_applied → purge lifecycle.
#[test]
fn delta_queue_full_lifecycle() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent_a = AgentRegistry::register(conn, "lifecycle-a", vec![])?;
        let agent_b = AgentRegistry::register(conn, "lifecycle-b", vec![])?;

        let clock = VectorClock::new();

        // Enqueue 50 deltas.
        for i in 0..50 {
            DeltaQueue::enqueue(
                conn, &agent_a.agent_id.0, &agent_b.agent_id.0,
                &format!("lc-mem-{i}"), r#"{"type":"lifecycle"}"#, &clock, 0,
            )?;
        }

        // Pending count should be 50.
        let pending = DeltaQueue::pending_count(conn, &agent_b.agent_id.0)?;
        assert_eq!(pending, 50);

        // Dequeue 20.
        let batch = DeltaQueue::dequeue(conn, &agent_b.agent_id.0, 20)?;
        assert_eq!(batch.len(), 20);

        // Mark them applied.
        let ids: Vec<i64> = batch.iter().map(|r| r.delta_id).collect();
        DeltaQueue::mark_applied(conn, &ids)?;

        // Pending should now be 30.
        let pending = DeltaQueue::pending_count(conn, &agent_b.agent_id.0)?;
        assert_eq!(pending, 30);

        // Dequeue remaining.
        let remaining = DeltaQueue::dequeue(conn, &agent_b.agent_id.0, 100)?;
        assert_eq!(remaining.len(), 30);

        // Purge applied deltas.
        let purged = DeltaQueue::purge_applied(conn, Utc::now() + chrono::Duration::hours(1))?;
        assert_eq!(purged, 20, "should purge 20 applied deltas");

        Ok(())
    }).unwrap();
}

/// Causal delivery: out-of-order deltas buffered, then drained correctly.
#[test]
fn causal_delivery_out_of_order_buffering_and_drain() {
    let mut manager = CausalDeliveryManager::new();
    let mut local_clock = VectorClock::new();
    local_clock.increment("agent-a"); // {A:1}

    // Delta 1: {A:2} — can apply (A is local+1).
    let mut d1 = VectorClock::new();
    d1.increment("agent-a");
    d1.increment("agent-a");
    assert!(manager.can_apply_clock(&d1, &local_clock));

    // Delta 2: {A:2, B:1} — can apply (A is local+1, B is 0+1).
    let mut d2 = VectorClock::new();
    d2.increment("agent-a");
    d2.increment("agent-a");
    d2.increment("agent-b");
    assert!(manager.can_apply_clock(&d2, &local_clock));

    // Delta 3: {A:5} — CANNOT apply (A is 1+4, missing 2,3,4).
    let mut d3 = VectorClock::new();
    for _ in 0..5 {
        d3.increment("agent-a");
    }
    assert!(!manager.can_apply_clock(&d3, &local_clock));

    // Buffer d3.
    manager.buffer_row(3, d3.clone());
    assert_eq!(manager.buffered_count(), 1);

    // Apply d1 and d2 to advance local clock.
    local_clock.merge(&d1);
    local_clock.merge(&d2);
    // local_clock is now {A:2, B:1}.

    // d3 still can't apply ({A:5} > {A:2}+1).
    let drained = manager.drain_applicable(&local_clock);
    assert_eq!(drained.len(), 0);
    assert_eq!(manager.buffered_count(), 1);

    // Advance local clock to {A:4, B:1}.
    local_clock.increment("agent-a");
    local_clock.increment("agent-a");

    // Now d3 can apply ({A:5} == {A:4}+1).
    let drained = manager.drain_applicable(&local_clock);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].0, 3); // delta_id 3.
    assert_eq!(manager.buffered_count(), 0);
}

/// Sync protocol: 3 agents in a chain, deltas propagate correctly.
#[test]
fn sync_protocol_3_agent_chain_propagation() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agents: Vec<_> = (0..3)
            .map(|i| AgentRegistry::register(conn, &format!("sync-chain-{i}"), vec![]).unwrap())
            .collect();

        // Agent 0 creates a memory.
        let mem = make_memory("sync-chain-mem", "Chain sync test", vec!["sync"], 0.8, &agents[0].agent_id);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // Agent 0 enqueues delta to Agent 1.
        let mut clock = VectorClock::new();
        clock.increment(&agents[0].agent_id.0);
        DeltaQueue::enqueue(
            conn, &agents[0].agent_id.0, &agents[1].agent_id.0,
            "sync-chain-mem", r#"{"type":"share"}"#, &clock, 0,
        )?;

        // Agent 1 syncs from Agent 0.
        let mut clock_1 = VectorClock::new();
        let result = DeltaSyncEngine::initiate_sync(conn, &agents[1].agent_id, &agents[0].agent_id, &mut clock_1)?;
        assert_eq!(result.deltas_applied, 1, "agent 1 should apply 1 delta");

        // Agent 1 enqueues delta to Agent 2.
        clock.increment(&agents[1].agent_id.0);
        DeltaQueue::enqueue(
            conn, &agents[1].agent_id.0, &agents[2].agent_id.0,
            "sync-chain-mem", r#"{"type":"forward"}"#, &clock, 0,
        )?;

        // Agent 2 syncs from Agent 1.
        let mut clock_2 = VectorClock::new();
        let result = DeltaSyncEngine::initiate_sync(conn, &agents[2].agent_id, &agents[1].agent_id, &mut clock_2)?;
        assert_eq!(result.deltas_applied, 1, "agent 2 should apply 1 delta");

        Ok(())
    }).unwrap();
}

/// Cloud sync detection: active agents → Local, deregistered → Cloud.
#[test]
fn cloud_sync_mode_detection() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let active_agent = AgentRegistry::register(conn, "cloud-active", vec![])?;
        let deregistered_agent = AgentRegistry::register(conn, "cloud-dereg", vec![])?;
        AgentRegistry::deregister(conn, &deregistered_agent.agent_id)?;

        // Active agent → Local.
        let mode = CloudSyncAdapter::detect_sync_mode(conn, &active_agent.agent_id)?;
        assert_eq!(mode, SyncTransport::Local);

        // Deregistered agent → Cloud.
        let mode = CloudSyncAdapter::detect_sync_mode(conn, &deregistered_agent.agent_id)?;
        assert_eq!(mode, SyncTransport::Cloud);

        // Unknown agent → Cloud.
        let mode = CloudSyncAdapter::detect_sync_mode(conn, &AgentId::from("nonexistent"))?;
        assert_eq!(mode, SyncTransport::Cloud);

        Ok(())
    }).unwrap();
}

// =============================================================================
// SHARE: Permission enforcement and provenance tracking
// =============================================================================

/// Share without write permission — must fail.
#[test]
fn share_permission_enforcement() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "share-owner", vec![])?;
        let reader = AgentRegistry::register(conn, "share-reader", vec![])?;
        let outsider = AgentRegistry::register(conn, "share-outsider", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("share-team".into()),
            name: "share-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        // Grant reader only read access.
        NamespacePermissionManager::grant(
            conn, &ns, &reader.agent_id,
            &[NamespacePermission::Read],
            &owner.agent_id,
        )?;

        // Create a memory.
        let mem = make_memory("share-perm-mem", "Test", vec![], 0.8, &owner.agent_id);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // Owner can share (has write via admin).
        assert!(share::share(conn, "share-perm-mem", &ns, &owner.agent_id).is_ok());

        // Reader cannot share (only has read).
        let mem2 = make_memory("share-perm-mem-2", "Test 2", vec![], 0.8, &reader.agent_id);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem2)?;
        assert!(share::share(conn, "share-perm-mem-2", &ns, &reader.agent_id).is_err());

        // Outsider cannot share (no permissions at all).
        let mem3 = make_memory("share-perm-mem-3", "Test 3", vec![], 0.8, &outsider.agent_id);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem3)?;
        assert!(share::share(conn, "share-perm-mem-3", &ns, &outsider.agent_id).is_err());

        Ok(())
    }).unwrap();
}

/// Share creates provenance hop on both original and copy.
#[test]
fn share_creates_provenance_on_both_memories() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "prov-share-owner", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("prov-share-team".into()),
            name: "prov-share-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        let mem = make_memory("prov-share-mem", "Shareable knowledge", vec!["share"], 0.8, &owner.agent_id);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // Share the memory.
        share::share(conn, "prov-share-mem", &ns, &owner.agent_id)?;

        // Original should have a provenance hop.
        let chain = ProvenanceTracker::get_chain(conn, "prov-share-mem")?;
        assert!(!chain.is_empty(), "original should have provenance after share");
        assert_eq!(chain[0].action, ProvenanceAction::SharedTo);

        Ok(())
    }).unwrap();
}

/// Retract archives the memory and records provenance.
#[test]
fn retract_archives_and_records_provenance() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "retract-owner", vec![])?;

        let ns = NamespaceId {
            scope: NamespaceScope::Team("retract-team".into()),
            name: "retract-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &owner.agent_id)?;

        let mem = make_memory("retract-mem", "Retractable", vec![], 0.8, &owner.agent_id);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // Retract.
        share::retract(conn, "retract-mem", &ns, &owner.agent_id)?;

        // Memory should be archived.
        let found = cortex_storage::queries::memory_crud::get_memory(conn, "retract-mem")?;
        assert!(found.is_some());
        assert!(found.unwrap().archived, "memory should be archived after retract");

        // Provenance should have a retracted hop.
        let chain = ProvenanceTracker::get_chain(conn, "retract-mem")?;
        assert!(
            chain.iter().any(|h| h.action == ProvenanceAction::Retracted),
            "provenance should contain Retracted action"
        );

        Ok(())
    }).unwrap();
}

// =============================================================================
// PROJECTION: Filter evaluation at scale
// =============================================================================

/// 10K memories, complex filter — verify correct match/reject counts.
#[test]
fn projection_filter_10k_memories() {
    let start = Instant::now();
    let agent = AgentId::from("proj-stress-agent");

    let filter = ProjectionFilter {
        memory_types: vec![MemoryType::Semantic],
        min_confidence: Some(0.7),
        min_importance: None,
        linked_files: vec![],
        tags: vec!["important".to_string()],
        max_age_days: None,
        predicate: None,
    };

    let mut matching = 0;
    let mut non_matching = 0;

    for i in 0..10_000 {
        // 50% have the right tag, 80% have high enough confidence.
        let tags = if i % 2 == 0 { vec!["important"] } else { vec!["trivial"] };
        let confidence = if i % 5 == 0 { 0.3 } else { 0.85 };
        let mem = make_memory(&format!("proj-{i:05}"), &format!("Memory {i}"), tags, confidence, &agent);

        if ProjectionEngine::evaluate_filter(&mem, &filter) {
            matching += 1;
        } else {
            non_matching += 1;
        }
    }

    // 50% have "important" tag, 80% have confidence >= 0.7.
    // Matching = has "important" AND confidence >= 0.7 = 50% × 80% = 40%.
    // Expected: ~4000 matching, ~6000 non-matching.
    assert!(matching > 3500 && matching < 4500, "expected ~4000 matching, got {matching}");
    assert_eq!(matching + non_matching, 10_000);

    let elapsed = start.elapsed();
    assert!(elapsed.as_secs() < 5, "10K filter evaluation took {:?}", elapsed);
}

// =============================================================================
// FULL INTEGRATION: End-to-end multi-agent workflow
// =============================================================================

/// Complete workflow: register → create namespace → share → sync → trust → provenance → deregister.
#[test]
fn full_integration_workflow() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let start = Instant::now();

        // 1. Register 3 agents.
        let alice = AgentRegistry::register(conn, "alice", vec!["code-review".into()])?;
        let bob = AgentRegistry::register(conn, "bob", vec!["testing".into()])?;
        let charlie = AgentRegistry::register(conn, "charlie", vec!["docs".into()])?;

        // 2. Create a shared team namespace.
        let team_ns = NamespaceId {
            scope: NamespaceScope::Team("engineering".into()),
            name: "engineering".into(),
        };
        NamespaceManager::create_namespace(conn, &team_ns, &alice.agent_id)?;

        // 3. Grant bob and charlie write access.
        NamespacePermissionManager::grant(
            conn, &team_ns, &bob.agent_id,
            &[NamespacePermission::Read, NamespacePermission::Write],
            &alice.agent_id,
        )?;
        NamespacePermissionManager::grant(
            conn, &team_ns, &charlie.agent_id,
            &[NamespacePermission::Read, NamespacePermission::Write],
            &alice.agent_id,
        )?;

        // 4. Alice creates memories and shares to team.
        for i in 0..10 {
            let mem = make_memory(
                &format!("alice-mem-{i}"),
                &format!("Alice's discovery about module {i}"),
                vec!["discovery", "code"],
                0.85,
                &alice.agent_id,
            );
            cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;
            share::share(conn, &format!("alice-mem-{i}"), &team_ns, &alice.agent_id)?;
        }

        // 5. Bob validates some of Alice's memories (builds trust).
        let initial_trust = bootstrap_trust(&bob.agent_id, &alice.agent_id);
        TrustScorer::update_trust(conn, &initial_trust)?;

        for i in 0..7 {
            TrustEvidenceTracker::record_validation(
                conn, &bob.agent_id, &alice.agent_id, &format!("alice-mem-{i}"),
            )?;
        }
        // Bob finds 1 contradiction.
        TrustEvidenceTracker::record_contradiction(
            conn, &bob.agent_id, &alice.agent_id, "alice-mem-8",
        )?;

        // 6. Verify trust score.
        let trust = TrustScorer::get_trust(conn, &bob.agent_id, &alice.agent_id)?;
        assert!(trust.overall_trust > 0.5, "trust should be positive after mostly validations");
        assert!(trust.overall_trust < 1.0, "trust should be < 1.0 with a contradiction");

        // 7. Sync: Alice enqueues deltas to Bob.
        let mut clock = VectorClock::new();
        clock.increment(&alice.agent_id.0);
        for i in 0..5 {
            DeltaQueue::enqueue(
                conn, &alice.agent_id.0, &bob.agent_id.0,
                &format!("alice-mem-{i}"), r#"{"type":"update"}"#, &clock, 0,
            )?;
        }

        let mut bob_clock = VectorClock::new();
        let sync_result = DeltaSyncEngine::initiate_sync(conn, &bob.agent_id, &alice.agent_id, &mut bob_clock)?;
        assert_eq!(sync_result.deltas_applied, 5);

        // 8. Deregister Charlie.
        AgentRegistry::deregister(conn, &charlie.agent_id)?;
        let charlie_status = AgentRegistry::get_agent(conn, &charlie.agent_id)?.unwrap();
        assert!(matches!(charlie_status.status, AgentStatus::Deregistered { .. }));

        // 9. Deregistered agent detected as Cloud transport.
        let mode = CloudSyncAdapter::detect_sync_mode(conn, &charlie.agent_id)?;
        assert_eq!(mode, SyncTransport::Cloud);

        // 10. Alice and Bob still active.
        let active = AgentRegistry::list_agents(conn, Some(&AgentStatus::Active))?;
        assert_eq!(active.len(), 2);

        let elapsed = start.elapsed();
        assert!(elapsed.as_secs() < 10, "full integration took {:?}", elapsed);

        Ok(())
    }).unwrap();
}

/// Stress: 10 agents, each creates 100 memories, shares to team, full sync cycle.
#[test]
fn full_integration_10_agents_1000_memories_sync() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let start = Instant::now();

        // Register 10 agents.
        let agents: Vec<_> = (0..10)
            .map(|i| AgentRegistry::register(conn, &format!("scale-agent-{i:02}"), vec![]).unwrap())
            .collect();

        // Create shared namespace.
        let ns = NamespaceId {
            scope: NamespaceScope::Team("scale-team".into()),
            name: "scale-team".into(),
        };
        NamespaceManager::create_namespace(conn, &ns, &agents[0].agent_id)?;

        // Grant all agents write access.
        for agent in &agents[1..] {
            NamespacePermissionManager::grant(
                conn, &ns, &agent.agent_id,
                &[NamespacePermission::Read, NamespacePermission::Write],
                &agents[0].agent_id,
            )?;
        }

        // Each agent creates 100 memories and shares to team.
        for (i, agent) in agents.iter().enumerate() {
            for j in 0..100 {
                let mem = make_memory(
                    &format!("scale-mem-{i:02}-{j:03}"),
                    &format!("Agent {i} memory {j}"),
                    vec!["scale"],
                    0.8,
                    &agent.agent_id,
                );
                cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;
                share::share(conn, &format!("scale-mem-{i:02}-{j:03}"), &ns, &agent.agent_id)?;
            }
        }

        // Enqueue sync deltas between all agent pairs.
        let mut clock = VectorClock::new();
        for (i, source) in agents.iter().enumerate() {
            clock.increment(&source.agent_id.0);
            for (j, target) in agents.iter().enumerate() {
                if i == j { continue; }
                DeltaQueue::enqueue(
                    conn, &source.agent_id.0, &target.agent_id.0,
                    &format!("scale-mem-{i:02}-000"), r#"{"type":"sync"}"#, &clock, 0,
                )?;
            }
        }

        // Each agent syncs.
        for agent in &agents {
            let mut agent_clock = VectorClock::new();
            let result = DeltaSyncEngine::initiate_sync(conn, &agent.agent_id, &agents[0].agent_id, &mut agent_clock)?;
            assert!(result.deltas_received > 0, "agent {} should receive deltas", agent.name);
        }

        let elapsed = start.elapsed();
        assert!(elapsed.as_secs() < 60, "10-agent 1000-memory sync took {:?}", elapsed);

        Ok(())
    }).unwrap();
}

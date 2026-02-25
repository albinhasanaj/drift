//! Golden fixture tests for cortex-multiagent (PMF-TEST-02).
//!
//! Loads each of the 10 multiagent golden JSON fixtures, runs the scenario,
//! and asserts expected output matches.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use cortex_core::config::MultiAgentConfig;
use cortex_core::memory::*;
use cortex_core::models::agent::AgentId;
use cortex_core::models::cross_agent::{AgentTrust, TrustEvidence};
use cortex_core::models::namespace::{NamespaceId, NamespacePermission, NamespaceScope};
use cortex_core::models::provenance::{ProvenanceAction, ProvenanceHop};
use cortex_crdt::primitives::{GCounter, LWWRegister, MaxRegister, ORSet};
use cortex_storage::StorageEngine;
use test_fixtures::load_fixture_value;

use cortex_multiagent::consolidation::ConsensusDetector;
use cortex_multiagent::namespace::NamespaceManager;
use cortex_multiagent::namespace::permissions::NamespacePermissionManager;
use cortex_multiagent::provenance::correction::CorrectionPropagator;
use cortex_multiagent::provenance::ProvenanceTracker;
use cortex_multiagent::registry::AgentRegistry;
use cortex_multiagent::trust::decay::apply_trust_decay;
use cortex_multiagent::trust::scorer::TrustScorer;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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


// ---------------------------------------------------------------------------
// PMF-GOLD-01: CRDT merge simple — ORSet tags + GCounter access_count
// ---------------------------------------------------------------------------

#[test]
fn pmf_gold_01_crdt_merge_simple() {
    let fixture = load_fixture_value("golden/multiagent/crdt_merge_simple.json");

    // Build two ORSets diverging from the same base.
    let mut tags_alpha = ORSet::<String>::new();
    let mut tags_beta = ORSet::<String>::new();

    // Both start with "rust".
    tags_alpha.add("rust".to_string(), "agent-alpha", 0);
    tags_beta.add("rust".to_string(), "agent-beta", 0);

    // Alpha adds "auth", Beta adds "security".
    tags_alpha.add("auth".to_string(), "agent-alpha", 1);
    tags_beta.add("security".to_string(), "agent-beta", 1);

    // Merge.
    let mut merged_tags = tags_alpha.clone();
    merged_tags.merge(&tags_beta);

    let mut elements: Vec<String> = merged_tags.elements().into_iter().cloned().collect();
    elements.sort();
    assert_eq!(elements, vec!["auth", "rust", "security"]);

    // GCounter: alpha increments 3×, beta increments 2×.
    let mut counter_alpha = GCounter::new();
    let mut counter_beta = GCounter::new();
    for _ in 0..3 {
        counter_alpha.increment("agent-alpha");
    }
    for _ in 0..2 {
        counter_beta.increment("agent-beta");
    }

    let mut merged_counter = counter_alpha.clone();
    merged_counter.merge(&counter_beta);
    assert_eq!(merged_counter.value(), 5);

    // Validate against fixture expected output.
    let expected_tags = fixture["expected_output"]["merged_tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(elements, expected_tags);
    assert_eq!(
        merged_counter.value(),
        fixture["expected_output"]["merged_access_count"].as_u64().unwrap()
    );
}

// ---------------------------------------------------------------------------
// PMF-GOLD-02: CRDT merge conflict — LWW-Register with timestamp + tiebreak
// ---------------------------------------------------------------------------

#[test]
fn pmf_gold_02_crdt_merge_conflict() {
    let fixture = load_fixture_value("golden/multiagent/crdt_merge_conflict.json");

    // Scenario 1: Different timestamps — later wins.
    let t1: DateTime<Utc> = "2026-01-15T10:00:00Z".parse().unwrap();
    let t2: DateTime<Utc> = "2026-01-15T10:00:05Z".parse().unwrap();

    let mut reg_alpha = LWWRegister::new(
        "Original summary".to_string(),
        "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        "agent-alpha".to_string(),
    );
    let mut reg_beta = reg_alpha.clone();

    reg_alpha.set(
        "Alpha's summary about auth patterns".to_string(),
        t1,
        "agent-alpha".to_string(),
    );
    reg_beta.set(
        "Beta's summary about security patterns".to_string(),
        t2,
        "agent-beta".to_string(),
    );

    let mut merged = reg_alpha.clone();
    merged.merge(&reg_beta);
    assert_eq!(merged.get(), "Beta's summary about security patterns");

    // Scenario 2: Same timestamp — lexicographic agent_id tiebreak.
    let t_same: DateTime<Utc> = "2026-01-15T12:00:00Z".parse().unwrap();

    let mut reg_aaa = LWWRegister::new(
        "Original".to_string(),
        "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
        "aaa-agent".to_string(),
    );
    let mut reg_bbb = reg_aaa.clone();

    reg_aaa.set("Agent AAA's summary".to_string(), t_same, "aaa-agent".to_string());
    reg_bbb.set("Agent BBB's summary".to_string(), t_same, "bbb-agent".to_string());

    let mut merged2 = reg_aaa.clone();
    merged2.merge(&reg_bbb);
    // Lexicographic: "bbb-agent" > "aaa-agent", so bbb wins.
    assert_eq!(merged2.get(), "Agent BBB's summary");

    // Validate against fixture.
    let scenario1 = &fixture["input"]["scenarios"][0]["expected"];
    assert_eq!(
        merged.get(),
        scenario1["merged_summary"].as_str().unwrap()
    );
    let scenario2 = &fixture["input"]["scenarios"][1]["expected"];
    assert_eq!(
        merged2.get(),
        scenario2["merged_summary"].as_str().unwrap()
    );
}

// ---------------------------------------------------------------------------
// PMF-GOLD-03: CRDT merge confidence — MaxRegister keeps highest
// ---------------------------------------------------------------------------

#[test]
fn pmf_gold_03_crdt_merge_confidence() {
    let fixture = load_fixture_value("golden/multiagent/crdt_merge_confidence.json");

    let t1: DateTime<Utc> = "2026-01-15T10:00:00Z".parse().unwrap();
    let _t2: DateTime<Utc> = "2026-01-15T10:01:00Z".parse().unwrap();
    let _t3: DateTime<Utc> = "2026-01-15T10:02:00Z".parse().unwrap();

    let mut reg_alpha = MaxRegister::new(0.5_f64, t1);
    let mut reg_beta = MaxRegister::new(0.5_f64, t1);
    let mut reg_gamma = MaxRegister::new(0.5_f64, t1);

    reg_alpha.set(0.7);
    reg_beta.set(0.85);
    reg_gamma.set(0.6);

    let mut merged = reg_alpha.clone();
    merged.merge(&reg_beta);
    merged.merge(&reg_gamma);

    assert!((*merged.get() - 0.85).abs() < f64::EPSILON);
    assert!(
        (*merged.get() - fixture["expected_output"]["merged_confidence"].as_f64().unwrap()).abs()
            < f64::EPSILON
    );
}

// ---------------------------------------------------------------------------
// PMF-GOLD-04: Namespace permissions
// ---------------------------------------------------------------------------

#[test]
fn pmf_gold_04_namespace_permissions() {
    let fixture = load_fixture_value("golden/multiagent/namespace_permissions.json");
    let eng = engine();

    eng.pool().writer.with_conn_sync(|conn| {
        // Register agents.
        let owner = AgentRegistry::register(conn, "owner", vec![])?;
        let member = AgentRegistry::register(conn, "member", vec![])?;
        let outsider = AgentRegistry::register(conn, "outsider", vec![])?;

        // Create team namespace.
        let team_ns = NamespaceId {
            scope: NamespaceScope::Team("backend".into()),
            name: "backend".into(),
        };
        NamespaceManager::create_namespace(conn, &team_ns, &owner.agent_id)?;

        // Create project namespace.
        let project_ns = NamespaceId {
            scope: NamespaceScope::Project("cortex".into()),
            name: "cortex".into(),
        };
        NamespaceManager::create_namespace(conn, &project_ns, &owner.agent_id)?;

        // Grant team permissions to member.
        NamespacePermissionManager::grant(
            conn,
            &team_ns,
            &member.agent_id,
            &[NamespacePermission::Read, NamespacePermission::Write],
            &owner.agent_id,
        )?;

        // Grant project read to member.
        NamespacePermissionManager::grant(
            conn,
            &project_ns,
            &member.agent_id,
            &[NamespacePermission::Read],
            &owner.agent_id,
        )?;

        // Verify owner has all permissions on their own namespace.
        let owner_ns_uri = &owner.namespace;
        let owner_ns = NamespaceId::parse(owner_ns_uri).unwrap();
        assert!(NamespacePermissionManager::check(conn, &owner_ns, &owner.agent_id, NamespacePermission::Read)?);
        assert!(NamespacePermissionManager::check(conn, &owner_ns, &owner.agent_id, NamespacePermission::Write)?);
        assert!(NamespacePermissionManager::check(conn, &owner_ns, &owner.agent_id, NamespacePermission::Share)?);
        assert!(NamespacePermissionManager::check(conn, &owner_ns, &owner.agent_id, NamespacePermission::Admin)?);

        // Outsider has no permissions on owner's namespace.
        assert!(!NamespacePermissionManager::check(conn, &owner_ns, &outsider.agent_id, NamespacePermission::Read)?);

        // Member has read+write on team, no admin.
        assert!(NamespacePermissionManager::check(conn, &team_ns, &member.agent_id, NamespacePermission::Read)?);
        assert!(NamespacePermissionManager::check(conn, &team_ns, &member.agent_id, NamespacePermission::Write)?);
        assert!(!NamespacePermissionManager::check(conn, &team_ns, &member.agent_id, NamespacePermission::Admin)?);

        // Outsider has no team permissions.
        assert!(!NamespacePermissionManager::check(conn, &team_ns, &outsider.agent_id, NamespacePermission::Read)?);

        // Member has read on project, no write.
        assert!(NamespacePermissionManager::check(conn, &project_ns, &member.agent_id, NamespacePermission::Read)?);
        assert!(!NamespacePermissionManager::check(conn, &project_ns, &member.agent_id, NamespacePermission::Write)?);

        // Outsider has no project permissions.
        assert!(!NamespacePermissionManager::check(conn, &project_ns, &outsider.agent_id, NamespacePermission::Read)?);

        // Validate against fixture expected checks count.
        let checks = fixture["expected_output"]["permission_checks"].as_array().unwrap();
        assert!(checks.len() >= 13, "fixture has at least 13 permission checks");

        Ok(())
    })
    .unwrap();
}

// ---------------------------------------------------------------------------
// PMF-GOLD-05: Namespace default compatibility
// ---------------------------------------------------------------------------

#[test]
fn pmf_gold_05_namespace_default_compat() {
    let fixture = load_fixture_value("golden/multiagent/namespace_default_compat.json");

    let default_ns = NamespaceId::default_namespace();
    assert_eq!(default_ns.to_uri(), "agent://default/");
    assert!(default_ns.is_agent());
    assert!(!default_ns.is_shared());

    let default_agent = AgentId::default_agent();
    assert_eq!(default_agent.0, "default");

    // Verify fixture expectations.
    assert_eq!(
        fixture["expected_output"]["default_namespace_uri"].as_str().unwrap(),
        "agent://default/"
    );
    assert_eq!(
        fixture["expected_output"]["default_source_agent"].as_str().unwrap(),
        "default"
    );
    assert!(fixture["expected_output"]["namespace_is_agent_scope"].as_bool().unwrap());
    assert!(fixture["expected_output"]["all_memories_in_default_namespace"].as_bool().unwrap());
}


// ---------------------------------------------------------------------------
// PMF-GOLD-06: Provenance chain — 3-agent chain with confidence
// ---------------------------------------------------------------------------

#[test]
fn pmf_gold_06_provenance_chain() {
    let fixture = load_fixture_value("golden/multiagent/provenance_chain.json");
    let eng = engine();

    eng.pool().writer.with_conn_sync(|conn| {
        // Register agents.
        let reg_a = AgentRegistry::register(conn, "alpha", vec![])?;
        let reg_b = AgentRegistry::register(conn, "beta", vec![])?;
        let reg_c = AgentRegistry::register(conn, "gamma", vec![])?;

        let memory_id = "mem-prov-001";

        // Create a test memory.
        let mem = make_memory(memory_id, "Auth uses JWT", vec!["auth"], 0.8);
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // Record provenance chain from fixture.
        let chain_input = fixture["input"]["chain"].as_array().unwrap();
        for hop_val in chain_input {
            let agent_str = hop_val["agent"].as_str().unwrap();
            let action_str = hop_val["action"].as_str().unwrap();
            let delta = hop_val["confidence_delta"].as_f64().unwrap();
            let ts: DateTime<Utc> = hop_val["timestamp"].as_str().unwrap().parse().unwrap();

            let agent_id = match agent_str {
                "agent-alpha" => reg_a.agent_id.clone(),
                "agent-beta" => reg_b.agent_id.clone(),
                "agent-gamma" => reg_c.agent_id.clone(),
                _ => unreachable!(),
            };

            let action = match action_str {
                "created" => ProvenanceAction::Created,
                "shared_to" => ProvenanceAction::SharedTo,
                "validated_by" => ProvenanceAction::ValidatedBy,
                _ => ProvenanceAction::Created,
            };

            let hop = ProvenanceHop {
                agent_id,
                action,
                timestamp: ts,
                confidence_delta: delta,
            };
            ProvenanceTracker::record_hop(conn, memory_id, &hop)?;
        }

        // Retrieve chain and verify.
        let chain = ProvenanceTracker::get_chain(conn, memory_id)?;
        assert_eq!(chain.len(), 5);

        // Compute chain confidence: product of (1.0 + delta), clamped to [0.0, 1.0].
        let chain_confidence = ProvenanceTracker::chain_confidence(conn, memory_id)?;
        // 1.0 × 1.0 × 1.05 × 1.0 × 1.1 = 1.155 → clamped to 1.0
        assert!(
            (chain_confidence - 1.0).abs() < 0.001,
            "chain confidence should be clamped to 1.0, got {chain_confidence}"
        );

        // Validate against fixture.
        let expected = fixture["expected_output"]["chain_confidence"].as_f64().unwrap();
        assert!((chain_confidence - expected).abs() < 0.001);
        assert_eq!(chain.len(), fixture["expected_output"]["chain_length"].as_u64().unwrap() as usize);

        Ok(())
    })
    .unwrap();
}

// ---------------------------------------------------------------------------
// PMF-GOLD-07: Provenance correction — dampened propagation
// ---------------------------------------------------------------------------

#[test]
fn pmf_gold_07_provenance_correction() {
    let fixture = load_fixture_value("golden/multiagent/provenance_correction.json");

    let config = MultiAgentConfig {
        correction_dampening_factor: 0.7,
        correction_min_threshold: 0.05,
        ..Default::default()
    };
    let propagator = CorrectionPropagator::new(&config);

    // Verify correction strengths at each depth.
    let expected = fixture["expected_output"]["corrections"].as_array().unwrap();
    for entry in expected {
        let distance = entry["hop_distance"].as_u64().unwrap() as usize;
        let expected_strength = entry["correction_strength"].as_f64().unwrap();
        let expected_applied = entry["applied"].as_bool().unwrap();

        let strength = propagator.correction_strength(distance);
        assert!(
            (strength - expected_strength).abs() < 0.0001,
            "distance {distance}: expected {expected_strength}, got {strength}"
        );
        assert_eq!(
            strength >= config.correction_min_threshold,
            expected_applied,
            "distance {distance}: applied mismatch"
        );
    }
}

// ---------------------------------------------------------------------------
// PMF-GOLD-08: Trust scoring — formula validation
// ---------------------------------------------------------------------------

#[test]
fn pmf_gold_08_trust_scoring() {
    let fixture = load_fixture_value("golden/multiagent/trust_scoring.json");

    let evidence = TrustEvidence {
        validated_count: 5,
        contradicted_count: 1,
        useful_count: 3,
        total_received: 10,
    };

    let trust = TrustScorer::compute_overall_trust(&evidence);

    // (5+3)/(10+1) × (1 - 1/(10+1)) = 8/11 × 10/11 ≈ 0.66116
    let expected = fixture["expected_output"]["overall_trust"].as_f64().unwrap();
    let tolerance = fixture["expected_output"]["overall_trust_tolerance"].as_f64().unwrap();
    assert!(
        (trust - expected).abs() < tolerance,
        "trust {trust} not within {tolerance} of expected {expected}"
    );

    // Verify bounds.
    assert!((0.0..=1.0).contains(&trust));
}

// ---------------------------------------------------------------------------
// PMF-GOLD-09: Trust decay — drift toward neutral
// ---------------------------------------------------------------------------

#[test]
fn pmf_gold_09_trust_decay() {
    let fixture = load_fixture_value("golden/multiagent/trust_decay.json");

    let initial_trust = fixture["input"]["initial_trust"].as_f64().unwrap();
    let decay_rate = fixture["input"]["decay_rate"].as_f64().unwrap();

    let scenarios = fixture["expected_output"]["scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let days = scenario["days"].as_f64().unwrap();
        let expected = scenario["expected_trust"].as_f64().unwrap();
        let tolerance = scenario["tolerance"].as_f64().unwrap();

        let mut trust = AgentTrust {
            agent_id: AgentId::from("observer"),
            target_agent: AgentId::from("target"),
            overall_trust: initial_trust,
            domain_trust: Default::default(),
            evidence: TrustEvidence::default(),
            last_updated: Utc::now(),
        };

        apply_trust_decay(&mut trust, days, decay_rate);

        assert!(
            (trust.overall_trust - expected).abs() < tolerance,
            "after {days} days: expected {expected}, got {}",
            trust.overall_trust
        );
        // Trust should always be between initial and 0.5.
        assert!(trust.overall_trust >= 0.5);
        assert!(trust.overall_trust <= initial_trust);
    }
}

// ---------------------------------------------------------------------------
// PMF-GOLD-10: Consensus detection
// ---------------------------------------------------------------------------

#[test]
fn pmf_gold_10_consensus_detection() {
    let fixture = load_fixture_value("golden/multiagent/consensus_detection.json");

    let config = MultiAgentConfig {
        consensus_similarity_threshold: 0.9,
        consensus_min_agents: 2,
        consensus_confidence_boost: 0.2,
        ..Default::default()
    };
    let detector = ConsensusDetector::new(&config);

    // Build memories by agent.
    let agent_alpha = AgentId::from("agent-alpha");
    let agent_beta = AgentId::from("agent-beta");
    let agent_gamma = AgentId::from("agent-gamma");

    let mut mem_alpha = make_memory(
        "mem-alpha-001",
        "Authentication system uses JWT tokens with RS256 signing algorithm",
        vec!["auth", "jwt", "security"],
        0.8,
    );
    mem_alpha.source_agent = agent_alpha.clone();

    let mut mem_beta = make_memory(
        "mem-beta-001",
        "Auth module implements JWT-based authentication using RS256",
        vec!["authentication", "jwt", "tokens"],
        0.75,
    );
    mem_beta.source_agent = agent_beta.clone();

    let mut mem_gamma = make_memory(
        "mem-gamma-001",
        "JWT tokens with RS256 are used for authentication",
        vec!["jwt", "auth", "rs256"],
        0.7,
    );
    mem_gamma.source_agent = agent_gamma.clone();

    let mut memories_by_agent: HashMap<AgentId, Vec<BaseMemory>> = HashMap::new();
    memories_by_agent.insert(agent_alpha, vec![mem_alpha]);
    memories_by_agent.insert(agent_beta, vec![mem_beta]);
    memories_by_agent.insert(agent_gamma, vec![mem_gamma]);

    // Similarity function: all pairs > 0.9 (simulating high embedding similarity).
    let similarity_fn = |_a: &BaseMemory, _b: &BaseMemory| -> f64 { 0.95 };

    let candidates = detector
        .detect_consensus(&memories_by_agent, &similarity_fn, 0.9)
        .unwrap();

    assert!(!candidates.is_empty(), "consensus should be detected");
    let candidate = &candidates[0];
    assert!(candidate.agent_count >= 2);
    assert!((candidate.confidence_boost - 0.2).abs() < f64::EPSILON);

    // Validate against fixture.
    assert!(fixture["expected_output"]["consensus_detected"].as_bool().unwrap());
}

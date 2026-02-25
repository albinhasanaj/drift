//! Trust tests — TMC-TRUST-01 through TMC-TRUST-08.

use chrono::Utc;
use cortex_core::models::agent::AgentId;
use cortex_core::models::cross_agent::{AgentTrust, TrustEvidence};
use cortex_storage::StorageEngine;

use cortex_multiagent::trust::bootstrap::{bootstrap_from_parent, bootstrap_trust};
use cortex_multiagent::trust::decay::apply_trust_decay;
use cortex_multiagent::trust::evidence::TrustEvidenceTracker;
use cortex_multiagent::trust::scorer::TrustScorer;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

/// TMC-TRUST-01: Trust bootstrap at 0.5 for new agents.
#[test]
fn tmc_trust_01_bootstrap_neutral() {
    let trust = bootstrap_trust(&AgentId::from("observer"), &AgentId::from("new-agent"));
    assert!((trust.overall_trust - 0.5).abs() < f64::EPSILON);
    assert_eq!(trust.evidence.total_received, 0);
    assert_eq!(trust.evidence.validated_count, 0);
    assert_eq!(trust.evidence.contradicted_count, 0);
    assert_eq!(trust.evidence.useful_count, 0);
    assert!(trust.domain_trust.is_empty());
}

/// TMC-TRUST-02: Trust increase from validation.
#[test]
fn tmc_trust_02_validation_increases_trust() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Register both agents so FK constraints are satisfied.
        let reg_a = cortex_multiagent::registry::AgentRegistry::register(conn, "trust-a", vec![])?;
        let reg_b = cortex_multiagent::registry::AgentRegistry::register(conn, "trust-b", vec![])?;
        let agent_a = reg_a.agent_id;
        let agent_b = reg_b.agent_id;

        // Bootstrap trust.
        let initial = bootstrap_trust(&agent_a, &agent_b);
        TrustScorer::update_trust(conn, &initial)?;

        // Record a validation.
        TrustEvidenceTracker::record_validation(conn, &agent_a, &agent_b, "mem-1")?;

        let trust = TrustScorer::get_trust(conn, &agent_a, &agent_b)?;
        assert!(trust.evidence.validated_count >= 1);

        // Record more validations to see trust increase.
        for i in 2..=5 {
            TrustEvidenceTracker::record_validation(conn, &agent_a, &agent_b, &format!("mem-{i}"))?;
        }
        let trust_after = TrustScorer::get_trust(conn, &agent_a, &agent_b)?;
        assert!(trust_after.evidence.validated_count > trust.evidence.validated_count);

        Ok(())
    }).unwrap();
}

/// TMC-TRUST-03: Trust decrease from contradiction.
#[test]
fn tmc_trust_03_contradiction_decreases_trust() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Register both agents.
        let reg_a = cortex_multiagent::registry::AgentRegistry::register(conn, "contra-a", vec![])?;
        let reg_b = cortex_multiagent::registry::AgentRegistry::register(conn, "contra-b", vec![])?;
        let agent_a = reg_a.agent_id;
        let agent_b = reg_b.agent_id;

        // Record several validations first to establish trust.
        for i in 1..=5 {
            TrustEvidenceTracker::record_validation(conn, &agent_a, &agent_b, &format!("val-{i}"))?;
        }
        let trust_before = TrustScorer::get_trust(conn, &agent_a, &agent_b)?;

        // Record a contradiction.
        TrustEvidenceTracker::record_contradiction(conn, &agent_a, &agent_b, "bad-mem")?;
        let trust_after = TrustScorer::get_trust(conn, &agent_a, &agent_b)?;

        // Trust should decrease after contradiction.
        assert!(trust_after.overall_trust < trust_before.overall_trust,
            "trust should decrease: before={}, after={}",
            trust_before.overall_trust, trust_after.overall_trust);
        assert_eq!(trust_after.evidence.contradicted_count, 1);

        Ok(())
    }).unwrap();
}

/// TMC-TRUST-04: Domain-specific trust computation.
#[test]
fn tmc_trust_04_domain_trust() {
    // Domain trust uses the same formula, just scoped to domain evidence.
    let evidence = TrustEvidence {
        validated_count: 3,
        contradicted_count: 0,
        useful_count: 2,
        total_received: 5,
    };
    let domain_trust = TrustScorer::compute_domain_trust(&evidence);
    // (3+2)/(5+1) × (1 - 0/(5+1)) = 5/6 × 1.0 ≈ 0.833
    assert!((domain_trust - 5.0 / 6.0).abs() < 0.001,
        "expected ~0.833, got {domain_trust}");
}

/// TMC-TRUST-05: Effective confidence modulation (memory × trust).
#[test]
fn tmc_trust_05_effective_confidence() {
    // memory_confidence 0.85, trust 0.9 → effective 0.765
    let effective = TrustScorer::effective_confidence(0.85, 0.9);
    assert!((effective - 0.765).abs() < 0.001,
        "expected 0.765, got {effective}");

    // Clamping: high values.
    let effective = TrustScorer::effective_confidence(1.0, 1.0);
    assert!((effective - 1.0).abs() < f64::EPSILON);

    // Clamping: zero trust.
    let effective = TrustScorer::effective_confidence(0.9, 0.0);
    assert!((effective - 0.0).abs() < f64::EPSILON);
}

/// TMC-TRUST-06: Trust decay toward neutral over time.
#[test]
fn tmc_trust_06_decay_toward_neutral() {
    // High trust decays toward 0.5.
    let mut trust = AgentTrust {
        agent_id: AgentId::from("a"),
        target_agent: AgentId::from("b"),
        overall_trust: 0.9,
        domain_trust: Default::default(),
        evidence: TrustEvidence::default(),
        last_updated: Utc::now(),
    };

    apply_trust_decay(&mut trust, 100.0, 0.99);
    // 0.9 + (0.5 - 0.9) × (1 - 0.99^100) ≈ 0.9 + (-0.4) × 0.634 ≈ 0.646
    assert!(trust.overall_trust < 0.9, "trust should decrease from 0.9");
    assert!(trust.overall_trust > 0.5, "trust should stay above 0.5");
    assert!((trust.overall_trust - 0.646).abs() < 0.02,
        "expected ~0.646, got {}", trust.overall_trust);

    // Low trust decays toward 0.5 (increases).
    let mut low_trust = AgentTrust {
        agent_id: AgentId::from("a"),
        target_agent: AgentId::from("c"),
        overall_trust: 0.1,
        domain_trust: Default::default(),
        evidence: TrustEvidence::default(),
        last_updated: Utc::now(),
    };

    apply_trust_decay(&mut low_trust, 100.0, 0.99);
    assert!(low_trust.overall_trust > 0.1, "low trust should increase toward 0.5");
    assert!(low_trust.overall_trust < 0.5, "low trust should stay below 0.5");

    // Zero days → no change.
    let mut unchanged = AgentTrust {
        agent_id: AgentId::from("a"),
        target_agent: AgentId::from("d"),
        overall_trust: 0.8,
        domain_trust: Default::default(),
        evidence: TrustEvidence::default(),
        last_updated: Utc::now(),
    };
    apply_trust_decay(&mut unchanged, 0.0, 0.99);
    assert!((unchanged.overall_trust - 0.8).abs() < f64::EPSILON);
}

/// TMC-TRUST-07: Spawned agent trust inheritance with discount.
#[test]
fn tmc_trust_07_spawned_trust_inheritance() {
    let parent_trust = AgentTrust {
        agent_id: AgentId::from("observer"),
        target_agent: AgentId::from("parent"),
        overall_trust: 0.8,
        domain_trust: {
            let mut m = std::collections::HashMap::new();
            m.insert("auth".to_string(), 0.9);
            m.insert("testing".to_string(), 0.7);
            m
        },
        evidence: TrustEvidence {
            validated_count: 10,
            contradicted_count: 1,
            useful_count: 5,
            total_received: 16,
        },
        last_updated: Utc::now(),
    };

    let spawned = bootstrap_from_parent(&parent_trust, &AgentId::from("child"), 0.8);

    // Overall: 0.8 × 0.8 = 0.64.
    assert!((spawned.overall_trust - 0.64).abs() < 0.001,
        "expected 0.64, got {}", spawned.overall_trust);

    // Domain trust discounted.
    assert!((spawned.domain_trust["auth"] - 0.72).abs() < 0.001); // 0.9 × 0.8
    assert!((spawned.domain_trust["testing"] - 0.56).abs() < 0.001); // 0.7 × 0.8

    // Evidence starts empty.
    assert_eq!(spawned.evidence.total_received, 0);
    assert_eq!(spawned.evidence.validated_count, 0);

    // Target is the spawned agent.
    assert_eq!(spawned.target_agent, AgentId::from("child"));
}

/// TMC-TRUST-08: Trust bounds [0.0, 1.0] maintained.
#[test]
fn tmc_trust_08_trust_bounds() {
    // Test with extreme evidence values.
    let evidence = TrustEvidence {
        validated_count: 1000,
        contradicted_count: 0,
        useful_count: 1000,
        total_received: 2000,
    };
    let trust = TrustScorer::compute_overall_trust(&evidence);
    assert!((0.0..=1.0).contains(&trust), "trust {trust} out of bounds");

    // All contradictions.
    let evidence = TrustEvidence {
        validated_count: 0,
        contradicted_count: 100,
        useful_count: 0,
        total_received: 100,
    };
    let trust = TrustScorer::compute_overall_trust(&evidence);
    assert!((0.0..=1.0).contains(&trust), "trust {trust} out of bounds");
    assert!((trust - 0.0).abs() < f64::EPSILON, "all contradictions should give 0 trust");

    // No evidence.
    let evidence = TrustEvidence::default();
    let trust = TrustScorer::compute_overall_trust(&evidence);
    assert!((0.0..=1.0).contains(&trust), "trust {trust} out of bounds");
    assert!((trust - 0.0).abs() < f64::EPSILON, "no evidence should give 0 trust");

    // Specific example from spec: validated=5, contradicted=1, useful=3, total=10.
    let evidence = TrustEvidence {
        validated_count: 5,
        contradicted_count: 1,
        useful_count: 3,
        total_received: 10,
    };
    let trust = TrustScorer::compute_overall_trust(&evidence);
    // (5+3)/(10+1) × (1 - 1/(10+1)) = 8/11 × 10/11 ≈ 0.661
    assert!((trust - 0.661).abs() < 0.01, "expected ~0.661, got {trust}");
}

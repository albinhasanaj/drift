//! Sync tests — TMC-SYNC-01 through TMC-SYNC-08,
//! TMC-PROP-01 through TMC-PROP-05.

use chrono::Utc;
use cortex_core::models::agent::AgentId;
use cortex_core::models::cross_agent::{AgentTrust, TrustEvidence};
use cortex_crdt::VectorClock;
use cortex_storage::StorageEngine;

use cortex_multiagent::sync::causal_delivery::CausalDeliveryManager;
use cortex_multiagent::sync::cloud_integration::{CloudSyncAdapter, SyncTransport};
use cortex_multiagent::sync::delta_queue::DeltaQueue;
use cortex_multiagent::sync::protocol::{DeltaSyncEngine, SyncAck, SyncRequest};

use cortex_multiagent::registry::AgentRegistry;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

/// TMC-SYNC-01: Delta sync protocol: request → response → ack.
#[test]
fn tmc_sync_01_protocol_round_trip() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Register agents for FK constraints.
        let reg_a = AgentRegistry::register(conn, "sync-a", vec![])?;
        let reg_b = AgentRegistry::register(conn, "sync-b", vec![])?;
        let agent_a = reg_a.agent_id;
        let agent_b = reg_b.agent_id;

        // Enqueue some deltas from B to A.
        let mut clock = VectorClock::new();
        clock.increment(&agent_b.0);
        DeltaQueue::enqueue(conn, &agent_b.0, &agent_a.0, "mem-1", r#"{"type":"test"}"#, &clock, 0)?;

        clock.increment(&agent_b.0);
        DeltaQueue::enqueue(conn, &agent_b.0, &agent_a.0, "mem-2", r#"{"type":"test2"}"#, &clock, 0)?;

        // A initiates sync.
        let mut local_clock = VectorClock::new();
        let result = DeltaSyncEngine::initiate_sync(conn, &agent_a, &agent_b, &mut local_clock)?;

        assert_eq!(result.deltas_received, 2);
        assert_eq!(result.deltas_applied, 2);
        assert_eq!(result.deltas_buffered, 0);

        // Verify deltas are marked applied (dequeue returns empty).
        let remaining = DeltaQueue::dequeue(conn, &agent_a.0, 100)?;
        assert_eq!(remaining.len(), 0);

        // Handle sync request.
        let request = SyncRequest {
            source_agent: agent_b.clone(),
            clock: VectorClock::new(),
        };
        let response = DeltaSyncEngine::handle_sync_request(conn, &request)?;
        assert_eq!(response.deltas.len(), 0);

        // Acknowledge sync.
        let ack = SyncAck {
            agent_id: agent_a,
            clock: local_clock,
        };
        DeltaSyncEngine::acknowledge_sync(conn, &ack)?;

        Ok(())
    }).unwrap();
}

/// TMC-SYNC-02: Causal delivery: in-order deltas applied immediately.
#[test]
fn tmc_sync_02_causal_in_order() {
    let manager = CausalDeliveryManager::new();
    let mut local = VectorClock::new();
    local.increment("A"); // {A:1}

    // Delta with {A:2} — can apply (A incremented by 1).
    let mut delta1 = VectorClock::new();
    delta1.increment("A");
    delta1.increment("A");
    assert!(manager.can_apply_clock(&delta1, &local));

    // Delta with {A:1, B:1} — can apply (A same, B new).
    let mut delta2 = VectorClock::new();
    delta2.increment("A");
    delta2.increment("B");
    assert!(manager.can_apply_clock(&delta2, &local));
}

/// TMC-SYNC-03: Causal delivery: out-of-order deltas buffered.
#[test]
fn tmc_sync_03_causal_out_of_order_buffered() {
    let manager = CausalDeliveryManager::new();
    let mut local = VectorClock::new();
    local.increment("A"); // {A:1}

    // Delta with {A:3} — cannot apply (missing A:2).
    let mut future = VectorClock::new();
    future.increment("A");
    future.increment("A");
    future.increment("A");
    assert!(!manager.can_apply_clock(&future, &local));

    // Delta with {A:1, B:2} — cannot apply (missing B:1).
    let mut missing_b = VectorClock::new();
    missing_b.increment("A");
    missing_b.increment("B");
    missing_b.increment("B");
    assert!(!manager.can_apply_clock(&missing_b, &local));
}

/// TMC-SYNC-04: Causal delivery: drain after unblock.
#[test]
fn tmc_sync_04_drain_after_unblock() {
    let mut manager = CausalDeliveryManager::new();
    let mut local = VectorClock::new();
    // local = {A:1}
    local.increment("A");

    // Buffer delta with {A:3} — needs A:2 first.
    let mut delta_a3 = VectorClock::new();
    delta_a3.increment("A");
    delta_a3.increment("A");
    delta_a3.increment("A");
    manager.buffer_row(3, delta_a3);

    // Nothing drainable yet.
    let drained = manager.drain_applicable(&local);
    assert_eq!(drained.len(), 0);
    assert_eq!(manager.buffered_count(), 1);

    // Now apply A:2 (update local clock).
    local.increment("A"); // {A:2}

    // Now A:3 should be drainable.
    let drained = manager.drain_applicable(&local);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].0, 3); // delta_id
    assert_eq!(manager.buffered_count(), 0);
}

/// TMC-SYNC-05: Delta queue: enqueue + dequeue round-trip.
#[test]
fn tmc_sync_05_delta_queue_round_trip() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Register agents for FK constraints.
        let reg_s = AgentRegistry::register(conn, "dq-source", vec![])?;
        let reg_t = AgentRegistry::register(conn, "dq-target", vec![])?;
        let clock = VectorClock::new();

        // Enqueue 10 deltas.
        for i in 0..10 {
            DeltaQueue::enqueue(
                conn, &reg_s.agent_id.0, &reg_t.agent_id.0, &format!("mem-{i}"),
                &format!(r#"{{"delta":{i}}}"#), &clock, 0,
            )?;
        }

        // Dequeue all.
        let deltas = DeltaQueue::dequeue(conn, &reg_t.agent_id.0, 100)?;
        assert_eq!(deltas.len(), 10);

        // Pending count.
        let count = DeltaQueue::pending_count(conn, &reg_t.agent_id.0)?;
        assert_eq!(count, 10);

        Ok(())
    }).unwrap();
}

/// TMC-SYNC-06: Delta queue: mark_applied excludes from dequeue.
#[test]
fn tmc_sync_06_mark_applied() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg_s = AgentRegistry::register(conn, "ma-src", vec![])?;
        let reg_t = AgentRegistry::register(conn, "ma-tgt", vec![])?;
        let clock = VectorClock::new();

        DeltaQueue::enqueue(conn, &reg_s.agent_id.0, &reg_t.agent_id.0, "mem-1", r#"{"a":1}"#, &clock, 0)?;
        DeltaQueue::enqueue(conn, &reg_s.agent_id.0, &reg_t.agent_id.0, "mem-2", r#"{"a":2}"#, &clock, 0)?;
        DeltaQueue::enqueue(conn, &reg_s.agent_id.0, &reg_t.agent_id.0, "mem-3", r#"{"a":3}"#, &clock, 0)?;

        let deltas = DeltaQueue::dequeue(conn, &reg_t.agent_id.0, 100)?;
        assert_eq!(deltas.len(), 3);

        // Mark first two as applied.
        let ids: Vec<i64> = deltas[..2].iter().map(|d| d.delta_id).collect();
        DeltaQueue::mark_applied(conn, &ids)?;

        // Only one remaining.
        let remaining = DeltaQueue::dequeue(conn, &reg_t.agent_id.0, 100)?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].memory_id, "mem-3");

        // Pending count.
        let count = DeltaQueue::pending_count(conn, &reg_t.agent_id.0)?;
        assert_eq!(count, 1);

        Ok(())
    }).unwrap();
}

/// TMC-SYNC-07: Cloud vs local sync mode detection.
#[test]
fn tmc_sync_07_sync_mode_detection() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Register a local agent.
        let agent = AgentRegistry::register(conn, "local-agent", vec![])?;

        // Local agent → Local transport.
        let mode = CloudSyncAdapter::detect_sync_mode(conn, &agent.agent_id)?;
        assert_eq!(mode, SyncTransport::Local);

        // Unknown agent → Cloud transport.
        let mode = CloudSyncAdapter::detect_sync_mode(conn, &AgentId::from("remote-agent"))?;
        assert_eq!(mode, SyncTransport::Cloud);

        Ok(())
    }).unwrap();
}

/// TMC-SYNC-08: Sync convergence: both agents have identical state.
#[test]
fn tmc_sync_08_sync_convergence() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg_a = AgentRegistry::register(conn, "conv-a", vec![])?;
        let reg_b = AgentRegistry::register(conn, "conv-b", vec![])?;
        let agent_a = reg_a.agent_id;
        let agent_b = reg_b.agent_id;

        // Agent B enqueues deltas for Agent A.
        let mut clock_b = VectorClock::new();
        clock_b.increment(&agent_b.0);
        DeltaQueue::enqueue(conn, &agent_b.0, &agent_a.0, "mem-1", r#"{"content":"hello"}"#, &clock_b, 0)?;

        clock_b.increment(&agent_b.0);
        DeltaQueue::enqueue(conn, &agent_b.0, &agent_a.0, "mem-2", r#"{"content":"world"}"#, &clock_b, 0)?;

        // Agent A syncs.
        let mut clock_a = VectorClock::new();
        let result = DeltaSyncEngine::initiate_sync(conn, &agent_a, &agent_b, &mut clock_a)?;

        assert_eq!(result.deltas_applied, 2);
        assert_eq!(result.deltas_buffered, 0);

        // After sync, A's clock should reflect B's deltas.
        assert!(clock_a.get(&agent_b.0) >= 2);

        // No more pending deltas.
        let pending = DeltaQueue::pending_count(conn, &agent_a.0)?;
        assert_eq!(pending, 0);

        Ok(())
    }).unwrap();
}

// ── Property Tests ──────────────────────────────────────────────────────────

/// TMC-PROP-01: Trust bounds (0.0 ≤ trust ≤ 1.0) for any evidence values.
#[test]
fn tmc_prop_01_trust_bounds() {
    use cortex_multiagent::trust::scorer::TrustScorer;

    // Test a wide range of evidence combinations.
    for validated in 0..20 {
        for contradicted in 0..20 {
            for useful in 0..20 {
                let total = validated + contradicted + useful;
                let evidence = TrustEvidence {
                    validated_count: validated,
                    contradicted_count: contradicted,
                    useful_count: useful,
                    total_received: total,
                };
                let trust = TrustScorer::compute_overall_trust(&evidence);
                assert!(
                    (0.0..=1.0).contains(&trust),
                    "trust {trust} out of bounds for v={validated} c={contradicted} u={useful} t={total}"
                );
            }
        }
    }
}

/// TMC-PROP-02: Trust decay monotonicity (always toward 0.5).
#[test]
fn tmc_prop_02_decay_monotonicity() {
    use cortex_multiagent::trust::decay::apply_trust_decay;

    // High trust should decrease toward 0.5.
    for initial in [0.6, 0.7, 0.8, 0.9, 1.0] {
        let mut trust = AgentTrust {
            agent_id: AgentId::from("a"),
            target_agent: AgentId::from("b"),
            overall_trust: initial,
            domain_trust: Default::default(),
            evidence: TrustEvidence::default(),
            last_updated: Utc::now(),
        };
        apply_trust_decay(&mut trust, 50.0, 0.99);
        assert!(trust.overall_trust < initial, "high trust {initial} should decrease");
        assert!(trust.overall_trust >= 0.5, "high trust should stay ≥ 0.5");
    }

    // Low trust should increase toward 0.5.
    for initial in [0.0, 0.1, 0.2, 0.3, 0.4] {
        let mut trust = AgentTrust {
            agent_id: AgentId::from("a"),
            target_agent: AgentId::from("b"),
            overall_trust: initial,
            domain_trust: Default::default(),
            evidence: TrustEvidence::default(),
            last_updated: Utc::now(),
        };
        apply_trust_decay(&mut trust, 50.0, 0.99);
        assert!(trust.overall_trust > initial, "low trust {initial} should increase");
        assert!(trust.overall_trust <= 0.5, "low trust should stay ≤ 0.5");
    }

    // Trust at 0.5 should not change.
    let mut neutral = AgentTrust {
        agent_id: AgentId::from("a"),
        target_agent: AgentId::from("b"),
        overall_trust: 0.5,
        domain_trust: Default::default(),
        evidence: TrustEvidence::default(),
        last_updated: Utc::now(),
    };
    apply_trust_decay(&mut neutral, 100.0, 0.99);
    assert!((neutral.overall_trust - 0.5).abs() < f64::EPSILON);
}

/// TMC-PROP-03: Causal delivery correctness (same final state regardless of order).
#[test]
fn tmc_prop_03_causal_delivery_correctness() {
    // Create deltas with known causal ordering.
    let mut clock_a1 = VectorClock::new();
    clock_a1.increment("A"); // {A:1}

    let mut clock_a2 = VectorClock::new();
    clock_a2.increment("A");
    clock_a2.increment("A"); // {A:2}

    let mut clock_b1 = VectorClock::new();
    clock_b1.increment("B"); // {B:1}

    // Scenario 1: Apply in order A1, A2, B1.
    let manager1 = CausalDeliveryManager::new();
    let mut local1 = VectorClock::new();

    assert!(manager1.can_apply_clock(&clock_a1, &local1));
    local1.merge(&clock_a1);

    assert!(manager1.can_apply_clock(&clock_a2, &local1));
    local1.merge(&clock_a2);

    assert!(manager1.can_apply_clock(&clock_b1, &local1));
    local1.merge(&clock_b1);

    // Scenario 2: Apply in order B1, A1, A2.
    let manager2 = CausalDeliveryManager::new();
    let mut local2 = VectorClock::new();

    assert!(manager2.can_apply_clock(&clock_b1, &local2));
    local2.merge(&clock_b1);

    assert!(manager2.can_apply_clock(&clock_a1, &local2));
    local2.merge(&clock_a1);

    assert!(manager2.can_apply_clock(&clock_a2, &local2));
    local2.merge(&clock_a2);

    // Both should have the same final clock state.
    assert_eq!(local1.get("A"), local2.get("A"));
    assert_eq!(local1.get("B"), local2.get("B"));
}

/// TMC-PROP-04: Delta sync convergence.
#[test]
fn tmc_prop_04_delta_sync_convergence() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Register agents for FK constraints.
        let reg_a = AgentRegistry::register(conn, "conv-a", vec![])?;
        let reg_b = AgentRegistry::register(conn, "conv-b", vec![])?;
        let agent_a = reg_a.agent_id;
        let agent_b = reg_b.agent_id;

        // B sends deltas to A.
        let mut clock = VectorClock::new();
        for i in 0..5 {
            clock.increment(&agent_b.0);
            DeltaQueue::enqueue(
                conn, &agent_b.0, &agent_a.0, &format!("mem-{i}"),
                &format!(r#"{{"i":{i}}}"#), &clock, 0,
            )?;
        }

        // A syncs.
        let mut clock_a = VectorClock::new();
        let result = DeltaSyncEngine::initiate_sync(conn, &agent_a, &agent_b, &mut clock_a)?;

        // All deltas applied.
        assert_eq!(result.deltas_applied, 5);
        assert_eq!(result.deltas_buffered, 0);

        // A's clock reflects all of B's operations.
        assert!(clock_a.get(&agent_b.0) >= 5);

        Ok(())
    }).unwrap();
}

/// TMC-PROP-05: Correction dampening monotonicity.
#[test]
fn tmc_prop_05_correction_dampening_monotonicity() {
    use cortex_multiagent::provenance::correction::CorrectionPropagator;

    let config = cortex_core::config::MultiAgentConfig::default();
    let propagator = CorrectionPropagator::new(&config);

    let mut prev_strength = f64::MAX;
    for distance in 0..20 {
        let strength = propagator.correction_strength(distance);
        assert!(strength <= prev_strength,
            "strength should be monotonically decreasing: distance={distance}, strength={strength}, prev={prev_strength}");
        assert!(strength >= 0.0, "strength should be non-negative");
        assert!(strength <= 1.0, "strength should be ≤ 1.0");
        prev_strength = strength;
    }
}

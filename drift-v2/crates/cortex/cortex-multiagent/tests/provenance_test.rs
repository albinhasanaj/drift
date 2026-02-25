//! Provenance tests — TMC-PROV-01 through TMC-PROV-06.

use chrono::Utc;
use cortex_core::memory::*;
use cortex_core::models::agent::AgentId;
use cortex_core::models::provenance::{ProvenanceAction, ProvenanceHop, ProvenanceOrigin};
use cortex_storage::StorageEngine;

use cortex_multiagent::provenance::correction::CorrectionPropagator;
use cortex_multiagent::provenance::cross_agent::CrossAgentTracer;
use cortex_multiagent::provenance::tracker::ProvenanceTracker;
use cortex_multiagent::registry::AgentRegistry;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

fn make_hop(agent: &str, action: ProvenanceAction, confidence_delta: f64) -> ProvenanceHop {
    ProvenanceHop {
        agent_id: AgentId::from(agent),
        action,
        timestamp: Utc::now(),
        confidence_delta,
    }
}

fn make_test_memory(id: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(cortex_core::memory::types::CoreContent {
            project_name: "test".into(),
            description: "test content".into(),
            metadata: serde_json::Value::Null,
        }),
        summary: format!("summary for {id}"),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::High,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: format!("hash-{id}"),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

/// Helper: register agents and insert a memory for provenance tests.
fn setup_provenance_test(
    conn: &rusqlite::Connection,
    memory_id: &str,
    agent_names: &[&str],
) -> cortex_core::errors::CortexResult<Vec<String>> {
    let mut agent_ids = Vec::new();
    for name in agent_names {
        let reg = AgentRegistry::register(conn, name, vec![])?;
        agent_ids.push(reg.agent_id.0);
    }
    let mem = make_test_memory(memory_id);
    cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;
    Ok(agent_ids)
}

/// TMC-PROV-01: Provenance hop recording and chain retrieval.
#[test]
fn tmc_prov_01_record_and_retrieve_chain() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agents = setup_provenance_test(conn, "mem-1", &["agent-a", "agent-b", "agent-c"])?;

        let hop1 = make_hop(&agents[0], ProvenanceAction::Created, 0.0);
        let hop2 = make_hop(&agents[1], ProvenanceAction::SharedTo, 0.0);
        let hop3 = make_hop(&agents[2], ProvenanceAction::ValidatedBy, 0.1);

        ProvenanceTracker::record_hop(conn, "mem-1", &hop1)?;
        ProvenanceTracker::record_hop(conn, "mem-1", &hop2)?;
        ProvenanceTracker::record_hop(conn, "mem-1", &hop3)?;

        let chain = ProvenanceTracker::get_chain(conn, "mem-1")?;
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].action, ProvenanceAction::Created);
        assert_eq!(chain[1].action, ProvenanceAction::SharedTo);
        assert_eq!(chain[2].action, ProvenanceAction::ValidatedBy);

        // Full provenance record.
        let record = ProvenanceTracker::get_provenance(conn, "mem-1")?;
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.memory_id, "mem-1");
        assert_eq!(record.chain.len(), 3);

        // No provenance for unknown memory.
        let none = ProvenanceTracker::get_provenance(conn, "nonexistent")?;
        assert!(none.is_none());

        Ok(())
    }).unwrap();
}

/// TMC-PROV-02: Chain confidence computation correct.
#[test]
fn tmc_prov_02_chain_confidence() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Chain: Created(0.0) → Shared(0.0) → Validated(+0.1) → Used(+0.05)
        // confidence = 1.0 × 1.0 × 1.1 × 1.05 = 1.155 → clamped to 1.0
        let agents = setup_provenance_test(conn, "conf-1", &["a1", "b1", "c1", "d1"])?;
        ProvenanceTracker::record_hop(conn, "conf-1", &make_hop(&agents[0], ProvenanceAction::Created, 0.0))?;
        ProvenanceTracker::record_hop(conn, "conf-1", &make_hop(&agents[1], ProvenanceAction::SharedTo, 0.0))?;
        ProvenanceTracker::record_hop(conn, "conf-1", &make_hop(&agents[2], ProvenanceAction::ValidatedBy, 0.1))?;
        ProvenanceTracker::record_hop(conn, "conf-1", &make_hop(&agents[3], ProvenanceAction::UsedInDecision, 0.05))?;

        let confidence = ProvenanceTracker::chain_confidence(conn, "conf-1")?;
        assert!((confidence - 1.0).abs() < 0.001, "expected 1.0 (clamped), got {confidence}");

        // Chain with negative delta: Created(0.0) → Corrected(-0.3)
        // confidence = 1.0 × 0.7 = 0.7
        let agents2 = setup_provenance_test(conn, "conf-2", &["a2", "b2"])?;
        ProvenanceTracker::record_hop(conn, "conf-2", &make_hop(&agents2[0], ProvenanceAction::Created, 0.0))?;
        ProvenanceTracker::record_hop(conn, "conf-2", &make_hop(&agents2[1], ProvenanceAction::CorrectedBy, -0.3))?;

        let confidence = ProvenanceTracker::chain_confidence(conn, "conf-2")?;
        assert!((confidence - 0.7).abs() < 0.001, "expected 0.7, got {confidence}");

        // Empty chain → confidence 1.0.
        let confidence = ProvenanceTracker::chain_confidence(conn, "no-chain")?;
        assert!((confidence - 1.0).abs() < f64::EPSILON);

        Ok(())
    }).unwrap();
}

/// TMC-PROV-03: Correction propagation with dampening (0.7^hop).
#[test]
fn tmc_prov_03_correction_dampening() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Create a chain of 3 hops.
        let agents = setup_provenance_test(conn, "corr-1", &["ca", "cb", "cc"])?;
        ProvenanceTracker::record_hop(conn, "corr-1", &make_hop(&agents[0], ProvenanceAction::Created, 0.0))?;
        ProvenanceTracker::record_hop(conn, "corr-1", &make_hop(&agents[1], ProvenanceAction::SharedTo, 0.0))?;
        ProvenanceTracker::record_hop(conn, "corr-1", &make_hop(&agents[2], ProvenanceAction::SharedTo, 0.0))?;

        let config = cortex_core::config::MultiAgentConfig::default();
        let propagator = CorrectionPropagator::new(&config);

        let results = propagator.propagate_correction(conn, "corr-1", "fix typo")?;

        // Distance 0: strength 1.0 (original).
        assert_eq!(results[0].hop_distance, 0);
        assert!((results[0].correction_strength - 1.0).abs() < f64::EPSILON);
        assert!(results[0].applied);

        // Distance 1: strength 0.7.
        assert_eq!(results[1].hop_distance, 1);
        assert!((results[1].correction_strength - 0.7).abs() < 0.001);
        assert!(results[1].applied);

        // Distance 2: strength 0.49.
        assert_eq!(results[2].hop_distance, 2);
        assert!((results[2].correction_strength - 0.49).abs() < 0.001);
        assert!(results[2].applied);

        // Distance 3: strength 0.343.
        assert_eq!(results[3].hop_distance, 3);
        assert!((results[3].correction_strength - 0.343).abs() < 0.001);
        assert!(results[3].applied);

        Ok(())
    }).unwrap();
}

/// TMC-PROV-04: Correction stops at threshold (strength < 0.05).
#[test]
fn tmc_prov_04_correction_threshold() {
    let config = cortex_core::config::MultiAgentConfig::default();
    let propagator = CorrectionPropagator::new(&config);

    // 0.7^0 = 1.0, 0.7^1 = 0.7, 0.7^2 = 0.49, 0.7^3 = 0.343,
    // 0.7^4 = 0.2401, 0.7^5 = 0.168, 0.7^6 = 0.118, 0.7^7 = 0.082,
    // 0.7^8 = 0.058, 0.7^9 = 0.040 < 0.05 → stops.
    assert!(propagator.correction_strength(0) == 1.0);
    assert!((propagator.correction_strength(1) - 0.7).abs() < 0.001);
    assert!((propagator.correction_strength(2) - 0.49).abs() < 0.001);
    assert!(propagator.correction_strength(8) > 0.05);
    assert!(propagator.correction_strength(9) < 0.05);
}

/// TMC-PROV-05: Cross-agent trace across 3 agents.
#[test]
fn tmc_prov_05_cross_agent_trace() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Memory shared A → B → C.
        let agents = setup_provenance_test(conn, "trace-1", &["ta", "tb", "tc"])?;
        ProvenanceTracker::record_hop(conn, "trace-1", &make_hop(&agents[0], ProvenanceAction::Created, 0.0))?;
        ProvenanceTracker::record_hop(conn, "trace-1", &make_hop(&agents[1], ProvenanceAction::SharedTo, 0.0))?;
        ProvenanceTracker::record_hop(conn, "trace-1", &make_hop(&agents[2], ProvenanceAction::SharedTo, 0.1))?;

        let trace = CrossAgentTracer::trace_cross_agent(conn, "trace-1", 10)?;

        assert_eq!(trace.memory_id, "trace-1");
        assert_eq!(trace.agents_involved.len(), 3);
        assert_eq!(trace.hop_count, 3);
        assert_eq!(trace.confidence_chain.len(), 3);
        assert!((trace.total_confidence - 1.0).abs() < 0.001); // 1.0 × 1.0 × 1.1 → clamped to 1.0

        // Trace with max_depth limit.
        let limited = CrossAgentTracer::trace_cross_agent(conn, "trace-1", 2)?;
        assert_eq!(limited.hop_count, 2);
        assert_eq!(limited.agents_involved.len(), 2);

        Ok(())
    }).unwrap();
}

/// TMC-PROV-06: Provenance origin detection correct.
#[test]
fn tmc_prov_06_origin_detection() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Created → AgentCreated origin.
        let agents1 = setup_provenance_test(conn, "orig-1", &["oa1"])?;
        ProvenanceTracker::record_hop(conn, "orig-1", &make_hop(&agents1[0], ProvenanceAction::Created, 0.0))?;
        let origin = ProvenanceTracker::get_origin(conn, "orig-1")?;
        assert_eq!(origin, ProvenanceOrigin::AgentCreated);

        // ProjectedTo → Projected origin.
        let agents2 = setup_provenance_test(conn, "orig-2", &["oa2"])?;
        ProvenanceTracker::record_hop(conn, "orig-2", &make_hop(&agents2[0], ProvenanceAction::ProjectedTo, 0.0))?;
        let origin = ProvenanceTracker::get_origin(conn, "orig-2")?;
        assert_eq!(origin, ProvenanceOrigin::Projected);

        // SharedTo → Derived origin.
        let agents3 = setup_provenance_test(conn, "orig-3", &["oa3"])?;
        ProvenanceTracker::record_hop(conn, "orig-3", &make_hop(&agents3[0], ProvenanceAction::SharedTo, 0.0))?;
        let origin = ProvenanceTracker::get_origin(conn, "orig-3")?;
        assert_eq!(origin, ProvenanceOrigin::Derived);

        // No provenance → Human (default).
        let origin = ProvenanceTracker::get_origin(conn, "no-prov")?;
        assert_eq!(origin, ProvenanceOrigin::Human);

        Ok(())
    }).unwrap();
}

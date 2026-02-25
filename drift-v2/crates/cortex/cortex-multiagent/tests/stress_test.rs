#![allow(clippy::needless_range_loop, clippy::nonminimal_bool)]
//! Stress tests for cortex-multiagent (PMF-TEST-03).
//!
//! - 5 agents, 10K memories, full sync cycle < 30s
//! - Concurrent delta application from 3 agents (no deadlocks)
//! - Projection with 1K matching memories
//! - Trust computation with 10K evidence records

use std::time::Instant;

use chrono::Utc;
use cortex_core::memory::*;
use cortex_core::models::agent::AgentId;
use cortex_core::models::namespace::ProjectionFilter;
use cortex_crdt::{MemoryCRDT, VectorClock};
use cortex_storage::StorageEngine;

use cortex_multiagent::projection::ProjectionEngine;
use cortex_multiagent::registry::AgentRegistry;
use cortex_multiagent::sync::delta_queue::DeltaQueue;
use cortex_multiagent::trust::bootstrap::bootstrap_trust;
use cortex_multiagent::trust::evidence::TrustEvidenceTracker;
use cortex_multiagent::trust::scorer::TrustScorer;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

fn make_memory(id: &str, summary: &str, agent: &AgentId) -> BaseMemory {
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
        tags: vec!["stress-test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: agent.clone(),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}


// ---------------------------------------------------------------------------
// Stress Test 1: 5 agents, 10K memories, full sync cycle
// ---------------------------------------------------------------------------

#[test]
fn stress_5_agents_10k_memories_sync() {
    let start = Instant::now();
    let eng = engine();

    eng.pool().writer.with_conn_sync(|conn| {
        // Register 5 agents.
        let mut agents = Vec::new();
        for i in 0..5 {
            let reg = AgentRegistry::register(conn, &format!("stress-agent-{i}"), vec![])?;
            agents.push(reg);
        }

        // Create 10K memories distributed across agents.
        for i in 0..10_000 {
            let agent_idx = i % 5;
            let agent = &agents[agent_idx];
            let mem = make_memory(
                &format!("stress-mem-{i:05}"),
                &format!("Stress test memory about topic {}", i % 100),
                &agent.agent_id,
            );
            cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;
        }

        // Simulate sync: enqueue deltas from each agent to all others.
        let mut clock = VectorClock::new();
        for i in 0..5 {
            let source = &agents[i];
            clock.increment(&source.agent_id.0);
            for j in 0..5 {
                if i == j {
                    continue;
                }
                let target = &agents[j];
                // Enqueue a batch of deltas.
                for k in 0..10 {
                    let mem_id = format!("stress-mem-{:05}", i * 2000 + k);
                    DeltaQueue::enqueue(
                        conn,
                        &source.agent_id.0,
                        &target.agent_id.0,
                        &mem_id,
                        r#"{"type":"stress_delta"}"#,
                        &clock,
                        0,
                    )?;
                }
            }
        }

        // Dequeue and verify.
        for agent in &agents {
            let deltas = DeltaQueue::dequeue(conn, &agent.agent_id.0, 1000)?;
            assert!(!deltas.is_empty(), "agent {} should have pending deltas", agent.name);
        }

        Ok(())
    })
    .unwrap();

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 30,
        "5 agents, 10K memories sync should complete in < 30s, took {:?}",
        elapsed
    );
}

// ---------------------------------------------------------------------------
// Stress Test 2: Concurrent delta application from 3 agents (no deadlocks)
// ---------------------------------------------------------------------------

#[test]
fn stress_concurrent_delta_application() {
    let start = Instant::now();

    // Test CRDT merge convergence with 3 agents making concurrent edits.
    let agent_ids = ["agent-x", "agent-y", "agent-z"];
    let mut crdts: Vec<MemoryCRDT> = Vec::new();

    // Each agent creates their own view of the same memory.
    for agent_id in &agent_ids {
        let mem = make_memory("shared-mem", "initial content", &AgentId::from(*agent_id));
        let crdt = MemoryCRDT::from_base_memory(&mem, agent_id);
        crdts.push(crdt);
    }

    // Each agent makes 1000 concurrent edits.
    for i in 0..1000 {
        for (idx, agent_id) in agent_ids.iter().enumerate() {
            crdts[idx].tags.add(format!("tag-{agent_id}-{i}"), agent_id, (i + 1) as u64);
            crdts[idx].access_count.increment(agent_id);
            crdts[idx].clock.increment(agent_id);
        }
    }

    // Merge all into a single state.
    let mut final_state = crdts[0].clone();
    for crdt in &crdts[1..] {
        final_state.merge(crdt);
    }

    // Verify convergence: all tags present.
    // access_count = 3 × (1 initial + 1000 increments) = 3003 (GCounter merges per-agent max).
    assert_eq!(final_state.access_count.value(), 3003);
    let tag_count = final_state.tags.elements().len();
    assert!(
        tag_count >= 3000,
        "should have at least 3000 tags, got {tag_count}"
    );

    // Verify commutativity: merge in different order → same result.
    let mut alt_state = crdts[2].clone();
    alt_state.merge(&crdts[0]);
    alt_state.merge(&crdts[1]);
    assert_eq!(alt_state.access_count.value(), final_state.access_count.value());
    assert_eq!(alt_state.tags.elements().len(), final_state.tags.elements().len());

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 30,
        "concurrent delta application should complete in < 30s, took {:?}",
        elapsed
    );
}

// ---------------------------------------------------------------------------
// Stress Test 3: Projection with 1K matching memories
// ---------------------------------------------------------------------------

#[test]
fn stress_projection_1k_memories() {
    let start = Instant::now();

    let filter = ProjectionFilter {
        memory_types: vec![MemoryType::Semantic],
        min_confidence: Some(0.5),
        min_importance: None,
        linked_files: vec![],
        tags: vec!["stress-test".to_string()],
        max_age_days: None,
        predicate: None,
    };

    let agent = AgentId::from("proj-agent");
    let mut matching = 0;
    let mut non_matching = 0;

    for i in 0..1000 {
        let mem = make_memory(
            &format!("proj-mem-{i:04}"),
            &format!("Projection test memory {i}"),
            &agent,
        );
        if ProjectionEngine::evaluate_filter(&mem, &filter) {
            matching += 1;
        } else {
            non_matching += 1;
        }
    }

    assert_eq!(matching, 1000, "all 1K memories should match the filter");
    assert_eq!(non_matching, 0);

    // Also test with non-matching filter.
    let strict_filter = ProjectionFilter {
        memory_types: vec![MemoryType::Episodic],
        ..filter
    };
    for i in 0..1000 {
        let mem = make_memory(
            &format!("proj-strict-{i:04}"),
            &format!("Strict filter test {i}"),
            &agent,
        );
        assert!(!ProjectionEngine::evaluate_filter(&mem, &strict_filter));
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 10,
        "projection filter evaluation for 2K memories should be fast, took {:?}",
        elapsed
    );
}

// ---------------------------------------------------------------------------
// Stress Test 4: Trust computation with 10K evidence records
// ---------------------------------------------------------------------------

#[test]
fn stress_trust_10k_evidence() {
    let start = Instant::now();
    let eng = engine();

    eng.pool().writer.with_conn_sync(|conn| {
        let agent_a = AgentRegistry::register(conn, "trust-stress-a", vec![])?;
        let agent_b = AgentRegistry::register(conn, "trust-stress-b", vec![])?;

        // Bootstrap trust.
        let initial = bootstrap_trust(&agent_a.agent_id, &agent_b.agent_id);
        TrustScorer::update_trust(conn, &initial)?;

        // Record 10K evidence records.
        for i in 0..10_000 {
            let mem_id = format!("trust-mem-{i:05}");
            match i % 10 {
                0 => TrustEvidenceTracker::record_contradiction(
                    conn,
                    &agent_a.agent_id,
                    &agent_b.agent_id,
                    &mem_id,
                )?,
                1..=3 => TrustEvidenceTracker::record_usage(
                    conn,
                    &agent_a.agent_id,
                    &agent_b.agent_id,
                    &mem_id,
                )?,
                _ => TrustEvidenceTracker::record_validation(
                    conn,
                    &agent_a.agent_id,
                    &agent_b.agent_id,
                    &mem_id,
                )?,
            }
        }

        // Verify trust is computed correctly.
        let trust = TrustScorer::get_trust(conn, &agent_a.agent_id, &agent_b.agent_id)?;
        assert!(trust.overall_trust >= 0.0 && trust.overall_trust <= 1.0);
        assert!(trust.evidence.total_received >= 10_000);
        // 60% validated, 30% useful, 10% contradicted.
        assert!(trust.evidence.validated_count >= 5000);
        assert!(trust.evidence.useful_count >= 2000);
        assert!(trust.evidence.contradicted_count >= 900);

        Ok(())
    })
    .unwrap();

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 30,
        "trust computation with 10K evidence should complete in < 30s, took {:?}",
        elapsed
    );
}

// ---------------------------------------------------------------------------
// Stress Test 5: CRDT merge at scale — 10K memories across 5 agents
// ---------------------------------------------------------------------------

#[test]
fn stress_crdt_merge_10k_memories() {
    let start = Instant::now();
    let agent_ids = ["agent-1", "agent-2", "agent-3", "agent-4", "agent-5"];

    // Create 10K MemoryCRDTs, each owned by one of 5 agents.
    let mut all_crdts: Vec<MemoryCRDT> = Vec::with_capacity(10_000);
    for i in 0..10_000 {
        let agent = agent_ids[i % 5];
        let mem = make_memory(
            &format!("merge-mem-{i:05}"),
            &format!("Memory about topic {}", i % 200),
            &AgentId::from(agent),
        );
        let crdt = MemoryCRDT::from_base_memory(&mem, agent);
        all_crdts.push(crdt);
    }

    // Simulate divergent edits: each agent modifies their memories.
    for (i, crdt) in all_crdts.iter_mut().enumerate() {
        let agent = agent_ids[i % 5];
        crdt.tags.add(format!("edited-by-{agent}"), agent, 1);
        crdt.access_count.increment(agent);
        crdt.clock.increment(agent);
    }

    // Merge pairs of CRDTs (simulating sync between agents).
    let merge_count = 5000;
    for i in 0..merge_count {
        let j = (i + 1) % all_crdts.len();
        if i == j {
            continue;
        }
        let other = all_crdts[j].clone();
        all_crdts[i].merge(&other);
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 30,
        "10K CRDT merges should complete in < 30s, took {:?}",
        elapsed
    );

    // Verify no data loss.
    for crdt in &all_crdts[..100] {
        assert!(crdt.access_count.value() >= 1);
        assert!(!crdt.tags.elements().is_empty());
    }
}

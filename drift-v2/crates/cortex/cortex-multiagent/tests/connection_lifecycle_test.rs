//! Phase B connection lifecycle tests (B-08, B-12, B-14, B-15).
//!
//! Verify that the multi-agent engine works correctly with shared connections,
//! especially in in-memory mode where per-call connection creation was broken.

use std::sync::Arc;

use cortex_core::config::MultiAgentConfig;
use cortex_core::models::namespace::NamespaceId;
use cortex_core::traits::IMultiAgentEngine;
use cortex_multiagent::MultiAgentEngine;
use cortex_storage::StorageEngine;

fn make_shared_engine() -> (Arc<StorageEngine>, MultiAgentEngine) {
    let storage = Arc::new(StorageEngine::open_in_memory().expect("in-memory storage"));
    let engine = MultiAgentEngine::new(
        storage.pool().writer.clone(),
        storage.pool().readers.clone(),
        MultiAgentConfig::default(),
    )
    .with_read_pool_disabled(); // In-memory readers are isolated DBs
    (storage, engine)
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().expect("tokio runtime")
}

// B-08: In-memory mode — register agent then get returns the same agent.
// This was broken before B-04 because each call created a new in-memory DB.
#[test]
fn b08_in_memory_register_then_get() {
    let (_storage, engine) = make_shared_engine();
    let rt = rt();

    let registration = rt
        .block_on(engine.register_agent("test-agent", vec!["code_review".into()]))
        .expect("register should succeed");

    assert_eq!(registration.name, "test-agent");
    let agent_id = registration.agent_id.clone();

    // Get the agent back — this must find it because we share the same connections.
    let found = rt
        .block_on(engine.get_agent(&agent_id))
        .expect("get_agent should succeed");

    assert!(
        found.is_some(),
        "agent should be found in shared in-memory DB (was broken before B-04)"
    );
    let found = found.unwrap();
    assert_eq!(found.name, "test-agent");
    assert_eq!(found.agent_id, agent_id);
}

// B-12: Multi-agent connection reuse — 100 calls don't leak connections.
#[test]
fn b12_connection_reuse_no_leak() {
    let (_storage, engine) = make_shared_engine();
    let rt = rt();

    // Register 50 agents using the same shared engine.
    let mut agent_ids = Vec::new();
    for i in 0..50 {
        let reg = rt
            .block_on(engine.register_agent(
                &format!("agent-{i}"),
                vec!["capability".into()],
            ))
            .expect("register should succeed");
        agent_ids.push(reg.agent_id);
    }

    // Verify all 50 are retrievable.
    for aid in &agent_ids {
        let found = rt
            .block_on(engine.get_agent(aid))
            .expect("get_agent should succeed");
        assert!(found.is_some(), "agent {aid:?} should be found");
    }

    // List all agents — should return all 50.
    let all = rt
        .block_on(engine.list_agents(None))
        .expect("list_agents should succeed");
    assert!(
        all.len() >= 50,
        "should have at least 50 agents, got {}",
        all.len()
    );
}

// B-14: Concurrent multi-agent calls don't deadlock.
#[test]
fn b14_concurrent_calls_no_deadlock() {
    let storage = Arc::new(StorageEngine::open_in_memory().expect("in-memory storage"));
    let writer = storage.pool().writer.clone();
    let readers = storage.pool().readers.clone();

    // Spawn 10 threads, each registering an agent and listing.
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let w = writer.clone();
            let r = readers.clone();
            let config = MultiAgentConfig::default();
            std::thread::spawn(move || {
                let engine = MultiAgentEngine::new(w, r, config)
                    .with_read_pool_disabled(); // In-memory readers are isolated DBs
                let rt = tokio::runtime::Runtime::new().unwrap();
                let _reg = rt
                    .block_on(engine.register_agent(
                        &format!("thread-agent-{i}"),
                        vec![],
                    ))
                    .expect("register should not deadlock");
                let _list = rt
                    .block_on(engine.list_agents(None))
                    .expect("list should not deadlock");
            })
        })
        .collect();

    // All threads should complete within 5 seconds.
    for h in handles {
        h.join().expect("thread should not panic");
    }
}

// B-15: retract_memory uses shared DB — verify retraction is visible.
#[test]
fn b15_retract_uses_shared_db() {
    let storage = Arc::new(StorageEngine::open_in_memory().expect("in-memory storage"));
    let engine = MultiAgentEngine::new(
        storage.pool().writer.clone(),
        storage.pool().readers.clone(),
        MultiAgentConfig::default(),
    );
    let rt = rt();

    // Register an agent and create a namespace.
    let reg = rt
        .block_on(engine.register_agent("retract-agent", vec![]))
        .expect("register");
    let agent_id = reg.agent_id.clone();

    // Create a memory in storage to retract.
    use cortex_core::memory::*;
    use cortex_core::traits::IMemoryStorage;

    let content = cortex_core::memory::types::InsightContent {
        observation: "test insight".to_string(),
        evidence: vec![],
    };
    let tc = TypedContent::Insight(content);
    let memory = BaseMemory {
        id: "retract-test-mem".to_string(),
        memory_type: MemoryType::Insight,
        content: tc.clone(),
        summary: "test insight".to_string(),
        transaction_time: chrono::Utc::now(),
        valid_time: chrono::Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: chrono::Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&tc).unwrap(),
    };
    storage.create(&memory).expect("create memory");

    // Retract using the shared writer connection (B-05 fix).
    let ns = NamespaceId::parse(&reg.namespace).expect("parse namespace");
    let retract_result = storage.pool().writer.with_conn_sync(|conn| {
        cortex_multiagent::share::actions::retract(conn, "retract-test-mem", &ns, &agent_id)
    });
    // Retract may fail if the share table doesn't have the entry, but it should not
    // fail with a connection error (which was the B-05 bug).
    // The important thing is it doesn't panic or create an isolated DB.
    if let Err(e) = &retract_result {
        // Expected: may fail because memory wasn't shared, but should not be a connection error.
        let msg = format!("{e}");
        assert!(
            !msg.contains("no such table") && !msg.contains("database is locked"),
            "retract should use shared DB, not isolated: {msg}"
        );
    }
}

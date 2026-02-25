//! Projection tests — TMB-PROJ-01 through TMB-PROJ-08.

use chrono::Utc;
use cortex_core::memory::*;
use cortex_core::models::namespace::*;
use cortex_storage::StorageEngine;

use cortex_multiagent::namespace::NamespaceManager;
use cortex_multiagent::projection::backpressure::{BackpressureController, SyncMode};
use cortex_multiagent::projection::compression::compress_for_projection;
use cortex_multiagent::projection::engine::ProjectionEngine;
use cortex_multiagent::projection::subscription::SubscriptionManager;
use cortex_multiagent::registry::AgentRegistry;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

fn make_test_memory(id: &str, mem_type: MemoryType, confidence: f64, importance: Importance, tags: Vec<String>) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: mem_type,
        content: TypedContent::Core(cortex_core::memory::types::CoreContent {
            project_name: "test".into(),
            description: "test context".into(),
            metadata: serde_json::Value::Null,
        }),
        summary: format!("summary for {id}"),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(confidence),
        importance,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags,
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: format!("hash-{id}"),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

/// TMB-PROJ-01: Projection creation with filter.
#[test]
fn tmb_proj_01_create_projection() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "proj-agent", vec![])?;

        let source_ns = NamespaceId {
            scope: NamespaceScope::Team("src".into()),
            name: "src".into(),
        };
        let target_ns = NamespaceId {
            scope: NamespaceScope::Team("tgt".into()),
            name: "tgt".into(),
        };
        NamespaceManager::create_namespace(conn, &source_ns, &agent.agent_id)?;
        NamespaceManager::create_namespace(conn, &target_ns, &agent.agent_id)?;

        let projection = MemoryProjection {
            id: "proj-1".into(),
            source: source_ns.clone(),
            target: target_ns.clone(),
            filter: ProjectionFilter {
                min_confidence: Some(0.7),
                tags: vec!["important".into()],
                ..Default::default()
            },
            compression_level: 1,
            live: true,
            created_at: Utc::now(),
            created_by: agent.agent_id.clone(),
        };

        let id = ProjectionEngine::create_projection(conn, &projection)?;
        assert_eq!(id, "proj-1");

        // Retrieve and verify.
        let found = ProjectionEngine::get_projection(conn, "proj-1")?;
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.source.to_uri(), source_ns.to_uri());
        assert_eq!(found.target.to_uri(), target_ns.to_uri());
        assert!(found.live);
        assert_eq!(found.compression_level, 1);

        Ok(())
    }).unwrap();
}

/// TMB-PROJ-02: Filter evaluation — matching memory returns true.
#[test]
fn tmb_proj_02_filter_match() {
    let filter = ProjectionFilter {
        memory_types: vec![MemoryType::Core],
        min_confidence: Some(0.5),
        tags: vec!["rust".into()],
        ..Default::default()
    };
    let mem = make_test_memory("m1", MemoryType::Core, 0.9, Importance::High, vec!["rust".into()]);
    assert!(ProjectionEngine::evaluate_filter(&mem, &filter));
}

/// TMB-PROJ-03: Filter evaluation — non-matching memory returns false.
#[test]
fn tmb_proj_03_filter_no_match() {
    let filter = ProjectionFilter {
        memory_types: vec![MemoryType::Episodic],
        ..Default::default()
    };
    let mem = make_test_memory("m2", MemoryType::Core, 0.9, Importance::High, vec![]);
    assert!(!ProjectionEngine::evaluate_filter(&mem, &filter));
}

/// TMB-PROJ-04: Filter evaluation — all conditions must match (AND logic).
#[test]
fn tmb_proj_04_filter_and_logic() {
    let filter = ProjectionFilter {
        memory_types: vec![MemoryType::Core],
        min_confidence: Some(0.8),
        tags: vec!["required-tag".into()],
        ..Default::default()
    };

    // Matches type and confidence but not tags → false.
    let mem = make_test_memory("m3", MemoryType::Core, 0.9, Importance::High, vec!["other".into()]);
    assert!(!ProjectionEngine::evaluate_filter(&mem, &filter));

    // Matches type and tags but not confidence → false.
    let mem = make_test_memory("m4", MemoryType::Core, 0.3, Importance::High, vec!["required-tag".into()]);
    assert!(!ProjectionEngine::evaluate_filter(&mem, &filter));

    // Matches all → true.
    let mem = make_test_memory("m5", MemoryType::Core, 0.9, Importance::High, vec!["required-tag".into()]);
    assert!(ProjectionEngine::evaluate_filter(&mem, &filter));
}

/// TMB-PROJ-05: Live projection subscription + delta push.
#[test]
fn tmb_proj_05_subscription_push_drain() {
    let mgr = SubscriptionManager::new(100);

    // Subscribe.
    let state = mgr.subscribe("proj-live").unwrap();
    assert_eq!(state.projection_id, "proj-live");
    assert_eq!(state.delta_queue.len(), 0);

    // Push deltas.
    mgr.push_delta("proj-live", r#"{"type":"content_updated"}"#.into()).unwrap();
    mgr.push_delta("proj-live", r#"{"type":"tag_added"}"#.into()).unwrap();

    assert_eq!(mgr.queue_depth("proj-live").unwrap(), 2);

    // Drain.
    let drained = mgr.drain_queue("proj-live").unwrap();
    assert_eq!(drained.len(), 2);
    assert_eq!(mgr.queue_depth("proj-live").unwrap(), 0);

    // Unsubscribe.
    mgr.unsubscribe("proj-live").unwrap();
    assert!(mgr.queue_depth("proj-live").is_err());
}

/// TMB-PROJ-06: Projection compression L0-L3 correct content reduction.
#[test]
fn tmb_proj_06_compression_levels() {
    let mem = make_test_memory("comp-1", MemoryType::Core, 0.85, Importance::High, vec!["rust".into()]);

    let l0 = compress_for_projection(&mem, 0);
    assert!(l0.contains("comp-1"));
    assert!(l0.contains("Core"));
    // L0 is shortest.
    let l0_len = l0.len();

    let l1 = compress_for_projection(&mem, 1);
    assert!(l1.contains("comp-1"));
    assert!(l1.contains("summary for comp-1"));
    assert!(l1.len() > l0_len);

    let l2 = compress_for_projection(&mem, 2);
    assert!(l2.contains("confidence"));
    assert!(l2.len() > l1.len());

    let l3 = compress_for_projection(&mem, 3);
    // L3 is full JSON — longest.
    assert!(l3.len() > l2.len());
}

/// TMB-PROJ-07: Backpressure mode transition: queue > 80% → Batched.
#[test]
fn tmb_proj_07_backpressure_to_batched() {
    let ctrl = BackpressureController::new(30);

    // 85% utilization → should switch to Batched.
    let mode = ctrl.check_backpressure(85, 100, &SyncMode::Streaming);
    assert!(matches!(mode, SyncMode::Batched { interval_secs: 30 }));

    // 90% → still Batched.
    let mode = ctrl.check_backpressure(90, 100, &SyncMode::Batched { interval_secs: 30 });
    assert!(matches!(mode, SyncMode::Batched { .. }));
}

/// TMB-PROJ-08: Backpressure recovery: queue < 50% → Streaming.
#[test]
fn tmb_proj_08_backpressure_recovery() {
    let ctrl = BackpressureController::new(30);

    // 40% utilization from Batched → should recover to Streaming.
    let mode = ctrl.check_backpressure(40, 100, &SyncMode::Batched { interval_secs: 30 });
    assert_eq!(mode, SyncMode::Streaming);

    // 60% (middle zone) → keep current mode.
    let mode = ctrl.check_backpressure(60, 100, &SyncMode::Batched { interval_secs: 30 });
    assert!(matches!(mode, SyncMode::Batched { .. }));

    let mode = ctrl.check_backpressure(60, 100, &SyncMode::Streaming);
    assert_eq!(mode, SyncMode::Streaming);
}

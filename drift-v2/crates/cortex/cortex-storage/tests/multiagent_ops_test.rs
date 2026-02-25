//! Multi-agent operations tests: agent registry, namespaces, permissions,
//! projections, provenance, trust, delta queue.
//!
//! This module (821 lines) had ZERO direct tests before this file.

use cortex_core::traits::IMemoryStorage;
use cortex_storage::queries::multiagent_ops::{self, *};
use cortex_storage::StorageEngine;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().unwrap()
}

fn with_writer<F, T>(engine: &StorageEngine, f: F) -> T
where
    F: FnOnce(&rusqlite::Connection) -> cortex_core::errors::CortexResult<T>,
{
    engine.pool().writer.with_conn_sync(f).unwrap()
}

/// Helper: register an agent (many tables FK to agent_registry).
fn ensure_agent(conn: &rusqlite::Connection, agent_id: &str) {
    let _ = insert_agent(
        conn,
        &InsertAgentParams {
            agent_id,
            name: agent_id,
            namespace_id: "default",
            capabilities_json: "[]",
            parent_agent: None,
            registered_at: "2024-01-01T00:00:00Z",
            status: "active",
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// AGENT REGISTRY: CRUD + status lifecycle
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn agent_insert_and_get() {
    let e = engine();
    with_writer(&e, |conn| {
        insert_agent(
            conn,
            &InsertAgentParams {
                agent_id: "agent-1",
                name: "Test Agent",
                namespace_id: "ns-default",
                capabilities_json: r#"["read","write"]"#,
                parent_agent: None,
                registered_at: "2024-06-01T00:00:00Z",
                status: "active",
            },
        )?;

        let agent = get_agent(conn, "agent-1")?;
        assert!(agent.is_some());
        let a = agent.unwrap();
        assert_eq!(a.name, "Test Agent");
        assert_eq!(a.status, "active");
        assert!(a.parent_agent.is_none());

        Ok(())
    });
}

#[test]
fn agent_get_nonexistent_returns_none() {
    let e = engine();
    with_writer(&e, |conn| {
        let agent = get_agent(conn, "ghost")?;
        assert!(agent.is_none());
        Ok(())
    });
}

#[test]
fn agent_list_and_filter_by_status() {
    let e = engine();
    with_writer(&e, |conn| {
        for (id, status) in &[("a1", "active"), ("a2", "active"), ("a3", "suspended")] {
            insert_agent(
                conn,
                &InsertAgentParams {
                    agent_id: id,
                    name: &format!("Agent {id}"),
                    namespace_id: "ns",
                    capabilities_json: "[]",
                    parent_agent: None,
                    registered_at: "2024-06-01T00:00:00Z",
                    status,
                },
            )?;
        }

        let all = list_agents(conn, None)?;
        assert_eq!(all.len(), 3);

        let active = list_agents(conn, Some("active"))?;
        assert_eq!(active.len(), 2);

        let suspended = list_agents(conn, Some("suspended"))?;
        assert_eq!(suspended.len(), 1);
        assert_eq!(suspended[0].agent_id, "a3");

        Ok(())
    });
}

#[test]
fn agent_update_status() {
    let e = engine();
    with_writer(&e, |conn| {
        insert_agent(
            conn,
            &InsertAgentParams {
                agent_id: "status-agent",
                name: "Status",
                namespace_id: "ns",
                capabilities_json: "[]",
                parent_agent: None,
                registered_at: "2024-06-01T00:00:00Z",
                status: "active",
            },
        )?;

        update_agent_status(conn, "status-agent", "suspended")?;
        let a = get_agent(conn, "status-agent")?.unwrap();
        assert_eq!(a.status, "suspended");

        Ok(())
    });
}

#[test]
fn agent_update_last_active() {
    let e = engine();
    with_writer(&e, |conn| {
        insert_agent(
            conn,
            &InsertAgentParams {
                agent_id: "active-agent",
                name: "Active",
                namespace_id: "ns",
                capabilities_json: "[]",
                parent_agent: None,
                registered_at: "2024-01-01T00:00:00Z",
                status: "active",
            },
        )?;

        update_last_active(conn, "active-agent", "2024-06-15T12:00:00Z")?;
        let a = get_agent(conn, "active-agent")?.unwrap();
        assert_eq!(a.last_active, "2024-06-15T12:00:00Z");

        Ok(())
    });
}

#[test]
fn agent_delete() {
    let e = engine();
    with_writer(&e, |conn| {
        insert_agent(
            conn,
            &InsertAgentParams {
                agent_id: "del-agent",
                name: "Delete Me",
                namespace_id: "ns",
                capabilities_json: "[]",
                parent_agent: None,
                registered_at: "2024-06-01T00:00:00Z",
                status: "active",
            },
        )?;

        delete_agent(conn, "del-agent")?;
        assert!(get_agent(conn, "del-agent")?.is_none());

        Ok(())
    });
}

#[test]
fn agent_with_parent() {
    let e = engine();
    with_writer(&e, |conn| {
        insert_agent(
            conn,
            &InsertAgentParams {
                agent_id: "parent",
                name: "Parent Agent",
                namespace_id: "ns",
                capabilities_json: "[]",
                parent_agent: None,
                registered_at: "2024-06-01T00:00:00Z",
                status: "active",
            },
        )?;
        insert_agent(
            conn,
            &InsertAgentParams {
                agent_id: "child",
                name: "Child Agent",
                namespace_id: "ns",
                capabilities_json: "[]",
                parent_agent: Some("parent"),
                registered_at: "2024-06-01T00:00:00Z",
                status: "active",
            },
        )?;

        let child = get_agent(conn, "child")?.unwrap();
        assert_eq!(child.parent_agent, Some("parent".to_string()));

        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// NAMESPACES: CRUD + scope filtering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn namespace_insert_and_get() {
    let e = engine();
    with_writer(&e, |conn| {
        ensure_agent(conn, "agent-1");
        insert_namespace(conn, "ns-test", "private", Some("agent-1"), "2024-06-01T00:00:00Z")?;

        let ns = get_namespace(conn, "ns-test")?;
        assert!(ns.is_some());
        let n = ns.unwrap();
        assert_eq!(n.scope, "private");
        assert_eq!(n.owner_agent, Some("agent-1".to_string()));

        Ok(())
    });
}

#[test]
fn namespace_list_and_filter() {
    let e = engine();
    with_writer(&e, |conn| {
        insert_namespace(conn, "ns-priv-1", "private", None, "2024-06-01T00:00:00Z")?;
        insert_namespace(conn, "ns-shared-1", "shared", None, "2024-06-01T00:00:00Z")?;
        insert_namespace(conn, "ns-priv-2", "private", None, "2024-06-01T00:00:00Z")?;

        let all = list_namespaces(conn, None)?;
        assert_eq!(all.len(), 3);

        let private = list_namespaces(conn, Some("private"))?;
        assert_eq!(private.len(), 2);

        Ok(())
    });
}

#[test]
fn namespace_delete() {
    let e = engine();
    with_writer(&e, |conn| {
        insert_namespace(conn, "ns-del", "private", None, "2024-06-01T00:00:00Z")?;
        delete_namespace(conn, "ns-del")?;
        assert!(get_namespace(conn, "ns-del")?.is_none());
        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// PERMISSIONS: grant, check, revoke, ACL
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn permission_grant_and_check() {
    let e = engine();
    with_writer(&e, |conn| {
        ensure_agent(conn, "agent-1");
        insert_namespace(conn, "ns-perm", "private", None, "2024-06-01T00:00:00Z")?;

        insert_permission(
            conn,
            "ns-perm",
            "agent-1",
            r#"["read","write"]"#,
            "admin",
            "2024-06-01T00:00:00Z",
        )?;

        // Check specific permissions
        assert!(check_permission(conn, "ns-perm", "agent-1", "read")?);
        assert!(check_permission(conn, "ns-perm", "agent-1", "write")?);
        assert!(!check_permission(conn, "ns-perm", "agent-1", "delete")?);

        Ok(())
    });
}

#[test]
fn permission_admin_has_all() {
    let e = engine();
    with_writer(&e, |conn| {
        ensure_agent(conn, "admin-agent");
        insert_namespace(conn, "ns-admin", "private", None, "2024-06-01T00:00:00Z")?;

        insert_permission(
            conn,
            "ns-admin",
            "admin-agent",
            r#"["admin"]"#,
            "system",
            "2024-06-01T00:00:00Z",
        )?;

        // Admin should have any permission
        assert!(check_permission(conn, "ns-admin", "admin-agent", "read")?);
        assert!(check_permission(conn, "ns-admin", "admin-agent", "write")?);
        assert!(check_permission(conn, "ns-admin", "admin-agent", "anything")?);

        Ok(())
    });
}

#[test]
fn permission_no_grant_returns_false() {
    let e = engine();
    with_writer(&e, |conn| {
        assert!(!check_permission(conn, "ns-x", "agent-x", "read")?);
        Ok(())
    });
}

#[test]
fn permission_acl_and_revoke() {
    let e = engine();
    with_writer(&e, |conn| {
        ensure_agent(conn, "a1");
        ensure_agent(conn, "a2");
        insert_namespace(conn, "ns-acl", "shared", None, "2024-06-01T00:00:00Z")?;

        insert_permission(conn, "ns-acl", "a1", r#"["read"]"#, "admin", "2024-06-01T00:00:00Z")?;
        insert_permission(conn, "ns-acl", "a2", r#"["read","write"]"#, "admin", "2024-06-01T00:00:00Z")?;

        let acl = get_acl(conn, "ns-acl")?;
        assert_eq!(acl.len(), 2);

        // Revoke a1's permission
        delete_permission(conn, "ns-acl", "a1")?;
        let acl = get_acl(conn, "ns-acl")?;
        assert_eq!(acl.len(), 1);
        assert_eq!(acl[0].0, "a2");

        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// PROJECTIONS: CRUD + list by namespace
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn projection_insert_get_list_delete() {
    let e = engine();
    with_writer(&e, |conn| {
        ensure_agent(conn, "admin");
        insert_namespace(conn, "ns-src", "private", None, "2024-06-01T00:00:00Z")?;
        insert_namespace(conn, "ns-tgt", "shared", None, "2024-06-01T00:00:00Z")?;

        insert_projection(
            conn,
            &InsertProjectionParams {
                projection_id: "proj-1",
                source_namespace: "ns-src",
                target_namespace: "ns-tgt",
                filter_json: r#"{"type":"tribal"}"#,
                compression_level: 2,
                live: true,
                created_at: "2024-06-01T00:00:00Z",
                created_by: "admin",
            },
        )?;

        // Get
        let proj = get_projection(conn, "proj-1")?;
        assert!(proj.is_some());
        let p = proj.unwrap();
        assert_eq!(p.source_namespace, "ns-src");
        assert!(p.live);
        assert_eq!(p.compression_level, 2);

        // List (from source or target namespace)
        let from_src = list_projections(conn, "ns-src")?;
        assert_eq!(from_src.len(), 1);
        let from_tgt = list_projections(conn, "ns-tgt")?;
        assert_eq!(from_tgt.len(), 1);

        // Delete
        delete_projection(conn, "proj-1")?;
        assert!(get_projection(conn, "proj-1")?.is_none());

        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// PROVENANCE: chain insert and query
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn provenance_chain_roundtrip() {
    let e = engine();
    // Create memory first (FK constraint)
    let mem = {
        let content = cortex_core::memory::TypedContent::Tribal(
            cortex_core::memory::types::TribalContent {
                knowledge: "test".to_string(),
                severity: "low".to_string(),
                warnings: vec![],
                consequences: vec![],
            },
        );
        cortex_core::memory::BaseMemory {
            id: "prov-mem".to_string(),
            memory_type: cortex_core::memory::MemoryType::Tribal,
            content: content.clone(),
            summary: "test".to_string(),
            transaction_time: chrono::Utc::now(),
            valid_time: chrono::Utc::now(),
            valid_until: None,
            confidence: cortex_core::memory::Confidence::new(0.8),
            importance: cortex_core::memory::Importance::Normal,
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
            content_hash: cortex_core::memory::BaseMemory::compute_content_hash(&content).unwrap(),
            namespace: Default::default(),
            source_agent: Default::default(),
        }
    };
    e.create(&mem).unwrap();

    with_writer(&e, |conn| {
        ensure_agent(conn, "agent-a");
        ensure_agent(conn, "agent-b");
        insert_provenance_hop(
            conn,
            &InsertProvenanceHopParams {
                memory_id: "prov-mem",
                hop_index: 0,
                agent_id: "agent-a",
                action: "created",
                timestamp: "2024-06-01T00:00:00Z",
                confidence_delta: 0.0,
                details: Some("initial creation"),
            },
        )?;
        insert_provenance_hop(
            conn,
            &InsertProvenanceHopParams {
                memory_id: "prov-mem",
                hop_index: 1,
                agent_id: "agent-b",
                action: "validated",
                timestamp: "2024-06-01T01:00:00Z",
                confidence_delta: 0.1,
                details: None,
            },
        )?;

        // Get chain
        let chain = get_provenance_chain(conn, "prov-mem")?;
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].hop_index, 0);
        assert_eq!(chain[0].agent_id, "agent-a");
        assert_eq!(chain[1].hop_index, 1);
        assert_eq!(chain[1].agent_id, "agent-b");

        // Get origin
        let origin = get_provenance_origin(conn, "prov-mem")?;
        assert!(origin.is_some());
        assert_eq!(origin.unwrap().action, "created");

        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// TRUST: upsert, get, list
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn trust_upsert_and_get() {
    let e = engine();
    with_writer(&e, |conn| {
        ensure_agent(conn, "agent-a");
        ensure_agent(conn, "agent-b");
        upsert_trust(
            conn,
            "agent-a",
            "agent-b",
            0.85,
            Some(r#"{"code_review": 0.9}"#),
            r#"["validated 5 memories"]"#,
            "2024-06-01T00:00:00Z",
        )?;

        let trust = get_trust(conn, "agent-a", "agent-b")?;
        assert!(trust.is_some());
        let t = trust.unwrap();
        assert!((t.overall_trust - 0.85).abs() < f64::EPSILON);

        Ok(())
    });
}

#[test]
fn trust_upsert_overwrites() {
    let e = engine();
    with_writer(&e, |conn| {
        ensure_agent(conn, "x");
        ensure_agent(conn, "y");
        upsert_trust(conn, "x", "y", 0.5, None, "[]", "2024-01-01T00:00:00Z")?;
        upsert_trust(conn, "x", "y", 0.9, None, "[]", "2024-06-01T00:00:00Z")?;

        let t = get_trust(conn, "x", "y")?.unwrap();
        assert!((t.overall_trust - 0.9).abs() < f64::EPSILON, "upsert should overwrite");

        Ok(())
    });
}

#[test]
fn trust_list_for_agent() {
    let e = engine();
    with_writer(&e, |conn| {
        ensure_agent(conn, "lister");
        ensure_agent(conn, "t1");
        ensure_agent(conn, "t2");
        ensure_agent(conn, "other");
        ensure_agent(conn, "t3");
        upsert_trust(conn, "lister", "t1", 0.8, None, "[]", "2024-06-01T00:00:00Z")?;
        upsert_trust(conn, "lister", "t2", 0.6, None, "[]", "2024-06-01T00:00:00Z")?;
        upsert_trust(conn, "other", "t3", 0.9, None, "[]", "2024-06-01T00:00:00Z")?;

        let trusts = list_trust_for_agent(conn, "lister")?;
        assert_eq!(trusts.len(), 2, "should only list trusts for 'lister'");

        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// DELTA QUEUE: enqueue, dequeue, mark applied, pending count, purge
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn delta_queue_full_lifecycle() {
    let e = engine();
    with_writer(&e, |conn| {
        ensure_agent(conn, "src");
        ensure_agent(conn, "tgt");
        // Enqueue 3 deltas
        enqueue_delta(conn, "src", "tgt", "m1", r#"{"op":"add"}"#, r#"{"src":1}"#, "2024-06-01T00:00:00Z")?;
        enqueue_delta(conn, "src", "tgt", "m2", r#"{"op":"update"}"#, r#"{"src":2}"#, "2024-06-01T00:01:00Z")?;
        enqueue_delta(conn, "src", "tgt", "m3", r#"{"op":"delete"}"#, r#"{"src":3}"#, "2024-06-01T00:02:00Z")?;

        // Pending count
        assert_eq!(pending_delta_count(conn, "tgt")?, 3);

        // Dequeue with limit
        let batch = dequeue_deltas(conn, "tgt", 2)?;
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].memory_id, "m1");
        assert_eq!(batch[1].memory_id, "m2");

        // Mark applied
        let ids: Vec<i64> = batch.iter().map(|d| d.delta_id).collect();
        mark_deltas_applied(conn, &ids, "2024-06-01T00:10:00Z")?;

        // Pending count should decrease
        assert_eq!(pending_delta_count(conn, "tgt")?, 1);

        // Dequeue remaining
        let remaining = dequeue_deltas(conn, "tgt", 10)?;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].memory_id, "m3");

        Ok(())
    });
}

#[test]
fn delta_purge_applied() {
    let e = engine();
    with_writer(&e, |conn| {
        ensure_agent(conn, "s");
        ensure_agent(conn, "t");
        enqueue_delta(conn, "s", "t", "m1", "{}", "{}", "2024-01-01T00:00:00Z")?;
        let batch = dequeue_deltas(conn, "t", 10)?;
        let ids: Vec<i64> = batch.iter().map(|d| d.delta_id).collect();
        mark_deltas_applied(conn, &ids, "2024-01-01T00:01:00Z")?;

        // Purge applied deltas older than 2024-06-01
        let purged = purge_applied_deltas(conn, "2024-06-01T00:00:00Z")?;
        assert_eq!(purged, 1);

        Ok(())
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// MEMORY NAMESPACE/AGENT QUERIES
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn memories_by_namespace_and_agent() {
    let e = engine();
    // Create memories with namespace and source_agent set
    let m1 = {
        let content = cortex_core::memory::TypedContent::Tribal(
            cortex_core::memory::types::TribalContent {
                knowledge: "k".to_string(),
                severity: "low".to_string(),
                warnings: vec![],
                consequences: vec![],
            },
        );
        cortex_core::memory::BaseMemory {
            id: "ns-mem-1".to_string(),
            memory_type: cortex_core::memory::MemoryType::Tribal,
            content: content.clone(),
            summary: "s".to_string(),
            transaction_time: chrono::Utc::now(),
            valid_time: chrono::Utc::now(),
            valid_until: None,
            confidence: cortex_core::memory::Confidence::new(0.8),
            importance: cortex_core::memory::Importance::Normal,
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
            content_hash: cortex_core::memory::BaseMemory::compute_content_hash(&content).unwrap(),
            namespace: Default::default(),
            source_agent: Default::default(),
        }
    };
    let mut m2 = m1.clone();
    m2.id = "ns-mem-2".to_string();

    e.create(&m1).unwrap();
    e.create(&m2).unwrap();

    // Update namespace via raw ops
    with_writer(&e, |conn| {
        multiagent_ops::update_memory_namespace(conn, "ns-mem-1", "ns-alpha")?;
        multiagent_ops::update_memory_namespace(conn, "ns-mem-2", "ns-alpha")?;
        Ok(())
    });

    let ns_mems = with_writer(&e, |conn| {
        multiagent_ops::get_memories_by_namespace(conn, "ns-alpha")
    });
    assert_eq!(ns_mems.len(), 2);
}

#[test]
fn archive_memory_via_multiagent_ops() {
    let e = engine();
    let content = cortex_core::memory::TypedContent::Tribal(
        cortex_core::memory::types::TribalContent {
            knowledge: "k".to_string(),
            severity: "low".to_string(),
            warnings: vec![],
            consequences: vec![],
        },
    );
    let mem = cortex_core::memory::BaseMemory {
        id: "arch-mem".to_string(),
        memory_type: cortex_core::memory::MemoryType::Tribal,
        content: content.clone(),
        summary: "s".to_string(),
        transaction_time: chrono::Utc::now(),
        valid_time: chrono::Utc::now(),
        valid_until: None,
        confidence: cortex_core::memory::Confidence::new(0.8),
        importance: cortex_core::memory::Importance::Normal,
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
        content_hash: cortex_core::memory::BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    };
    e.create(&mem).unwrap();

    with_writer(&e, |conn| {
        multiagent_ops::archive_memory(conn, "arch-mem")?;
        Ok(())
    });

    let loaded = e.get("arch-mem").unwrap();
    // archived=1 memories are filtered out by default queries
    // The memory exists but archived flag is set
    // Direct get should still find it (it checks by id, not filtered)
    // Actually, get_memory doesn't filter by archived. Let's verify.
    assert!(loaded.is_some());
    assert!(loaded.unwrap().archived);
}

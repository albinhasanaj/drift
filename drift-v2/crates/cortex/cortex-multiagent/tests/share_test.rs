//! Share tests — TMB-SHARE-01 through TMB-SHARE-05.

use chrono::Utc;
use cortex_core::memory::*;
use cortex_core::models::namespace::*;
use cortex_storage::StorageEngine;

use cortex_multiagent::namespace::NamespaceManager;
use cortex_multiagent::namespace::permissions::NamespacePermissionManager;
use cortex_multiagent::registry::AgentRegistry;
use cortex_multiagent::share;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

fn make_test_memory(id: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(cortex_core::memory::types::CoreContent {
            project_name: "shareable".into(),
            description: "shareable content".into(),
            metadata: serde_json::Value::Null,
        }),
        summary: format!("summary for {id}"),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::High,
        last_accessed: Utc::now(),
        access_count: 5,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["shared".into(), "test".into()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: format!("hash-{id}"),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

/// TMB-SHARE-01: Share copies memory with provenance hop.
#[test]
fn tmb_share_01_share_copies_with_provenance() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "sharer", vec![])?;

        // Create target namespace and grant write.
        let target_ns = NamespaceId {
            scope: NamespaceScope::Team("target".into()),
            name: "target".into(),
        };
        NamespaceManager::create_namespace(conn, &target_ns, &agent.agent_id)?;
        NamespacePermissionManager::grant(
            conn, &target_ns, &agent.agent_id,
            &[NamespacePermission::Write],
            &agent.agent_id,
        )?;

        // Insert source memory.
        let mem = make_test_memory("share-src");
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        // Share it.
        share::actions::share(conn, "share-src", &target_ns, &agent.agent_id)?;

        // Original still exists.
        let original = cortex_storage::queries::memory_crud::get_memory(conn, "share-src")?;
        assert!(original.is_some());

        // Provenance recorded on original.
        let chain = cortex_storage::queries::multiagent_ops::get_provenance_chain(conn, "share-src")?;
        assert!(!chain.is_empty());
        assert_eq!(chain[0].action, "shared_to");

        // A copy exists in target namespace.
        let target_mems = cortex_storage::queries::multiagent_ops::get_memories_by_namespace(
            conn, &target_ns.to_uri(),
        )?;
        assert_eq!(target_mems.len(), 1);
        assert_ne!(target_mems[0], "share-src"); // Different ID.

        Ok(())
    }).unwrap();
}

/// TMB-SHARE-02: Promote moves memory, updates namespace field.
#[test]
fn tmb_share_02_promote_moves_memory() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "promoter", vec![])?;

        let target_ns = NamespaceId {
            scope: NamespaceScope::Team("promoted".into()),
            name: "promoted".into(),
        };
        NamespaceManager::create_namespace(conn, &target_ns, &agent.agent_id)?;
        NamespacePermissionManager::grant(
            conn, &target_ns, &agent.agent_id,
            &[NamespacePermission::Write],
            &agent.agent_id,
        )?;

        let mem = make_test_memory("promote-src");
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        share::actions::promote(conn, "promote-src", &target_ns, &agent.agent_id)?;

        // Memory still exists but namespace updated.
        let updated = cortex_storage::queries::memory_crud::get_memory(conn, "promote-src")?;
        assert!(updated.is_some());

        // Provenance recorded.
        let chain = cortex_storage::queries::multiagent_ops::get_provenance_chain(conn, "promote-src")?;
        assert!(!chain.is_empty());
        assert_eq!(chain[0].action, "projected_to");

        Ok(())
    }).unwrap();
}

/// TMB-SHARE-03: Retract tombstones memory.
#[test]
fn tmb_share_03_retract_archives_memory() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "retractor", vec![])?;

        let mem = make_test_memory("retract-src");
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        let ns = NamespaceId::default();
        share::actions::retract(conn, "retract-src", &ns, &agent.agent_id)?;

        // Memory is archived.
        let found = cortex_storage::queries::memory_crud::get_memory(conn, "retract-src")?;
        assert!(found.is_some());
        assert!(found.unwrap().archived);

        // Provenance recorded.
        let chain = cortex_storage::queries::multiagent_ops::get_provenance_chain(conn, "retract-src")?;
        assert!(!chain.is_empty());
        assert_eq!(chain[0].action, "retracted");

        Ok(())
    }).unwrap();
}

/// TMB-SHARE-04: Permission denied on unauthorized share.
#[test]
fn tmb_share_04_permission_denied() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let owner = AgentRegistry::register(conn, "ns-owner", vec![])?;
        let intruder = AgentRegistry::register(conn, "intruder", vec![])?;

        let target_ns = NamespaceId {
            scope: NamespaceScope::Team("restricted".into()),
            name: "restricted".into(),
        };
        NamespaceManager::create_namespace(conn, &target_ns, &owner.agent_id)?;
        // No write permission granted to intruder.

        let mem = make_test_memory("denied-mem");
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        let result = share::actions::share(conn, "denied-mem", &target_ns, &intruder.agent_id);
        assert!(result.is_err());

        // Verify error is PermissionDenied.
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("permission denied") || err_msg.contains("Permission"));

        Ok(())
    }).unwrap();
}

/// TMB-SHARE-05: Share preserves memory content and metadata.
#[test]
fn tmb_share_05_share_preserves_content() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let agent = AgentRegistry::register(conn, "content-sharer", vec![])?;

        let target_ns = NamespaceId {
            scope: NamespaceScope::Team("content-target".into()),
            name: "content-target".into(),
        };
        NamespaceManager::create_namespace(conn, &target_ns, &agent.agent_id)?;
        NamespacePermissionManager::grant(
            conn, &target_ns, &agent.agent_id,
            &[NamespacePermission::Write],
            &agent.agent_id,
        )?;

        let mem = make_test_memory("preserve-src");
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        share::actions::share(conn, "preserve-src", &target_ns, &agent.agent_id)?;

        // Find the copy.
        let copies = cortex_storage::queries::multiagent_ops::get_memories_by_namespace(
            conn, &target_ns.to_uri(),
        )?;
        assert_eq!(copies.len(), 1);

        let copy = cortex_storage::queries::memory_crud::get_memory(conn, &copies[0])?;
        assert!(copy.is_some());
        let copy = copy.unwrap();

        // Content preserved.
        assert_eq!(copy.memory_type, mem.memory_type);
        assert_eq!(copy.summary, mem.summary);
        assert_eq!(copy.importance, mem.importance);
        assert_eq!(copy.content_hash, mem.content_hash);

        Ok(())
    }).unwrap();
}

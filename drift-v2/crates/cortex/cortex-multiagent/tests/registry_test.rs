//! Registry tests — TMB-REG-01 through TMB-REG-06.

use cortex_core::models::agent::{AgentStatus, SpawnConfig};
use cortex_storage::StorageEngine;

use cortex_multiagent::registry::AgentRegistry;
use cortex_multiagent::registry::spawn;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

/// TMB-REG-01: Agent registration creates agent + namespace.
#[test]
fn tmb_reg_01_register_creates_agent_and_namespace() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg = AgentRegistry::register(conn, "test-agent", vec!["code_review".into()])?;

        assert!(!reg.agent_id.0.is_empty());
        assert_eq!(reg.name, "test-agent");
        assert_eq!(reg.capabilities, vec!["code_review"]);
        assert!(matches!(reg.status, AgentStatus::Active));
        assert!(reg.namespace.starts_with("agent://"));
        assert!(reg.parent_agent.is_none());

        // Verify agent is retrievable.
        let found = AgentRegistry::get_agent(conn, &reg.agent_id)?;
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.agent_id, reg.agent_id);
        assert_eq!(found.name, "test-agent");

        // Verify namespace was created in DB.
        let ns = cortex_storage::queries::multiagent_ops::get_namespace(conn, &reg.namespace)?;
        assert!(ns.is_some());

        Ok(())
    }).unwrap();
}

/// TMB-REG-02: Agent deregistration sets status, preserves provenance.
#[test]
fn tmb_reg_02_deregister_archives_agent() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg = AgentRegistry::register(conn, "to-deregister", vec![])?;
        AgentRegistry::deregister(conn, &reg.agent_id)?;

        let found = AgentRegistry::get_agent(conn, &reg.agent_id)?;
        assert!(found.is_some());
        let found = found.unwrap();
        assert!(matches!(found.status, AgentStatus::Deregistered { .. }));

        // Namespace still exists (preserved).
        let ns = cortex_storage::queries::multiagent_ops::get_namespace(conn, &reg.namespace)?;
        assert!(ns.is_some());

        Ok(())
    }).unwrap();
}

/// TMB-REG-03: Agent lifecycle transitions: Active → Idle → Deregistered.
#[test]
fn tmb_reg_03_lifecycle_transitions() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg = AgentRegistry::register(conn, "lifecycle", vec![])?;
        assert!(matches!(reg.status, AgentStatus::Active));

        // Active → Idle.
        AgentRegistry::mark_idle(conn, &reg.agent_id)?;
        let found = AgentRegistry::get_agent(conn, &reg.agent_id)?.unwrap();
        assert!(matches!(found.status, AgentStatus::Idle { .. }));

        // Idle → Deregistered.
        AgentRegistry::deregister(conn, &reg.agent_id)?;
        let found = AgentRegistry::get_agent(conn, &reg.agent_id)?.unwrap();
        assert!(matches!(found.status, AgentStatus::Deregistered { .. }));

        Ok(())
    }).unwrap();
}

/// TMB-REG-04: Spawned agent creation with parent reference.
#[test]
fn tmb_reg_04_spawn_agent_with_parent() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let parent = AgentRegistry::register(conn, "parent", vec!["orchestrate".into()])?;

        let config = SpawnConfig {
            parent_agent: parent.agent_id.clone(),
            trust_discount: 0.8,
            auto_promote_on_deregister: false,
            ..Default::default()
        };
        let child = spawn::spawn_agent(conn, &config, "child", vec!["testing".into()])?;

        assert_eq!(child.parent_agent.as_ref().unwrap(), &parent.agent_id);
        assert_eq!(child.name, "child");
        assert!(matches!(child.status, AgentStatus::Active));
        assert!(child.namespace.starts_with("agent://"));
        assert_ne!(child.namespace, parent.namespace);

        Ok(())
    }).unwrap();
}

/// TMB-REG-05: Spawned agent deregister with memory promotion.
#[test]
fn tmb_reg_05_spawn_deregister_promotes_memories() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let parent = AgentRegistry::register(conn, "parent-promo", vec![])?;
        let config = SpawnConfig {
            parent_agent: parent.agent_id.clone(),
            auto_promote_on_deregister: true,
            ..Default::default()
        };
        let child = spawn::spawn_agent(conn, &config, "child-promo", vec![])?;

        // Insert a memory in the child's namespace.
        let mem = make_test_memory("child-mem-1");
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;
        cortex_storage::queries::multiagent_ops::update_memory_namespace(
            conn, &mem.id, &child.namespace,
        )?;

        // Verify memory is in child namespace.
        let mems = cortex_storage::queries::multiagent_ops::get_memories_by_namespace(
            conn, &child.namespace,
        )?;
        assert_eq!(mems.len(), 1);

        // Deregister with auto-promote.
        spawn::deregister_spawned(conn, &child.agent_id, true)?;

        // Memory should now be in parent namespace.
        let parent_mems = cortex_storage::queries::multiagent_ops::get_memories_by_namespace(
            conn, &parent.namespace,
        )?;
        assert!(parent_mems.contains(&"child-mem-1".to_string()));

        Ok(())
    }).unwrap();
}

/// TMB-REG-06: Deregistered agent cannot be deregistered again.
#[test]
fn tmb_reg_06_double_deregister_fails() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let reg = AgentRegistry::register(conn, "double-dereg", vec![])?;
        AgentRegistry::deregister(conn, &reg.agent_id)?;

        // Second deregister should fail.
        let result = AgentRegistry::deregister(conn, &reg.agent_id);
        assert!(result.is_err());

        Ok(())
    }).unwrap();
}

// ── Helper ──────────────────────────────────────────────────────────────────

fn make_test_memory(id: &str) -> cortex_core::memory::BaseMemory {
    use chrono::Utc;
    use cortex_core::memory::*;

    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(cortex_core::memory::types::CoreContent {
            project_name: "test".into(),
            description: "test".into(),
            metadata: serde_json::Value::Null,
        }),
        summary: "test memory".into(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".into()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: "test-hash".into(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

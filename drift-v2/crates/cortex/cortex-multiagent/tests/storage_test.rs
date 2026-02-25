//! Storage tests — TMB-STOR-01 through TMB-STOR-05.

use chrono::Utc;
use cortex_core::memory::*;
use cortex_core::models::agent::AgentId;
use cortex_core::models::namespace::NamespaceId;
use cortex_storage::StorageEngine;

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

fn make_test_memory(id: &str, ns_uri: &str, agent: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(cortex_core::memory::types::CoreContent {
            project_name: "test".into(),
            description: "test".into(),
            metadata: serde_json::Value::Null,
        }),
        summary: format!("summary-{id}"),
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
        content_hash: format!("hash-{id}"),
        namespace: NamespaceId::parse(ns_uri).unwrap_or_default(),
        source_agent: AgentId::from(agent),
    }
}

/// TMB-STOR-01: Migration v015 runs cleanly on fresh DB.
#[test]
fn tmb_stor_01_migration_runs_cleanly() {
    // open_in_memory runs all migrations including v015.
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Verify we can query the new tables without error.
        let agents = cortex_storage::queries::multiagent_ops::list_agents(conn, None)?;
        assert!(agents.is_empty());

        let namespaces = cortex_storage::queries::multiagent_ops::list_namespaces(conn, None)?;
        assert!(namespaces.is_empty());

        Ok(())
    }).unwrap();
}

/// TMB-STOR-02: Migration v015 adds columns with correct defaults.
#[test]
fn tmb_stor_02_default_column_values() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Insert a memory without explicit namespace/source_agent (uses defaults).
        let mem = BaseMemory {
            id: "default-cols".into(),
            memory_type: MemoryType::Core,
            content: TypedContent::Core(cortex_core::memory::types::CoreContent {
                project_name: "test".into(),
                description: "test".into(),
                metadata: serde_json::Value::Null,
            }),
            summary: "test".into(),
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
            tags: vec![],
            archived: false,
            superseded_by: None,
            supersedes: None,
            content_hash: "hash".into(),
            namespace: Default::default(),
            source_agent: Default::default(),
        };
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem)?;

        let found = cortex_storage::queries::memory_crud::get_memory(conn, "default-cols")?;
        assert!(found.is_some());
        let found = found.unwrap();
        // Default namespace is agent://default/.
        assert_eq!(found.namespace.to_uri(), "agent://default/");
        // Default source_agent is "default".
        assert_eq!(found.source_agent.0, "default");

        Ok(())
    }).unwrap();
}

/// TMB-STOR-03: Namespace-aware memory queries filter correctly.
#[test]
fn tmb_stor_03_namespace_query_filter() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let mem_a = make_test_memory("ns-a-1", "agent://alpha/", "agent-a");
        let mem_b = make_test_memory("ns-b-1", "team://beta/", "agent-b");
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem_a)?;
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem_b)?;

        // Query by namespace.
        let alpha_mems = cortex_storage::queries::multiagent_ops::get_memories_by_namespace(
            conn, "agent://alpha/",
        )?;
        assert_eq!(alpha_mems.len(), 1);
        assert_eq!(alpha_mems[0], "ns-a-1");

        let beta_mems = cortex_storage::queries::multiagent_ops::get_memories_by_namespace(
            conn, "team://beta/",
        )?;
        assert_eq!(beta_mems.len(), 1);
        assert_eq!(beta_mems[0], "ns-b-1");

        // Namespace filter on query_by_type.
        let ns_alpha = NamespaceId::parse("agent://alpha/").unwrap();
        let filtered = cortex_storage::queries::memory_query::query_by_type(
            conn, MemoryType::Core, Some(&ns_alpha),
        )?;
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "ns-a-1");

        // Without filter → both.
        let all = cortex_storage::queries::memory_query::query_by_type(
            conn, MemoryType::Core, None,
        )?;
        assert_eq!(all.len(), 2);

        Ok(())
    }).unwrap();
}

/// TMB-STOR-04: Agent-aware memory queries filter correctly.
#[test]
fn tmb_stor_04_agent_query_filter() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        let mem_a = make_test_memory("ag-a-1", "agent://default/", "agent-alpha");
        let mem_b = make_test_memory("ag-b-1", "agent://default/", "agent-beta");
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem_a)?;
        cortex_storage::queries::memory_crud::insert_memory(conn, &mem_b)?;

        let alpha_mems = cortex_storage::queries::multiagent_ops::get_memories_by_agent(
            conn, "agent-alpha",
        )?;
        assert_eq!(alpha_mems.len(), 1);
        assert_eq!(alpha_mems[0], "ag-a-1");

        let beta_mems = cortex_storage::queries::multiagent_ops::get_memories_by_agent(
            conn, "agent-beta",
        )?;
        assert_eq!(beta_mems.len(), 1);
        assert_eq!(beta_mems[0], "ag-b-1");

        Ok(())
    }).unwrap();
}

/// TMB-STOR-05: All v015 tables and indexes created.
#[test]
fn tmb_stor_05_all_tables_and_indexes() {
    let eng = engine();
    eng.pool().writer.with_conn_sync(|conn| {
        // Check all 7 new tables exist.
        let tables = vec![
            "agent_registry",
            "memory_namespaces",
            "namespace_permissions",
            "memory_projections",
            "provenance_log",
            "agent_trust",
            "delta_queue",
        ];
        for table in &tables {
            let exists: bool = conn
                .prepare(&format!(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='{table}'"
                ))
                .unwrap()
                .exists([])
                .unwrap();
            assert!(exists, "table {table} should exist");
        }

        // Check key indexes exist.
        let indexes = vec![
            "idx_agent_status",
            "idx_agent_parent",
            "idx_proj_source",
            "idx_proj_target",
            "idx_prov_memory",
            "idx_prov_agent",
            "idx_delta_target",
            "idx_delta_created",
            "idx_memories_namespace",
            "idx_memories_source_agent",
        ];
        for idx in &indexes {
            let exists: bool = conn
                .prepare(&format!(
                    "SELECT 1 FROM sqlite_master WHERE type='index' AND name='{idx}'"
                ))
                .unwrap()
                .exists([])
                .unwrap();
            assert!(exists, "index {idx} should exist");
        }

        // Verify memories table has the new columns.
        let mut stmt = conn.prepare("PRAGMA table_info(memories)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(columns.contains(&"namespace_id".to_string()), "memories.namespace_id column missing");
        assert!(columns.contains(&"source_agent".to_string()), "memories.source_agent column missing");

        Ok(())
    }).unwrap();
}

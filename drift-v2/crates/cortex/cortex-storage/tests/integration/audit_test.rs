//! Integration test: audit log records all mutations.

use chrono::Utc;
use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

fn make_memory(id: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(CoreContent {
            project_name: "audit test".to_string(),
            description: "test".to_string(),
            metadata: serde_json::json!({}),
        }),
        summary: "audit test".to_string(),
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
        content_hash: "audit_hash".to_string(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

#[test]
fn test_audit_log_on_create() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("audit-1")).unwrap();

    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let entries = cortex_storage::queries::audit_ops::query_by_memory(conn, "audit-1")?;
            assert!(!entries.is_empty(), "should have audit entry for create");
            assert_eq!(
                entries[0].operation,
                cortex_core::models::AuditOperation::Create
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn test_audit_log_on_update() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut memory = make_memory("audit-update");
    engine.create(&memory).unwrap();

    memory.summary = "updated".to_string();
    engine.update(&memory).unwrap();

    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let entries =
                cortex_storage::queries::audit_ops::query_by_memory(conn, "audit-update")?;
            // Should have create + update entries.
            assert!(
                entries.len() >= 2,
                "should have at least 2 audit entries, got {}",
                entries.len()
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn test_audit_log_on_delete() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("audit-delete")).unwrap();
    engine.delete("audit-delete").unwrap();

    // Audit entries survive deletion since they're in a separate table.
    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let entries =
                cortex_storage::queries::audit_ops::query_by_memory(conn, "audit-delete")?;
            assert!(entries.len() >= 2, "should have create + archive entries");
            Ok(())
        })
        .unwrap();
}

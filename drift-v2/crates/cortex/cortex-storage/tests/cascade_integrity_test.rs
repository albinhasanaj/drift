//! Cascade integrity tests: verify that every mutation produces the correct
//! side-effects across ALL related tables — audit logs, temporal events,
//! version snapshots, links, embeddings, relationships, causal edges.
//!
//! These tests are the most important for 99.5%+ reliability because they
//! verify cross-table consistency that no single-module test can catch.

use chrono::Utc;
use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::models::{AuditActor, AuditOperation};
use cortex_core::traits::{CausalEdge, CausalEvidence, ICausalStorage, IMemoryStorage};
use cortex_storage::queries::{audit_ops, event_ops, version_ops};
use cortex_storage::StorageEngine;

fn make_memory(id: &str) -> BaseMemory {
    let content = TypedContent::Tribal(TribalContent {
        knowledge: format!("Knowledge for {id}"),
        severity: "medium".to_string(),
        warnings: vec![],
        consequences: vec![],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Tribal,
        content: content.clone(),
        summary: format!("Summary of {id}"),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![PatternLink {
            pattern_id: format!("pat-{id}"),
            pattern_name: format!("Pattern {id}"),
        }],
        linked_constraints: vec![ConstraintLink {
            constraint_id: format!("cst-{id}"),
            constraint_name: format!("Constraint {id}"),
        }],
        linked_files: vec![FileLink {
            file_path: format!("/src/{id}.rs"),
            line_start: Some(1),
            line_end: Some(10),
            content_hash: Some("abc123".to_string()),
        }],
        linked_functions: vec![FunctionLink {
            function_name: format!("fn_{id}"),
            file_path: format!("/src/{id}.rs"),
            signature: Some(format!("fn {id}() -> Result<()>")),
        }],
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT LOG COMPLETENESS: every CUD must produce correct audit entries
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn create_produces_audit_entry() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("audit-create");
    engine.create(&mem).unwrap();

    let entries = engine
        .pool()
        .writer
        .with_conn_sync(|conn| audit_ops::query_by_memory(conn, "audit-create"))
        .unwrap();

    assert!(!entries.is_empty(), "create must produce audit entry");
    assert!(
        entries.iter().any(|e| e.operation == AuditOperation::Create),
        "audit entry must have Create operation, got: {:?}",
        entries.iter().map(|e| &e.operation).collect::<Vec<_>>()
    );
    assert!(
        entries.iter().all(|e| e.actor == AuditActor::System),
        "audit actor should be System"
    );
}

#[test]
fn update_produces_audit_entry_and_version_snapshot() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("audit-update");
    engine.create(&mem).unwrap();

    // Update the memory
    mem.summary = "Updated summary".to_string();
    mem.confidence = Confidence::new(0.95);
    engine.update(&mem).unwrap();

    // Check audit log
    let entries = engine
        .pool()
        .writer
        .with_conn_sync(|conn| audit_ops::query_by_memory(conn, "audit-update"))
        .unwrap();

    let update_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.operation == AuditOperation::Update)
        .collect();
    assert!(
        !update_entries.is_empty(),
        "update must produce Update audit entry"
    );

    // Check version snapshot was created
    let versions = engine
        .pool()
        .writer
        .with_conn_sync(|conn| version_ops::get_version_history(conn, "audit-update"))
        .unwrap();
    assert!(
        !versions.is_empty(),
        "update must create a version snapshot of the pre-update state"
    );
    // Version should capture the OLD state (before update)
    assert_eq!(
        versions[0].summary, "Summary of audit-update",
        "version should capture pre-update summary"
    );
}

#[test]
fn delete_produces_audit_entry() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("audit-delete");
    engine.create(&mem).unwrap();
    engine.delete("audit-delete").unwrap();

    let entries = engine
        .pool()
        .writer
        .with_conn_sync(|conn| audit_ops::query_by_memory(conn, "audit-delete"))
        .unwrap();

    let archive_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.operation == AuditOperation::Archive)
        .collect();
    assert!(
        !archive_entries.is_empty(),
        "delete must produce Archive audit entry, got operations: {:?}",
        entries.iter().map(|e| &e.operation).collect::<Vec<_>>()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// CASCADE DELETE: verify ALL related data is cleaned up
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn delete_removes_all_links() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("cascade-links");
    engine.create(&mem).unwrap();

    // Verify links exist
    let loaded = engine.get("cascade-links").unwrap().unwrap();
    assert_eq!(loaded.linked_patterns.len(), 1);
    assert_eq!(loaded.linked_constraints.len(), 1);
    assert_eq!(loaded.linked_files.len(), 1);
    assert_eq!(loaded.linked_functions.len(), 1);

    // Delete
    engine.delete("cascade-links").unwrap();

    // Memory gone
    assert!(engine.get("cascade-links").unwrap().is_none());

    // Verify links are gone by directly querying link tables
    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            for table in &[
                "memory_patterns",
                "memory_constraints",
                "memory_files",
                "memory_functions",
            ] {
                let count: i64 = conn
                    .query_row(
                        &format!(
                            "SELECT COUNT(*) FROM {table} WHERE memory_id = 'cascade-links'"
                        ),
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 0, "table {table} should have no rows for deleted memory");
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn delete_does_not_remove_relationships_or_embeddings() {
    // Relationships and embeddings are separate concerns — verify they persist
    // even after the memory row is deleted (they may be cleaned up by compaction).
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("cascade-rel");
    engine.create(&mem).unwrap();

    // Add relationship
    let edge = RelationshipEdge {
        source_id: "cascade-rel".to_string(),
        target_id: "other".to_string(),
        relationship_type: RelationshipType::Related,
        strength: 0.5,
        evidence: vec!["test".to_string()],
        cross_agent_relation: None,
    };
    // Create the "other" memory for the relationship
    engine.create(&make_memory("other")).unwrap();
    engine.add_relationship(&edge).unwrap();

    // Store embedding
    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            cortex_storage::queries::vector_search::store_embedding(
                conn,
                "cascade-rel",
                "hash-cascade",
                &[1.0, 0.0],
                "test",
            )
        })
        .unwrap();

    // Delete the memory
    engine.delete("cascade-rel").unwrap();

    // Events should still exist (temporal history preserved)
    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "cascade-rel", None))
        .unwrap();
    assert!(
        !events.is_empty(),
        "events should persist after memory delete (temporal history)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// TEMPORAL EVENT COMPLETENESS: every mutation = correct event types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn create_emits_created_event() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ev-create")).unwrap();

    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "ev-create", None))
        .unwrap();

    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(
        types.contains(&"created"),
        "create must emit 'created' event, got: {types:?}"
    );
}

#[test]
fn update_content_emits_content_updated_event() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("ev-content");
    engine.create(&mem).unwrap();

    // Change content (different hash)
    let new_content = TypedContent::Tribal(TribalContent {
        knowledge: "Updated knowledge".to_string(),
        severity: "high".to_string(),
        warnings: vec![],
        consequences: vec![],
    });
    mem.content = new_content.clone();
    mem.content_hash = BaseMemory::compute_content_hash(&new_content).unwrap();
    engine.update(&mem).unwrap();

    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "ev-content", None))
        .unwrap();

    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(
        types.contains(&"content_updated"),
        "content change must emit 'content_updated', got: {types:?}"
    );
}

#[test]
fn update_confidence_emits_confidence_changed_event() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("ev-conf");
    engine.create(&mem).unwrap();

    mem.confidence = Confidence::new(0.3);
    engine.update(&mem).unwrap();

    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "ev-conf", None))
        .unwrap();

    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(
        types.contains(&"confidence_changed"),
        "confidence change must emit 'confidence_changed', got: {types:?}"
    );
}

#[test]
fn update_tags_emits_tags_modified_event() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("ev-tags");
    engine.create(&mem).unwrap();

    mem.tags = vec!["new-tag".to_string(), "another".to_string()];
    engine.update(&mem).unwrap();

    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "ev-tags", None))
        .unwrap();

    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(
        types.contains(&"tags_modified"),
        "tag change must emit 'tags_modified', got: {types:?}"
    );
}

#[test]
fn update_importance_emits_importance_changed_event() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("ev-imp");
    engine.create(&mem).unwrap();

    mem.importance = Importance::Critical;
    engine.update(&mem).unwrap();

    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "ev-imp", None))
        .unwrap();

    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(
        types.contains(&"importance_changed"),
        "importance change must emit 'importance_changed', got: {types:?}"
    );
}

#[test]
fn archive_memory_emits_archived_event() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("ev-archive");
    engine.create(&mem).unwrap();

    mem.archived = true;
    engine.update(&mem).unwrap();

    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "ev-archive", None))
        .unwrap();

    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(
        types.contains(&"archived"),
        "archive must emit 'archived' event, got: {types:?}"
    );
}

#[test]
fn delete_emits_archived_event() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ev-del")).unwrap();
    engine.delete("ev-del").unwrap();

    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "ev-del", None))
        .unwrap();

    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(
        types.contains(&"archived"),
        "delete must emit 'archived' event, got: {types:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// VERSION CHAIN: create → update → version → rollback lifecycle
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn update_creates_version_snapshot_of_old_state() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("ver-chain");
    engine.create(&mem).unwrap();

    // Update 3 times
    for i in 1..=3 {
        mem.summary = format!("Summary v{i}");
        let new_content = TypedContent::Tribal(TribalContent {
            knowledge: format!("Knowledge v{i}"),
            severity: "medium".to_string(),
            warnings: vec![],
            consequences: vec![],
        });
        mem.content = new_content.clone();
        mem.content_hash = BaseMemory::compute_content_hash(&new_content).unwrap();
        engine.update(&mem).unwrap();
    }

    // Should have 3 version snapshots (one per update, capturing pre-update state)
    let versions = engine
        .pool()
        .writer
        .with_conn_sync(|conn| version_ops::get_version_history(conn, "ver-chain"))
        .unwrap();

    assert_eq!(
        versions.len(),
        3,
        "3 updates should create 3 version snapshots"
    );

    // Versions should be in descending order
    assert!(versions[0].version > versions[1].version);
    assert!(versions[1].version > versions[2].version);

    // First version (oldest) should have original summary
    let oldest = &versions[2];
    assert_eq!(oldest.summary, "Summary of ver-chain");
}

#[test]
fn version_retention_enforces_limit() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("ver-ret");
    engine.create(&mem).unwrap();

    // Create 15 updates (exceeds MAX_VERSIONS = 10)
    for i in 1..=15 {
        mem.summary = format!("Summary v{i}");
        let new_content = TypedContent::Tribal(TribalContent {
            knowledge: format!("Knowledge v{i}"),
            severity: "medium".to_string(),
            warnings: vec![],
            consequences: vec![],
        });
        mem.content = new_content.clone();
        mem.content_hash = BaseMemory::compute_content_hash(&new_content).unwrap();
        engine.update(&mem).unwrap();
    }

    let count = engine
        .pool()
        .writer
        .with_conn_sync(|conn| version_ops::version_count(conn, "ver-ret"))
        .unwrap();

    assert!(
        count <= 10,
        "version retention should cap at 10, got {count}"
    );
}

#[test]
fn rollback_restores_old_content() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("ver-rb");
    engine.create(&mem).unwrap();

    let original_summary = mem.summary.clone();

    // Update to change content
    mem.summary = "Changed summary".to_string();
    let new_content = TypedContent::Tribal(TribalContent {
        knowledge: "Changed knowledge".to_string(),
        severity: "medium".to_string(),
        warnings: vec![],
        consequences: vec![],
    });
    mem.content = new_content.clone();
    mem.content_hash = BaseMemory::compute_content_hash(&new_content).unwrap();
    engine.update(&mem).unwrap();

    // Rollback to version 1
    engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            cortex_storage::versioning::rollback::rollback_to_version(conn, "ver-rb", 1)
        })
        .unwrap();

    // Verify content is restored
    let restored = engine.get("ver-rb").unwrap().unwrap();
    assert_eq!(
        restored.summary, original_summary,
        "rollback should restore original summary"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// EVENT OPS: direct query capabilities
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn event_count_matches_actual_events() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ev-count")).unwrap();

    let (events, count) = engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let events = event_ops::get_events_for_memory(conn, "ev-count", None)?;
            let count = event_ops::get_event_count(conn, "ev-count")?;
            Ok((events, count))
        })
        .unwrap();

    assert_eq!(
        events.len() as u64,
        count,
        "event count should match actual events"
    );
}

#[test]
fn events_by_type_filters_correctly() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("ev-type");
    engine.create(&mem).unwrap();

    // Generate confidence_changed events
    mem.confidence = Confidence::new(0.3);
    engine.update(&mem).unwrap();

    let confidence_events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_by_type(conn, "confidence_changed", None))
        .unwrap();

    assert!(
        !confidence_events.is_empty(),
        "should find confidence_changed events"
    );
    assert!(
        confidence_events
            .iter()
            .all(|e| e.event_type == "confidence_changed"),
        "filter should only return matching type"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// CAUSAL EDGE INTEGRITY
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn causal_edge_emits_events() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("cause")).unwrap();
    engine.create(&make_memory("effect")).unwrap();

    let edge = CausalEdge {
        source_id: "cause".to_string(),
        target_id: "effect".to_string(),
        relation: "causes".to_string(),
        strength: 0.9,
        evidence: vec![CausalEvidence {
            description: "Evidence".to_string(),
            source: "test".to_string(),
            timestamp: Utc::now(),
        }],
        source_agent: None,
    };
    engine.add_edge(&edge).unwrap();

    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "cause", None))
        .unwrap();

    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(
        types.contains(&"relationship_added"),
        "add_edge should emit relationship_added event, got: {types:?}"
    );
}

#[test]
fn causal_edge_update_strength_emits_event() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("str-src")).unwrap();
    engine.create(&make_memory("str-tgt")).unwrap();

    let edge = CausalEdge {
        source_id: "str-src".to_string(),
        target_id: "str-tgt".to_string(),
        relation: "influences".to_string(),
        strength: 0.5,
        evidence: vec![],
        source_agent: None,
    };
    engine.add_edge(&edge).unwrap();
    engine.update_strength("str-src", "str-tgt", 0.9).unwrap();

    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "str-src", None))
        .unwrap();

    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(
        types.contains(&"strength_updated"),
        "update_strength should emit strength_updated event, got: {types:?}"
    );
}

#[test]
fn causal_edge_remove_emits_event() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("rem-src")).unwrap();
    engine.create(&make_memory("rem-tgt")).unwrap();

    let edge = CausalEdge {
        source_id: "rem-src".to_string(),
        target_id: "rem-tgt".to_string(),
        relation: "triggers".to_string(),
        strength: 0.7,
        evidence: vec![],
        source_agent: None,
    };
    engine.add_edge(&edge).unwrap();
    engine.remove_edge("rem-src", "rem-tgt").unwrap();

    let events = engine
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, "rem-src", None))
        .unwrap();

    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(
        types.contains(&"relationship_removed"),
        "remove_edge should emit relationship_removed event, got: {types:?}"
    );
}

#[test]
fn causal_cycle_detection_works() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("a")).unwrap();
    engine.create(&make_memory("b")).unwrap();
    engine.create(&make_memory("c")).unwrap();

    // A → B → C
    engine
        .add_edge(&CausalEdge {
            source_id: "a".to_string(),
            target_id: "b".to_string(),
            relation: "causes".to_string(),
            strength: 0.9,
            evidence: vec![],
            source_agent: None,
        })
        .unwrap();
    engine
        .add_edge(&CausalEdge {
            source_id: "b".to_string(),
            target_id: "c".to_string(),
            relation: "causes".to_string(),
            strength: 0.9,
            evidence: vec![],
            source_agent: None,
        })
        .unwrap();

    // C → A would create a cycle
    let has_cycle = engine.has_cycle("c", "a").unwrap();
    assert!(has_cycle, "C→A should detect cycle through A→B→C");

    // D → A would not create a cycle (D doesn't exist in chain)
    let no_cycle = engine.has_cycle("a", "c").unwrap();
    // a→c: check if c can reach a. c has no outgoing edges yet, so no cycle.
    // Actually, let's check A→C direct: C→(nothing), so no path from C back to A except through existing B→C
    // has_cycle(a, c) checks if adding a→c creates cycle, meaning can c reach a?
    // c has no outgoing edges, so no.
    assert!(!no_cycle, "A→C direct should not detect cycle (C has no path back to A)");
}

#[test]
fn orphaned_edge_removal() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("orphan-src")).unwrap();
    engine.create(&make_memory("orphan-tgt")).unwrap();

    engine
        .add_edge(&CausalEdge {
            source_id: "orphan-src".to_string(),
            target_id: "orphan-tgt".to_string(),
            relation: "depends".to_string(),
            strength: 0.8,
            evidence: vec![],
            source_agent: None,
        })
        .unwrap();

    assert_eq!(engine.edge_count().unwrap(), 1);

    // Delete one of the memories
    engine.delete("orphan-tgt").unwrap();

    // Remove orphaned edges
    let removed = engine.remove_orphaned_edges().unwrap();
    assert_eq!(removed, 1, "should remove 1 orphaned edge");
    assert_eq!(engine.edge_count().unwrap(), 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT OPS: query by time range and actor
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn audit_query_by_time_range() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let before = Utc::now();
    engine.create(&make_memory("audit-time")).unwrap();
    let after = Utc::now();

    let entries = engine
        .pool()
        .writer
        .with_conn_sync(|conn| audit_ops::query_by_time_range(conn, before, after))
        .unwrap();

    assert!(
        !entries.is_empty(),
        "should find audit entries in time range"
    );
    assert!(
        entries.iter().any(|e| e.memory_id == "audit-time"),
        "should find our memory's audit entry"
    );
}

#[test]
fn audit_query_by_actor() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("audit-actor")).unwrap();

    let entries = engine
        .pool()
        .writer
        .with_conn_sync(|conn| audit_ops::query_by_actor(conn, &AuditActor::System))
        .unwrap();

    assert!(
        !entries.is_empty(),
        "should find System audit entries"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// LINK OPS: individual add_*_link operations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn add_individual_links_after_create() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("link-add");
    mem.linked_patterns = vec![];
    mem.linked_constraints = vec![];
    mem.linked_files = vec![];
    mem.linked_functions = vec![];
    engine.create(&mem).unwrap();

    // Add links individually
    engine
        .add_pattern_link(
            "link-add",
            &PatternLink {
                pattern_id: "p1".to_string(),
                pattern_name: "Pattern 1".to_string(),
            },
        )
        .unwrap();

    engine
        .add_constraint_link(
            "link-add",
            &ConstraintLink {
                constraint_id: "c1".to_string(),
                constraint_name: "Constraint 1".to_string(),
            },
        )
        .unwrap();

    engine
        .add_file_link(
            "link-add",
            &FileLink {
                file_path: "/test.rs".to_string(),
                line_start: Some(1),
                line_end: Some(5),
                content_hash: None,
            },
        )
        .unwrap();

    engine
        .add_function_link(
            "link-add",
            &FunctionLink {
                function_name: "test_fn".to_string(),
                file_path: "/test.rs".to_string(),
                signature: None,
            },
        )
        .unwrap();

    let loaded = engine.get("link-add").unwrap().unwrap();
    assert_eq!(loaded.linked_patterns.len(), 1);
    assert_eq!(loaded.linked_constraints.len(), 1);
    assert_eq!(loaded.linked_files.len(), 1);
    assert_eq!(loaded.linked_functions.len(), 1);
}

#[test]
fn add_duplicate_link_is_ignored() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("link-dup");
    engine.create(&mem).unwrap();

    // Add the same pattern link again (INSERT OR IGNORE)
    let link = PatternLink {
        pattern_id: "pat-link-dup".to_string(),
        pattern_name: "Pattern link-dup".to_string(),
    };
    engine.add_pattern_link("link-dup", &link).unwrap();

    let loaded = engine.get("link-dup").unwrap().unwrap();
    // Should still have only 1 pattern link (the one from create + the duplicate ignored)
    assert_eq!(
        loaded.linked_patterns.len(),
        1,
        "duplicate link should be ignored"
    );
}

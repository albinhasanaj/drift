//! Persistence reliability tests: transaction atomicity, rollback correctness,
//! read/write pool separation, WAL mode verification.

use chrono::Utc;
use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::traits::{CausalEdge, CausalEvidence, ICausalStorage, IMemoryStorage};
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
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

fn make_memory_with_links(id: &str) -> BaseMemory {
    let mut mem = make_memory(id);
    mem.linked_patterns = vec![PatternLink {
        pattern_id: format!("pat-{id}"),
        pattern_name: format!("Pattern {id}"),
    }];
    mem.linked_files = vec![FileLink {
        file_path: format!("/src/{id}.rs"),
        line_start: Some(1),
        line_end: Some(10),
        content_hash: Some("abc123".to_string()),
    }];
    mem
}

// ── Insert atomicity ──────────────────────────────────────────────────────

#[test]
fn insert_memory_persists_with_links() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory_with_links("link-test");

    engine.create(&mem).unwrap();
    let loaded = engine.get("link-test").unwrap().expect("should exist");

    assert_eq!(loaded.id, "link-test");
    assert_eq!(loaded.linked_patterns.len(), 1);
    assert_eq!(loaded.linked_patterns[0].pattern_id, "pat-link-test");
    assert_eq!(loaded.linked_files.len(), 1);
    assert_eq!(loaded.linked_files[0].file_path, "/src/link-test.rs");
}

#[test]
fn insert_duplicate_id_fails_atomically() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("dup-test");

    engine.create(&mem).unwrap();

    // Second insert with same ID should fail.
    let result = engine.create(&mem);
    assert!(result.is_err(), "duplicate insert should fail");

    // Original should still be intact.
    let loaded = engine.get("dup-test").unwrap().expect("original should exist");
    assert_eq!(loaded.id, "dup-test");
}

// ── Update atomicity ──────────────────────────────────────────────────────

#[test]
fn update_memory_is_atomic_with_links() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory_with_links("update-atom");
    engine.create(&mem).unwrap();

    // Update: change tags, confidence, add a constraint link.
    mem.tags = vec!["updated".to_string(), "new-tag".to_string()];
    mem.confidence = Confidence::new(0.95);
    mem.linked_constraints = vec![ConstraintLink {
        constraint_id: "cst-1".to_string(),
        constraint_name: "Constraint 1".to_string(),
    }];

    engine.update(&mem).unwrap();

    let loaded = engine.get("update-atom").unwrap().expect("should exist");
    assert_eq!(loaded.tags, vec!["updated", "new-tag"]);
    assert!((loaded.confidence.value() - 0.95).abs() < f64::EPSILON);
    assert_eq!(loaded.linked_constraints.len(), 1);
    // Old links should still be there.
    assert_eq!(loaded.linked_patterns.len(), 1);
    assert_eq!(loaded.linked_files.len(), 1);
}

#[test]
fn update_nonexistent_memory_returns_error() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("ghost");

    let result = engine.update(&mem);
    assert!(result.is_err(), "update nonexistent should fail");
}

// ── Delete atomicity ──────────────────────────────────────────────────────

#[test]
fn delete_memory_removes_all_links() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory_with_links("del-links");
    engine.create(&mem).unwrap();

    engine.delete("del-links").unwrap();

    let loaded = engine.get("del-links").unwrap();
    assert!(loaded.is_none(), "memory should be deleted");
}

// ── Bulk insert atomicity ─────────────────────────────────────────────────

#[test]
fn bulk_insert_all_or_nothing() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let memories: Vec<_> = (0..5).map(|i| make_memory(&format!("bulk-{i}"))).collect();

    let count = engine.create_bulk(&memories).unwrap();
    assert_eq!(count, 5);

    for i in 0..5 {
        let mem = engine.get(&format!("bulk-{i}")).unwrap();
        assert!(mem.is_some(), "bulk-{i} should exist");
    }
}

#[test]
fn bulk_insert_duplicate_rolls_back_entire_batch() {
    let engine = StorageEngine::open_in_memory().unwrap();

    // Pre-insert one memory.
    let existing = make_memory("bulk-dup-2");
    engine.create(&existing).unwrap();

    // Try bulk insert with a duplicate at index 2.
    let memories: Vec<_> = (0..5).map(|i| make_memory(&format!("bulk-dup-{i}"))).collect();
    let result = engine.create_bulk(&memories);
    assert!(result.is_err(), "bulk insert with duplicate should fail");

    // Only the pre-existing memory should exist. All others from the batch should be rolled back.
    assert!(engine.get("bulk-dup-2").unwrap().is_some(), "pre-existing should survive");
    assert!(engine.get("bulk-dup-0").unwrap().is_none(), "batch item 0 should be rolled back");
    assert!(engine.get("bulk-dup-1").unwrap().is_none(), "batch item 1 should be rolled back");
    assert!(engine.get("bulk-dup-3").unwrap().is_none(), "batch item 3 should be rolled back");
    assert!(engine.get("bulk-dup-4").unwrap().is_none(), "batch item 4 should be rolled back");
}

// ── Causal edge atomicity ─────────────────────────────────────────────────

#[test]
fn add_edge_with_evidence_is_atomic() {
    let engine = StorageEngine::open_in_memory().unwrap();

    // Create two memories for the edge.
    engine.create(&make_memory("cause")).unwrap();
    engine.create(&make_memory("effect")).unwrap();

    let edge = CausalEdge {
        source_id: "cause".to_string(),
        target_id: "effect".to_string(),
        relation: "causes".to_string(),
        strength: 0.9,
        evidence: vec![
            CausalEvidence {
                description: "Evidence 1".to_string(),
                source: "test".to_string(),
                timestamp: Utc::now(),
            },
            CausalEvidence {
                description: "Evidence 2".to_string(),
                source: "test".to_string(),
                timestamp: Utc::now(),
            },
        ],
        source_agent: None,
    };

    engine.add_edge(&edge).unwrap();

    let edges = engine.get_edges("cause").unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].evidence.len(), 2);
    assert!((edges[0].strength - 0.9).abs() < f64::EPSILON);
}

#[test]
fn remove_edge_cleans_up_evidence() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("src")).unwrap();
    engine.create(&make_memory("tgt")).unwrap();

    let edge = CausalEdge {
        source_id: "src".to_string(),
        target_id: "tgt".to_string(),
        relation: "relates".to_string(),
        strength: 0.7,
        evidence: vec![CausalEvidence {
            description: "proof".to_string(),
            source: "test".to_string(),
            timestamp: Utc::now(),
        }],
        source_agent: None,
    };

    engine.add_edge(&edge).unwrap();
    assert_eq!(engine.edge_count().unwrap(), 1);

    engine.remove_edge("src", "tgt").unwrap();
    assert_eq!(engine.edge_count().unwrap(), 0);
    assert!(engine.get_edges("src").unwrap().is_empty());
}

// ── Relationship atomicity ────────────────────────────────────────────────

#[test]
fn relationship_add_remove_roundtrip() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("rel-a")).unwrap();
    engine.create(&make_memory("rel-b")).unwrap();

    let edge = cortex_core::memory::RelationshipEdge {
        source_id: "rel-a".to_string(),
        target_id: "rel-b".to_string(),
        relationship_type: cortex_core::memory::RelationshipType::Related,
        strength: 0.5,
        evidence: vec!["test evidence".to_string()],
        cross_agent_relation: None,
    };

    engine.add_relationship(&edge).unwrap();
    let rels = engine.get_relationships("rel-a", None).unwrap();
    assert_eq!(rels.len(), 1);

    engine.remove_relationship("rel-a", "rel-b").unwrap();
    let rels = engine.get_relationships("rel-a", None).unwrap();
    assert!(rels.is_empty());
}

// ── Embedding store atomicity ─────────────────────────────────────────────

#[test]
fn store_embedding_and_search() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("emb-1")).unwrap();
    engine.create(&make_memory("emb-2")).unwrap();

    // Store embeddings via pool writer.
    engine.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::vector_search::store_embedding(
            conn, "emb-1", "hash-1", &[1.0, 0.0, 0.0], "test-model",
        )?;
        cortex_storage::queries::vector_search::store_embedding(
            conn, "emb-2", "hash-2", &[0.0, 1.0, 0.0], "test-model",
        )?;
        Ok(())
    }).unwrap();

    // Search should find emb-1 as most similar to query [1,0,0].
    let results = engine.search_vector(&[1.0, 0.0, 0.0], 5).unwrap();
    assert!(!results.is_empty());
    assert_eq!(results[0].0.id, "emb-1");
}

// ── WAL mode verification ─────────────────────────────────────────────────

#[test]
fn wal_mode_verified_on_file_backed_db() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test-wal.db");
    let engine = StorageEngine::open(&db_path).unwrap();

    // Verify WAL mode via the pool.
    engine.pool().writer.with_conn_sync(|conn| {
        let ok = cortex_storage::pool::pragmas::verify_wal_mode(conn)?;
        assert!(ok, "WAL mode should be active");
        Ok(())
    }).unwrap();

    // Create and retrieve a memory to verify basic function.
    engine.create(&make_memory("wal-test")).unwrap();
    let mem = engine.get("wal-test").unwrap();
    assert!(mem.is_some());

    drop(engine);
    dir.close().unwrap();
}

// ── Version tracking atomicity ────────────────────────────────────────────

#[test]
fn version_insert_is_sequential() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_memory("ver-test")).unwrap();

    engine.pool().writer.with_conn_sync(|conn| {
        let v1 = cortex_storage::queries::version_ops::insert_version(
            conn, "ver-test", "{}", "summary v1", 0.8, "system", "create",
        )?;
        assert_eq!(v1, 1);

        let v2 = cortex_storage::queries::version_ops::insert_version(
            conn, "ver-test", "{}", "summary v2", 0.9, "system", "update",
        )?;
        assert_eq!(v2, 2);

        let history = cortex_storage::queries::version_ops::get_version_history(conn, "ver-test")?;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].version, 2); // newest first
        assert_eq!(history[1].version, 1);

        Ok(())
    }).unwrap();
}

//! Integration test: full CRUD lifecycle.

use chrono::Utc;
use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

fn make_test_memory(id: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(CoreContent {
            project_name: "test project".to_string(),
            description: "test description".to_string(),
            metadata: serde_json::json!({}),
        }),
        summary: "test summary".to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::High,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![PatternLink {
            pattern_id: "p1".to_string(),
            pattern_name: "singleton".to_string(),
        }],
        linked_constraints: vec![],
        linked_files: vec![FileLink {
            file_path: "src/main.rs".to_string(),
            line_start: Some(1),
            line_end: Some(10),
            content_hash: Some("abc123".to_string()),
        }],
        linked_functions: vec![],
        tags: vec!["test".to_string(), "core".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: "hash123".to_string(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

#[test]
fn test_create_and_get() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let memory = make_test_memory("mem-001");

    engine.create(&memory).unwrap();
    let retrieved = engine.get("mem-001").unwrap().expect("memory should exist");

    assert_eq!(retrieved.id, "mem-001");
    assert_eq!(retrieved.memory_type, MemoryType::Core);
    assert_eq!(retrieved.summary, "test summary");
    assert_eq!(retrieved.importance, Importance::High);
    assert!(retrieved.confidence.value() > 0.89);
    assert_eq!(retrieved.tags, vec!["test", "core"]);
    assert!(!retrieved.archived);
    assert_eq!(retrieved.content_hash, "hash123");
}

#[test]
fn test_create_and_get_with_links() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let memory = make_test_memory("mem-links");

    engine.create(&memory).unwrap();
    let retrieved = engine
        .get("mem-links")
        .unwrap()
        .expect("memory should exist");

    assert_eq!(retrieved.linked_patterns.len(), 1);
    assert_eq!(retrieved.linked_patterns[0].pattern_name, "singleton");
    assert_eq!(retrieved.linked_files.len(), 1);
    assert_eq!(retrieved.linked_files[0].file_path, "src/main.rs");
    assert_eq!(retrieved.linked_files[0].line_start, Some(1));
}

#[test]
fn test_update() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut memory = make_test_memory("mem-update");

    engine.create(&memory).unwrap();

    memory.summary = "updated summary".to_string();
    memory.importance = Importance::Critical;
    memory.tags = vec!["updated".to_string()];

    engine.update(&memory).unwrap();

    let retrieved = engine
        .get("mem-update")
        .unwrap()
        .expect("memory should exist");
    assert_eq!(retrieved.summary, "updated summary");
    assert_eq!(retrieved.importance, Importance::Critical);
    assert_eq!(retrieved.tags, vec!["updated"]);
}

#[test]
fn test_delete() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let memory = make_test_memory("mem-delete");

    engine.create(&memory).unwrap();
    assert!(engine.get("mem-delete").unwrap().is_some());

    engine.delete("mem-delete").unwrap();
    assert!(engine.get("mem-delete").unwrap().is_none());
}

#[test]
fn test_bulk_insert_and_get() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let memories: Vec<BaseMemory> = (0..100)
        .map(|i| make_test_memory(&format!("bulk-{i:03}")))
        .collect();

    let count = engine.create_bulk(&memories).unwrap();
    assert_eq!(count, 100);

    let ids: Vec<String> = (0..100).map(|i| format!("bulk-{i:03}")).collect();
    let retrieved = engine.get_bulk(&ids).unwrap();
    assert_eq!(retrieved.len(), 100);
}

#[test]
fn test_query_by_type() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let memory = make_test_memory("mem-type");
    engine.create(&memory).unwrap();

    let results = engine.query_by_type(MemoryType::Core).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "mem-type");

    let results = engine.query_by_type(MemoryType::Episodic).unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_query_by_importance() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let memory = make_test_memory("mem-imp");
    engine.create(&memory).unwrap();

    let results = engine.query_by_importance(Importance::High).unwrap();
    assert_eq!(results.len(), 1);

    let results = engine.query_by_importance(Importance::Critical).unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_query_by_confidence_range() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let memory = make_test_memory("mem-conf");
    engine.create(&memory).unwrap();

    let results = engine.query_by_confidence_range(0.8, 1.0).unwrap();
    assert_eq!(results.len(), 1);

    let results = engine.query_by_confidence_range(0.0, 0.5).unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_query_by_tags() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let memory = make_test_memory("mem-tags");
    engine.create(&memory).unwrap();

    let results = engine.query_by_tags(&["test".to_string()]).unwrap();
    assert_eq!(results.len(), 1);

    let results = engine.query_by_tags(&["nonexistent".to_string()]).unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_get_nonexistent() {
    let engine = StorageEngine::open_in_memory().unwrap();
    assert!(engine.get("does-not-exist").unwrap().is_none());
}

#[test]
fn test_fts5_search() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut memory = make_test_memory("mem-fts");
    memory.content = TypedContent::Core(CoreContent {
        project_name: "bcrypt password hashing is required".to_string(),
        description: "security best practice".to_string(),
        metadata: serde_json::json!({"scope": "authentication"}),
    });
    engine.create(&memory).unwrap();

    let results = engine.search_fts5("bcrypt", 10).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "mem-fts");
}

#[test]
fn test_aggregation() {
    let engine = StorageEngine::open_in_memory().unwrap();
    for i in 0..5 {
        engine
            .create(&make_test_memory(&format!("agg-{i}")))
            .unwrap();
    }

    let counts = engine.count_by_type().unwrap();
    let core_count = counts.iter().find(|(t, _)| *t == MemoryType::Core);
    assert_eq!(core_count.map(|(_, c)| *c), Some(5));

    let avg = engine.average_confidence().unwrap();
    assert!(avg > 0.8);
}

#[test]
fn test_relationships() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.create(&make_test_memory("rel-a")).unwrap();
    engine.create(&make_test_memory("rel-b")).unwrap();

    let edge = RelationshipEdge {
        source_id: "rel-a".to_string(),
        target_id: "rel-b".to_string(),
        relationship_type: RelationshipType::Supports,
        strength: 0.8,
        evidence: vec!["test evidence".to_string()],
        cross_agent_relation: None,
    };

    engine.add_relationship(&edge).unwrap();

    let rels = engine.get_relationships("rel-a", None).unwrap();
    assert_eq!(rels.len(), 1);
    assert_eq!(rels[0].relationship_type, RelationshipType::Supports);

    let rels = engine
        .get_relationships("rel-a", Some(RelationshipType::Supports))
        .unwrap();
    assert_eq!(rels.len(), 1);

    engine.remove_relationship("rel-a", "rel-b").unwrap();
    let rels = engine.get_relationships("rel-a", None).unwrap();
    assert!(rels.is_empty());
}

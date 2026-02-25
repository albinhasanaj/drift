//! Targeted coverage tests for cortex-storage uncovered paths.
//!
//! Focuses on: compaction (archived cleanup, storage health, embedding dedup),
//! versioning (tracker, retention, query, diff), audit rotation,
//! aggregation (count_by_type, avg_confidence, stale_count, storage_stats),
//! maintenance (vacuum, checkpoint, integrity), engine trait impls.

use chrono::{Duration, Utc};
use cortex_core::memory::links::{ConstraintLink, FileLink, FunctionLink, PatternLink};
use cortex_core::memory::*;
use cortex_core::traits::{CausalEdge, CausalEvidence, ICausalStorage, IMemoryStorage};
use cortex_storage::StorageEngine;

// ─── Helper ──────────────────────────────────────────────────────────────────

fn make_memory(id: &str, summary: &str, mem_type: MemoryType) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: mem_type,
        content: TypedContent::Semantic(cortex_core::memory::types::SemanticContent {
            knowledge: summary.to_string(),
            source_episodes: vec![],
            consolidation_confidence: 0.8,
        }),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 1,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: format!("hash-{id}"),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

fn engine() -> StorageEngine {
    StorageEngine::open_in_memory().expect("open in-memory storage")
}

// ─── Engine: IMemoryStorage trait methods ────────────────────────────────────

#[test]
fn engine_create_and_get() {
    let eng = engine();
    let mem = make_memory("m1", "test memory", MemoryType::Semantic);
    eng.create(&mem).unwrap();
    let got = eng.get("m1").unwrap().unwrap();
    assert_eq!(got.id, "m1");
    assert_eq!(got.summary, "test memory");
}

#[test]
fn engine_get_nonexistent() {
    let eng = engine();
    assert!(eng.get("nonexistent").unwrap().is_none());
}

#[test]
fn engine_update() {
    let eng = engine();
    let mut mem = make_memory("m2", "original", MemoryType::Semantic);
    eng.create(&mem).unwrap();
    mem.summary = "updated".to_string();
    eng.update(&mem).unwrap();
    let got = eng.get("m2").unwrap().unwrap();
    assert_eq!(got.summary, "updated");
}

#[test]
fn engine_delete() {
    let eng = engine();
    let mem = make_memory("m3", "to delete", MemoryType::Episodic);
    eng.create(&mem).unwrap();
    eng.delete("m3").unwrap();
    assert!(eng.get("m3").unwrap().is_none());
}

#[test]
fn engine_create_bulk_and_get_bulk() {
    let eng = engine();
    let mems: Vec<BaseMemory> = (0..5)
        .map(|i| {
            make_memory(
                &format!("bulk{i}"),
                &format!("bulk mem {i}"),
                MemoryType::Semantic,
            )
        })
        .collect();
    let count = eng.create_bulk(&mems).unwrap();
    assert_eq!(count, 5);

    let ids: Vec<String> = (0..5).map(|i| format!("bulk{i}")).collect();
    let got = eng.get_bulk(&ids).unwrap();
    assert_eq!(got.len(), 5);
}

#[test]
fn engine_query_by_type() {
    let eng = engine();
    eng.create(&make_memory("qt1", "semantic", MemoryType::Semantic))
        .unwrap();
    eng.create(&make_memory("qt2", "episodic", MemoryType::Episodic))
        .unwrap();
    eng.create(&make_memory("qt3", "semantic2", MemoryType::Semantic))
        .unwrap();
    let results = eng.query_by_type(MemoryType::Semantic).unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn engine_query_by_importance() {
    let eng = engine();
    let mut mem = make_memory("qi1", "critical", MemoryType::Semantic);
    mem.importance = Importance::Critical;
    eng.create(&mem).unwrap();
    eng.create(&make_memory("qi2", "normal", MemoryType::Semantic))
        .unwrap();
    let results = eng.query_by_importance(Importance::Critical).unwrap();
    assert!(results.iter().all(|m| m.importance >= Importance::Critical));
}

#[test]
fn engine_query_by_confidence_range() {
    let eng = engine();
    let mut low = make_memory("qc1", "low conf", MemoryType::Semantic);
    low.confidence = Confidence::new(0.3);
    eng.create(&low).unwrap();
    eng.create(&make_memory("qc2", "high conf", MemoryType::Semantic))
        .unwrap();
    let results = eng.query_by_confidence_range(0.7, 1.0).unwrap();
    assert!(results.iter().all(|m| m.confidence.value() >= 0.7));
}

#[test]
fn engine_query_by_date_range() {
    let eng = engine();
    eng.create(&make_memory("qd1", "today", MemoryType::Semantic))
        .unwrap();
    let from = Utc::now() - Duration::hours(1);
    let to = Utc::now() + Duration::hours(1);
    let results = eng.query_by_date_range(from, to).unwrap();
    assert!(!results.is_empty());
}

#[test]
fn engine_query_by_tags() {
    let eng = engine();
    eng.create(&make_memory("tg1", "tagged", MemoryType::Semantic))
        .unwrap();
    let results = eng.query_by_tags(&["test".to_string()]).unwrap();
    assert!(!results.is_empty());
}

#[test]
fn engine_search_fts5() {
    let eng = engine();
    eng.create(&make_memory(
        "fts1",
        "bcrypt password hashing",
        MemoryType::Semantic,
    ))
    .unwrap();
    let results = eng.search_fts5("bcrypt", 10).unwrap();
    assert!(!results.is_empty());
}

// ─── Relationships ───────────────────────────────────────────────────────────

#[test]
fn engine_add_and_get_relationships() {
    let eng = engine();
    eng.create(&make_memory("r1", "source", MemoryType::Semantic))
        .unwrap();
    eng.create(&make_memory("r2", "target", MemoryType::Semantic))
        .unwrap();
    let edge = RelationshipEdge {
        source_id: "r1".to_string(),
        target_id: "r2".to_string(),
        relationship_type: RelationshipType::Supports,
        strength: 0.9,
        evidence: vec![],
        cross_agent_relation: None,
    };
    eng.add_relationship(&edge).unwrap();
    let rels = eng.get_relationships("r1", None).unwrap();
    assert_eq!(rels.len(), 1);
    assert_eq!(rels[0].target_id, "r2");
}

#[test]
fn engine_remove_relationship() {
    let eng = engine();
    eng.create(&make_memory("rr1", "src", MemoryType::Semantic))
        .unwrap();
    eng.create(&make_memory("rr2", "tgt", MemoryType::Semantic))
        .unwrap();
    let edge = RelationshipEdge {
        source_id: "rr1".to_string(),
        target_id: "rr2".to_string(),
        relationship_type: RelationshipType::Related,
        strength: 0.5,
        evidence: vec![],
        cross_agent_relation: None,
    };
    eng.add_relationship(&edge).unwrap();
    eng.remove_relationship("rr1", "rr2").unwrap();
    let rels = eng.get_relationships("rr1", None).unwrap();
    assert!(rels.is_empty());
}

// ─── Links ───────────────────────────────────────────────────────────────────

#[test]
fn engine_add_pattern_link() {
    let eng = engine();
    eng.create(&make_memory("pl1", "pattern linked", MemoryType::Semantic))
        .unwrap();
    let link = PatternLink {
        pattern_id: "pat1".to_string(),
        pattern_name: "singleton".to_string(),
    };
    eng.add_pattern_link("pl1", &link).unwrap();
}

#[test]
fn engine_add_constraint_link() {
    let eng = engine();
    eng.create(&make_memory(
        "cl1",
        "constraint linked",
        MemoryType::Semantic,
    ))
    .unwrap();
    let link = ConstraintLink {
        constraint_id: "con1".to_string(),
        constraint_name: "no-raw-sql".to_string(),
    };
    eng.add_constraint_link("cl1", &link).unwrap();
}

#[test]
fn engine_add_file_link() {
    let eng = engine();
    eng.create(&make_memory("fl1", "file linked", MemoryType::Semantic))
        .unwrap();
    let link = FileLink {
        file_path: "src/main.rs".to_string(),
        line_start: Some(1),
        line_end: Some(10),
        content_hash: Some("abc123".to_string()),
    };
    eng.add_file_link("fl1", &link).unwrap();
}

#[test]
fn engine_add_function_link() {
    let eng = engine();
    eng.create(&make_memory("fn1", "function linked", MemoryType::Semantic))
        .unwrap();
    let link = FunctionLink {
        function_name: "main".to_string(),
        file_path: "src/main.rs".to_string(),
        signature: Some("fn main()".to_string()),
    };
    eng.add_function_link("fn1", &link).unwrap();
}

// ─── Aggregation ─────────────────────────────────────────────────────────────

#[test]
fn engine_count_by_type() {
    let eng = engine();
    eng.create(&make_memory("ct1", "sem", MemoryType::Semantic))
        .unwrap();
    eng.create(&make_memory("ct2", "epi", MemoryType::Episodic))
        .unwrap();
    let counts = eng.count_by_type().unwrap();
    assert!(!counts.is_empty());
}

#[test]
fn engine_average_confidence() {
    let eng = engine();
    eng.create(&make_memory("ac1", "conf test", MemoryType::Semantic))
        .unwrap();
    let avg = eng.average_confidence().unwrap();
    assert!(avg > 0.0);
}

#[test]
fn engine_stale_count() {
    let eng = engine();
    eng.create(&make_memory("sc1", "fresh", MemoryType::Semantic))
        .unwrap();
    let stale = eng.stale_count(30).unwrap();
    assert_eq!(stale, 0); // Just created, not stale.
}

#[test]
fn engine_vacuum() {
    let eng = engine();
    eng.vacuum().unwrap(); // Should not panic on empty DB.
}

// ─── ICausalStorage trait methods ────────────────────────────────────────────

fn causal_edge(src: &str, tgt: &str, strength: f64) -> CausalEdge {
    CausalEdge {
        source_id: src.to_string(),
        target_id: tgt.to_string(),
        relation: "causes".to_string(),
        strength,
        evidence: vec![],
        source_agent: None,
    }
}

#[test]
fn engine_causal_add_and_get_edges() {
    let eng = engine();
    eng.create(&make_memory("ce1", "cause", MemoryType::Semantic))
        .unwrap();
    eng.create(&make_memory("ce2", "effect", MemoryType::Semantic))
        .unwrap();
    eng.add_edge(&causal_edge("ce1", "ce2", 0.8)).unwrap();
    let edges = eng.get_edges("ce1").unwrap();
    assert_eq!(edges.len(), 1);
}

#[test]
fn engine_causal_remove_edge() {
    let eng = engine();
    eng.create(&make_memory("cr1", "src", MemoryType::Semantic))
        .unwrap();
    eng.create(&make_memory("cr2", "tgt", MemoryType::Semantic))
        .unwrap();
    eng.add_edge(&causal_edge("cr1", "cr2", 0.7)).unwrap();
    eng.remove_edge("cr1", "cr2").unwrap();
    let edges = eng.get_edges("cr1").unwrap();
    assert!(edges.is_empty());
}

#[test]
fn engine_causal_update_strength() {
    let eng = engine();
    eng.create(&make_memory("us1", "src", MemoryType::Semantic))
        .unwrap();
    eng.create(&make_memory("us2", "tgt", MemoryType::Semantic))
        .unwrap();
    eng.add_edge(&causal_edge("us1", "us2", 0.5)).unwrap();
    eng.update_strength("us1", "us2", 0.9).unwrap();
    let edges = eng.get_edges("us1").unwrap();
    assert!((edges[0].strength - 0.9).abs() < 0.01);
}

#[test]
fn engine_causal_add_evidence() {
    let eng = engine();
    eng.create(&make_memory("ev1", "src", MemoryType::Semantic))
        .unwrap();
    eng.create(&make_memory("ev2", "tgt", MemoryType::Semantic))
        .unwrap();
    eng.add_edge(&causal_edge("ev1", "ev2", 0.6)).unwrap();
    let evidence = CausalEvidence {
        description: "observed correlation".to_string(),
        source: "ev1".to_string(),
        timestamp: Utc::now(),
    };
    eng.add_evidence("ev1", "ev2", &evidence).unwrap();
}

#[test]
fn engine_causal_has_cycle() {
    let eng = engine();
    eng.create(&make_memory("cy1", "a", MemoryType::Semantic))
        .unwrap();
    eng.create(&make_memory("cy2", "b", MemoryType::Semantic))
        .unwrap();
    eng.add_edge(&causal_edge("cy1", "cy2", 0.5)).unwrap();
    // cy2 → cy1 would create a cycle.
    let has = eng.has_cycle("cy2", "cy1").unwrap();
    assert!(has);
}

#[test]
fn engine_causal_edge_and_node_count() {
    let eng = engine();
    assert_eq!(eng.edge_count().unwrap(), 0);
    assert_eq!(eng.node_count().unwrap(), 0);

    eng.create(&make_memory("nc1", "a", MemoryType::Semantic))
        .unwrap();
    eng.create(&make_memory("nc2", "b", MemoryType::Semantic))
        .unwrap();
    eng.add_edge(&causal_edge("nc1", "nc2", 0.5)).unwrap();
    assert_eq!(eng.edge_count().unwrap(), 1);
    assert_eq!(eng.node_count().unwrap(), 2);
}

#[test]
fn engine_causal_remove_orphaned_edges() {
    let eng = engine();
    let removed = eng.remove_orphaned_edges().unwrap();
    assert_eq!(removed, 0); // No orphans on empty DB.
}

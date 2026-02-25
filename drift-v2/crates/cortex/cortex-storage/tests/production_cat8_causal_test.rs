//! Cat 8: Causal Graph Storage (CG-01 through CG-12)
//!
//! Tests add_edge atomicity, SAVEPOINT rollback, INSERT OR REPLACE,
//! bidirectional get, evidence loading, remove_edge event ordering,
//! evidence cascade, update_strength events, cycle detection,
//! edge/node counts, and orphaned edge cleanup.

use chrono::Utc;

use cortex_core::memory::*;
use cortex_core::traits::{CausalEdge, CausalEvidence, ICausalStorage, IMemoryStorage};
use cortex_storage::queries::event_ops;
use cortex_storage::StorageEngine;

// ─── Fixtures ────────────────────────────────────────────────────────────────

fn make_memory(id: &str) -> BaseMemory {
    let now = Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: format!("obs {id}"),
        evidence: vec![],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Insight,
        content: tc.clone(),
        summary: format!("summary {id}"),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: now,
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&tc).unwrap(),
    }
}

fn make_edge(src: &str, tgt: &str, strength: f64) -> CausalEdge {
    CausalEdge {
        source_id: src.into(),
        target_id: tgt.into(),
        relation: "causes".into(),
        strength,
        evidence: vec![],
        source_agent: None,
    }
}

fn make_edge_with_evidence(src: &str, tgt: &str, n: usize) -> CausalEdge {
    let evidence: Vec<CausalEvidence> = (0..n)
        .map(|i| CausalEvidence {
            description: format!("evidence {i}"),
            source: "test".into(),
            timestamp: Utc::now(),
        })
        .collect();
    CausalEdge {
        source_id: src.into(),
        target_id: tgt.into(),
        relation: "causes".into(),
        strength: 0.5,
        evidence,
        source_agent: None,
    }
}

fn get_events(storage: &StorageEngine, memory_id: &str) -> Vec<event_ops::RawEvent> {
    storage
        .pool()
        .writer
        .with_conn_sync(|conn| event_ops::get_events_for_memory(conn, memory_id, None))
        .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-01: add_edge with evidence persists atomically
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_01_add_edge_with_evidence_atomic() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let edge = make_edge_with_evidence("A", "B", 2);
    storage.add_edge(&edge).unwrap();

    let edges = storage.get_edges("A").unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].evidence.len(), 2, "should have 2 evidence entries");

    // Verify temporal event.
    let events = get_events(&storage, "A");
    assert!(
        events.iter().any(|e| e.event_type == "relationship_added"),
        "should emit relationship_added event"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-03: add_edge INSERT OR REPLACE updates strength
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_03_add_edge_replace_updates_strength() {
    let storage = StorageEngine::open_in_memory().unwrap();

    storage.add_edge(&make_edge("A", "B", 0.5)).unwrap();
    storage.add_edge(&make_edge("A", "B", 0.9)).unwrap();

    let edges = storage.get_edges("A").unwrap();
    assert_eq!(edges.len(), 1, "should have 1 edge (replaced)");
    assert!(
        (edges[0].strength - 0.9).abs() < 1e-10,
        "strength should be 0.9, got {}",
        edges[0].strength
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-04: get_edges returns bidirectional
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_04_get_edges_bidirectional() {
    let storage = StorageEngine::open_in_memory().unwrap();

    storage.add_edge(&make_edge("A", "B", 0.5)).unwrap();
    storage.add_edge(&make_edge("C", "A", 0.7)).unwrap();

    let edges = storage.get_edges("A").unwrap();
    assert_eq!(edges.len(), 2, "should return both inbound and outbound edges");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-05: get_edges loads evidence for each edge
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_05_get_edges_loads_evidence() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let edge = make_edge_with_evidence("A", "B", 3);
    storage.add_edge(&edge).unwrap();

    let edges = storage.get_edges("A").unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].evidence.len(), 3, "should load 3 evidence entries");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-06: remove_edge emits event BEFORE deletion
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_06_remove_edge_emits_event() {
    let storage = StorageEngine::open_in_memory().unwrap();

    storage.add_edge(&make_edge("A", "B", 0.5)).unwrap();
    storage.remove_edge("A", "B").unwrap();

    // Edge should be gone.
    let edges = storage.get_edges("A").unwrap();
    assert!(edges.is_empty());

    // Event should exist.
    let events = get_events(&storage, "A");
    assert!(
        events
            .iter()
            .any(|e| e.event_type == "relationship_removed"),
        "should have relationship_removed event"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-07: remove_edge cascades evidence
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_07_remove_edge_cascades_evidence() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let edge = make_edge_with_evidence("A", "B", 3);
    storage.add_edge(&edge).unwrap();
    storage.remove_edge("A", "B").unwrap();

    // Verify no orphaned evidence.
    let count: i64 = storage
        .pool()
        .writer
        .with_conn_sync(|conn| {
            Ok(conn
                .query_row(
                    "SELECT COUNT(*) FROM causal_evidence WHERE source_id = 'A' AND target_id = 'B'",
                    [],
                    |row| row.get(0),
                )
                .unwrap())
        })
        .unwrap();
    assert_eq!(count, 0, "evidence should be cascade-deleted");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-08: update_strength emits temporal event
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_08_update_strength_emits_event() {
    let storage = StorageEngine::open_in_memory().unwrap();

    storage.add_edge(&make_edge("A", "B", 0.5)).unwrap();
    storage.update_strength("A", "B", 0.9).unwrap();

    let events = get_events(&storage, "A");
    let strength_event = events
        .iter()
        .find(|e| e.event_type == "strength_updated");
    assert!(strength_event.is_some(), "should emit strength_updated");

    let delta: serde_json::Value =
        serde_json::from_str(&strength_event.unwrap().delta).unwrap();
    assert_eq!(delta["new_strength"], 0.9);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-09: has_cycle detects A→B→C→A
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_09_has_cycle_detects_cycle() {
    let storage = StorageEngine::open_in_memory().unwrap();

    storage.add_edge(&make_edge("A", "B", 0.5)).unwrap();
    storage.add_edge(&make_edge("B", "C", 0.5)).unwrap();

    // Adding C→A would create a cycle.
    let has_cycle = storage.has_cycle("C", "A").unwrap();
    assert!(has_cycle, "should detect cycle A→B→C→A");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-10: has_cycle returns false for DAG
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_10_has_cycle_false_for_dag() {
    let storage = StorageEngine::open_in_memory().unwrap();

    storage.add_edge(&make_edge("A", "B", 0.5)).unwrap();
    storage.add_edge(&make_edge("A", "C", 0.5)).unwrap();
    storage.add_edge(&make_edge("B", "D", 0.5)).unwrap();

    // A→D is not a cycle.
    let has_cycle = storage.has_cycle("A", "D").unwrap();
    assert!(!has_cycle, "should NOT detect cycle in DAG");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-11: edge_count and node_count accurate
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_11_edge_and_node_count() {
    let storage = StorageEngine::open_in_memory().unwrap();

    storage.add_edge(&make_edge("A", "B", 0.5)).unwrap();
    storage.add_edge(&make_edge("B", "C", 0.5)).unwrap();
    storage.add_edge(&make_edge("A", "C", 0.5)).unwrap();
    storage.add_edge(&make_edge("D", "A", 0.5)).unwrap();
    storage.add_edge(&make_edge("D", "C", 0.5)).unwrap();

    assert_eq!(storage.edge_count().unwrap(), 5);
    assert_eq!(storage.node_count().unwrap(), 4); // A, B, C, D
}

// ═══════════════════════════════════════════════════════════════════════════════
// CG-12: remove_orphaned_edges cleans dangling references
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cg_12_remove_orphaned_edges() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Create memories for "mem-a" and "mem-b".
    storage.create(&make_memory("mem-a")).unwrap();
    storage.create(&make_memory("mem-b")).unwrap();

    // Add edges — "mem-a"→"mem-b" (valid) and "orphan-x"→"mem-a" (orphan).
    storage.add_edge(&make_edge("mem-a", "mem-b", 0.5)).unwrap();
    storage
        .add_edge(&make_edge("orphan-x", "mem-a", 0.5))
        .unwrap();

    assert_eq!(storage.edge_count().unwrap(), 2);

    let removed = storage.remove_orphaned_edges().unwrap();
    assert_eq!(removed, 1, "should remove 1 orphaned edge");
    assert_eq!(storage.edge_count().unwrap(), 1);
}

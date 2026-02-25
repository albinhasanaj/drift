//! Integration test: causal storage operations.

use cortex_core::traits::{CausalEdge, CausalEvidence, ICausalStorage};
use cortex_storage::StorageEngine;

fn make_edge(src: &str, tgt: &str) -> CausalEdge {
    CausalEdge {
        source_id: src.to_string(),
        target_id: tgt.to_string(),
        relation: "causes".to_string(),
        strength: 0.8,
        evidence: vec![CausalEvidence {
            description: "test evidence".to_string(),
            source: "test".to_string(),
            timestamp: chrono::Utc::now(),
        }],
        source_agent: None,
    }
}

#[test]
fn test_causal_edge_crud() {
    let engine = StorageEngine::open_in_memory().unwrap();

    engine.add_edge(&make_edge("a", "b")).unwrap();

    let edges = engine.get_edges("a").unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].relation, "causes");
    assert!((edges[0].strength - 0.8).abs() < 0.01);
    assert_eq!(edges[0].evidence.len(), 1);

    engine.update_strength("a", "b", 0.5).unwrap();
    let edges = engine.get_edges("a").unwrap();
    assert!((edges[0].strength - 0.5).abs() < 0.01);

    engine.remove_edge("a", "b").unwrap();
    let edges = engine.get_edges("a").unwrap();
    assert!(edges.is_empty());
}

#[test]
fn test_causal_cycle_detection() {
    let engine = StorageEngine::open_in_memory().unwrap();

    engine.add_edge(&make_edge("x", "y")).unwrap();
    engine.add_edge(&make_edge("y", "z")).unwrap();

    // z -> x would create a cycle.
    let has_cycle = engine.has_cycle("z", "x").unwrap();
    assert!(has_cycle, "should detect cycle z->x->y->z");

    // x -> z would not create a cycle.
    let has_cycle = engine.has_cycle("x", "z").unwrap();
    assert!(!has_cycle, "x->z should not create a cycle");
}

#[test]
fn test_causal_statistics() {
    let engine = StorageEngine::open_in_memory().unwrap();

    engine.add_edge(&make_edge("n1", "n2")).unwrap();
    engine.add_edge(&make_edge("n2", "n3")).unwrap();

    assert_eq!(engine.edge_count().unwrap(), 2);
    assert_eq!(engine.node_count().unwrap(), 3);
}

#[test]
fn test_add_evidence() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine.add_edge(&make_edge("ev1", "ev2")).unwrap();

    let new_evidence = CausalEvidence {
        description: "additional evidence".to_string(),
        source: "user".to_string(),
        timestamp: chrono::Utc::now(),
    };
    engine.add_evidence("ev1", "ev2", &new_evidence).unwrap();

    let edges = engine.get_edges("ev1").unwrap();
    assert_eq!(edges[0].evidence.len(), 2);
}

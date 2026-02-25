//! Storage stress tests: high-volume CRUD, bulk ops, queries, relationships,
//! causal storage, and edge cases.

use chrono::Utc;
use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::traits::{CausalEdge, CausalEvidence, ICausalStorage, IMemoryStorage};
use cortex_storage::StorageEngine;
use std::time::Instant;

fn make_memory(
    id: &str,
    mem_type: MemoryType,
    importance: Importance,
    tags: Vec<&str>,
) -> BaseMemory {
    let content = TypedContent::Tribal(TribalContent {
        knowledge: format!("Knowledge for {id}"),
        severity: "medium".to_string(),
        warnings: vec![],
        consequences: vec![],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: mem_type,
        content: content.clone(),
        summary: format!("Summary of {id}"),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: tags.into_iter().map(String::from).collect(),
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ── High-volume CRUD ─────────────────────────────────────────────────────

#[test]
fn stress_1000_individual_creates_and_gets() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let start = Instant::now();

    for i in 0..1000 {
        let mem = make_memory(
            &format!("mem-{i:04}"),
            MemoryType::Episodic,
            Importance::Normal,
            vec!["stress"],
        );
        engine.create(&mem).unwrap();
    }

    let create_elapsed = start.elapsed();
    assert!(
        create_elapsed.as_secs() < 10,
        "1000 creates took {:?}",
        create_elapsed
    );

    // Verify random reads.
    for id in ["mem-0000", "mem-0500", "mem-0999"] {
        let retrieved = engine.get(id).unwrap();
        assert!(retrieved.is_some(), "Memory {id} should exist");
        assert_eq!(retrieved.unwrap().id, id);
    }
}

#[test]
fn stress_bulk_create_1000() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let memories: Vec<BaseMemory> = (0..1000)
        .map(|i| {
            make_memory(
                &format!("bulk-{i:04}"),
                MemoryType::Tribal,
                if i % 10 == 0 {
                    Importance::Critical
                } else {
                    Importance::Normal
                },
                vec!["bulk", if i % 2 == 0 { "even" } else { "odd" }],
            )
        })
        .collect();

    let start = Instant::now();
    let count = engine.create_bulk(&memories).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(count, 1000);
    assert!(
        elapsed.as_secs() < 5,
        "Bulk create of 1000 took {:?}",
        elapsed
    );

    // Verify bulk get.
    let ids: Vec<String> = (0..100).map(|i| format!("bulk-{i:04}")).collect();
    let retrieved = engine.get_bulk(&ids).unwrap();
    assert_eq!(retrieved.len(), 100);
}

// ── Query stress ─────────────────────────────────────────────────────────

#[test]
fn stress_query_by_type_across_many_types() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let types = [
        MemoryType::Core,
        MemoryType::Tribal,
        MemoryType::Episodic,
        MemoryType::Semantic,
        MemoryType::Decision,
    ];

    for (i, &mt) in types.iter().enumerate() {
        for j in 0..200 {
            let mem = make_memory(&format!("qt-{i}-{j}"), mt, Importance::Normal, vec![]);
            engine.create(&mem).unwrap();
        }
    }

    for &mt in &types {
        let results = engine.query_by_type(mt).unwrap();
        assert_eq!(results.len(), 200, "Expected 200 memories of type {:?}", mt);
    }
}

#[test]
fn stress_query_by_importance() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let importances = [
        Importance::Low,
        Importance::Normal,
        Importance::High,
        Importance::Critical,
    ];

    for (i, &imp) in importances.iter().enumerate() {
        for j in 0..100 {
            let mem = make_memory(&format!("qi-{i}-{j}"), MemoryType::Tribal, imp, vec![]);
            engine.create(&mem).unwrap();
        }
    }

    // Query for High+ should return High + Critical = 200.
    let high_plus = engine.query_by_importance(Importance::High).unwrap();
    assert!(
        high_plus.len() >= 200,
        "Expected >= 200 High+ memories, got {}",
        high_plus.len()
    );

    // Query for Critical should return exactly 100.
    let critical = engine.query_by_importance(Importance::Critical).unwrap();
    assert_eq!(critical.len(), 100);
}

#[test]
fn stress_query_by_tags() {
    let engine = StorageEngine::open_in_memory().unwrap();

    for i in 0..500 {
        let tags = if i % 3 == 0 {
            vec!["rust", "systems"]
        } else if i % 3 == 1 {
            vec!["python", "ml"]
        } else {
            vec!["rust", "ml"]
        };
        let mem = make_memory(
            &format!("tag-{i}"),
            MemoryType::Tribal,
            Importance::Normal,
            tags,
        );
        engine.create(&mem).unwrap();
    }

    let rust_mems = engine.query_by_tags(&["rust".to_string()]).unwrap();
    // i%3==0 (167) + i%3==2 (166) = 333
    assert!(
        rust_mems.len() >= 300,
        "Expected ~333 rust-tagged memories, got {}",
        rust_mems.len()
    );
}

// ── FTS5 search stress ───────────────────────────────────────────────────

#[test]
fn stress_fts5_search_1000_memories() {
    let engine = StorageEngine::open_in_memory().unwrap();

    let topics = [
        "database optimization",
        "memory safety",
        "async runtime",
        "error handling",
        "testing patterns",
    ];
    for i in 0..1000 {
        let topic = topics[i % topics.len()];
        let mut mem = make_memory(
            &format!("fts-{i:04}"),
            MemoryType::Tribal,
            Importance::Normal,
            vec![],
        );
        mem.summary = format!("{topic} technique number {i}");
        engine.create(&mem).unwrap();
    }

    let start = Instant::now();
    let results = engine.search_fts5("memory safety", 50).unwrap();
    let elapsed = start.elapsed();

    assert!(
        !results.is_empty(),
        "FTS5 should find results for 'memory safety'"
    );
    assert!(elapsed.as_millis() < 1000, "FTS5 search took {:?}", elapsed);
}

// ── Relationship stress ──────────────────────────────────────────────────

#[test]
fn stress_500_relationships() {
    let engine = StorageEngine::open_in_memory().unwrap();

    // Create 100 memories.
    for i in 0..100 {
        let mem = make_memory(
            &format!("rel-{i:02}"),
            MemoryType::Tribal,
            Importance::Normal,
            vec![],
        );
        engine.create(&mem).unwrap();
    }

    // Create 500 relationships (each memory connects to 5 others).
    for i in 0..100 {
        for j in 1..=5 {
            let target = (i + j * 7) % 100;
            if target != i {
                let edge = RelationshipEdge {
                    source_id: format!("rel-{i:02}"),
                    target_id: format!("rel-{target:02}"),
                    relationship_type: RelationshipType::Related,
                    strength: 0.8,
                    evidence: vec!["stress test".to_string()],
                    cross_agent_relation: None,
                };
                let _ = engine.add_relationship(&edge);
            }
        }
    }

    // Verify we can query relationships.
    let rels = engine.get_relationships("rel-00", None).unwrap();
    assert!(!rels.is_empty(), "rel-00 should have relationships");
}

// ── Causal storage stress ────────────────────────────────────────────────

#[test]
fn stress_causal_500_edges() {
    let engine = StorageEngine::open_in_memory().unwrap();

    // Create memories first.
    for i in 0..100 {
        let mem = make_memory(
            &format!("causal-{i:02}"),
            MemoryType::Tribal,
            Importance::Normal,
            vec![],
        );
        engine.create(&mem).unwrap();
    }

    // Add 500 causal edges.
    let start = Instant::now();
    for i in 0..500 {
        let source = i % 100;
        let target = (i * 7 + 3) % 100;
        if source != target {
            let edge = CausalEdge {
                source_id: format!("causal-{source:02}"),
                target_id: format!("causal-{target:02}"),
                relation: "caused".to_string(),
                strength: 0.5 + (i % 5) as f64 * 0.1,
                evidence: vec![CausalEvidence {
                    description: format!("Evidence {i}"),
                    source: "stress_test".to_string(),
                    timestamp: Utc::now(),
                }],
                source_agent: None,
            };
            let _ = engine.add_edge(&edge);
        }
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 10,
        "500 causal edges took {:?}",
        elapsed
    );

    // Verify edge retrieval.
    let edges = engine.get_edges("causal-00").unwrap();
    assert!(!edges.is_empty(), "causal-00 should have edges");

    // Verify counts.
    let edge_count = engine.edge_count().unwrap();
    assert!(edge_count > 0, "Should have causal edges");
}

// ── Aggregation stress ───────────────────────────────────────────────────

#[test]
fn stress_aggregation_queries() {
    let engine = StorageEngine::open_in_memory().unwrap();

    for i in 0..500 {
        let mut mem = make_memory(
            &format!("agg-{i:03}"),
            if i % 2 == 0 {
                MemoryType::Tribal
            } else {
                MemoryType::Episodic
            },
            Importance::Normal,
            vec![],
        );
        mem.confidence = Confidence::new(0.5 + (i % 50) as f64 * 0.01);
        engine.create(&mem).unwrap();
    }

    let counts = engine.count_by_type().unwrap();
    let total: usize = counts.iter().map(|(_, c)| c).sum();
    assert_eq!(total, 500);

    let avg_conf = engine.average_confidence().unwrap();
    assert!(
        avg_conf > 0.0 && avg_conf <= 1.0,
        "Average confidence should be in (0,1], got {}",
        avg_conf
    );
}

// ── Edge cases ───────────────────────────────────────────────────────────

#[test]
fn stress_get_nonexistent_returns_none() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let result = engine.get("does-not-exist").unwrap();
    assert!(result.is_none());
}

#[test]
fn stress_delete_and_verify_gone() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("to-delete", MemoryType::Tribal, Importance::Normal, vec![]);
    engine.create(&mem).unwrap();
    assert!(engine.get("to-delete").unwrap().is_some());

    engine.delete("to-delete").unwrap();
    assert!(engine.get("to-delete").unwrap().is_none());
}

#[test]
fn stress_update_preserves_changes() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory(
        "to-update",
        MemoryType::Tribal,
        Importance::Normal,
        vec!["original"],
    );
    engine.create(&mem).unwrap();

    mem.importance = Importance::Critical;
    mem.tags = vec!["updated".to_string()];
    mem.confidence = Confidence::new(0.99);
    engine.update(&mem).unwrap();

    let retrieved = engine.get("to-update").unwrap().unwrap();
    assert_eq!(retrieved.importance, Importance::Critical);
    assert_eq!(retrieved.tags, vec!["updated"]);
    assert!(retrieved.confidence.value() > 0.98);
}

#[test]
fn stress_confidence_range_query() {
    let engine = StorageEngine::open_in_memory().unwrap();

    for i in 0..100 {
        let mut mem = make_memory(
            &format!("conf-{i:02}"),
            MemoryType::Tribal,
            Importance::Normal,
            vec![],
        );
        mem.confidence = Confidence::new(i as f64 / 100.0);
        engine.create(&mem).unwrap();
    }

    // Query for confidence 0.5-0.8 should return ~30 memories.
    let results = engine.query_by_confidence_range(0.5, 0.8).unwrap();
    assert!(
        results.len() >= 25 && results.len() <= 35,
        "Expected ~30 memories in [0.5, 0.8], got {}",
        results.len()
    );
}

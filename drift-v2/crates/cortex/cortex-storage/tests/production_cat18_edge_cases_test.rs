//! Cat 18: Edge Cases & Adversarial (EC-01 through EC-14)
//!
//! Tests SQL injection, Unicode, empty strings, huge content,
//! max u64, NaN embeddings, concurrent stress, NULL fields,
//! special characters in tags, very long IDs, and boundary dates.

use chrono::Utc;

use cortex_core::memory::*;
use cortex_core::traits::{CausalEdge, ICausalStorage, IMemoryStorage};
use cortex_storage::StorageEngine;

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

// ═══════════════════════════════════════════════════════════════════════════════
// EC-01: SQL injection in memory ID
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_01_sql_injection_memory_id() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("'; DROP TABLE memories; --");
    storage.create(&mem).unwrap();

    // Table should still exist and the memory should be retrievable.
    let got = storage.get("'; DROP TABLE memories; --").unwrap();
    assert!(got.is_some(), "SQL injection in ID should be parameterized");

    // Verify table still works.
    let mem2 = make_memory("normal-after-injection");
    storage.create(&mem2).unwrap();
    assert!(storage.get("normal-after-injection").unwrap().is_some());
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-02: SQL injection in summary
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_02_sql_injection_summary() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("ec02");
    mem.summary = "'; DROP TABLE memories; --".to_string();
    storage.create(&mem).unwrap();

    let got = storage.get("ec02").unwrap().unwrap();
    assert_eq!(got.summary, "'; DROP TABLE memories; --");
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-03: Unicode in all text fields
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_03_unicode_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("ec03-日本語");
    mem.summary = "概要：テストメモリ 🧠".to_string();
    mem.tags = vec!["тег".to_string(), "标签".to_string(), "🏷️".to_string()];
    storage.create(&mem).unwrap();

    let got = storage.get("ec03-日本語").unwrap().unwrap();
    assert_eq!(got.summary, "概要：テストメモリ 🧠");
    assert_eq!(got.tags, vec!["тег", "标签", "🏷️"]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-04: Empty string fields
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_04_empty_string_fields() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("ec04");
    mem.summary = "".to_string();
    mem.tags = vec![];
    storage.create(&mem).unwrap();

    let got = storage.get("ec04").unwrap().unwrap();
    assert_eq!(got.summary, "");
    assert!(got.tags.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-05: Very large content
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_05_large_content() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let large_text = "x".repeat(100_000);
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: large_text.clone(),
        evidence: vec![],
    });
    let mut mem = make_memory("ec05");
    mem.content = tc.clone();
    mem.content_hash = BaseMemory::compute_content_hash(&tc).unwrap();
    storage.create(&mem).unwrap();

    let got = storage.get("ec05").unwrap().unwrap();
    if let TypedContent::Insight(ref c) = got.content {
        assert_eq!(c.observation.len(), 100_000);
    } else {
        panic!("wrong content type");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-06: NaN embedding doesn't infect search results
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_06_nan_embedding_no_infection() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem_good = make_memory("ec06-good");
    let mem_nan = make_memory("ec06-nan");
    storage.create(&mem_good).unwrap();
    storage.create(&mem_nan).unwrap();

    // Store a good embedding.
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::vector_search::store_embedding(
            conn, "ec06-good", "hg", &[1.0, 0.0, 0.0], "model",
        )
    }).unwrap();

    // Store a NaN-containing embedding.
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::vector_search::store_embedding(
            conn, "ec06-nan", "hn", &[f32::NAN, 0.0, 0.0], "model",
        )
    }).unwrap();

    // Search should return good result without NaN infection.
    let results = storage.search_vector(&[1.0, 0.0, 0.0], 10).unwrap();
    for (mem, sim) in &results {
        assert!(sim.is_finite(), "similarity should be finite, not NaN/Inf. mem={}", mem.id);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-07: Concurrent bulk operations
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_07_concurrent_bulk_operations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ec07.db");
    let storage = std::sync::Arc::new(StorageEngine::open(&path).unwrap());

    let handles: Vec<_> = (0..4)
        .map(|batch| {
            let s = std::sync::Arc::clone(&storage);
            std::thread::spawn(move || {
                for i in 0..25 {
                    let mem = make_memory(&format!("ec07-b{batch}-{i}"));
                    s.create(&mem).unwrap();
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    // Verify all 100 memories exist.
    for batch in 0..4 {
        for i in 0..25 {
            let got = storage.get(&format!("ec07-b{batch}-{i}")).unwrap();
            assert!(got.is_some(), "ec07-b{batch}-{i} should exist");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-08: NULL optional fields roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_08_null_optional_fields() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("ec08");
    mem.valid_until = None;
    mem.superseded_by = None;
    mem.supersedes = None;
    storage.create(&mem).unwrap();

    let got = storage.get("ec08").unwrap().unwrap();
    assert!(got.valid_until.is_none());
    assert!(got.superseded_by.is_none());
    assert!(got.supersedes.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-09: Special characters in tags
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_09_special_chars_in_tags() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("ec09");
    mem.tags = vec![
        "tag with spaces".into(),
        "tag-with-dashes".into(),
        "tag_with_underscores".into(),
        "tag/with/slashes".into(),
        "tag\"with\"quotes".into(),
        "tag\\with\\backslashes".into(),
    ];
    storage.create(&mem).unwrap();

    let got = storage.get("ec09").unwrap().unwrap();
    assert_eq!(got.tags.len(), 6);
    assert_eq!(got.tags[0], "tag with spaces");
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-10: Very long memory ID
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_10_very_long_id() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let long_id = "x".repeat(1000);
    let mem = make_memory(&long_id);
    storage.create(&mem).unwrap();

    let got = storage.get(&long_id).unwrap();
    assert!(got.is_some(), "1000-char ID should roundtrip");
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-11: Causal edge with SQL injection in node IDs
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_11_causal_sql_injection() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let edge = CausalEdge {
        source_id: "'; DROP TABLE causal_edges; --".into(),
        target_id: "target".into(),
        relation: "causes".into(),
        strength: 0.5,
        evidence: vec![],
        source_agent: None,
    };
    storage.add_edge(&edge).unwrap();

    let edges = storage.get_edges("'; DROP TABLE causal_edges; --").unwrap();
    assert_eq!(edges.len(), 1, "SQL injection in edge ID should be parameterized");

    // Table should still work.
    assert_eq!(storage.edge_count().unwrap(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-12: Zero-length embedding stored and skipped in search
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_12_zero_length_embedding() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("ec12");
    storage.create(&mem).unwrap();

    // Store zero-length embedding.
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::vector_search::store_embedding(
            conn, "ec12", "h12", &[], "model",
        )
    }).unwrap();

    // Search with 3D query — should not return ec12 (dimension mismatch).
    let results = storage.search_vector(&[1.0, 0.0, 0.0], 10).unwrap();
    assert!(
        !results.iter().any(|(m, _)| m.id == "ec12"),
        "zero-dim embedding should be skipped"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-13: Rapid create-delete-create with same ID
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_13_create_delete_create_same_id() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("ec13");
    storage.create(&mem).unwrap();
    storage.delete("ec13").unwrap();

    // Re-create with same ID.
    let mut mem2 = make_memory("ec13");
    mem2.summary = "recreated".into();
    storage.create(&mem2).unwrap();

    let got = storage.get("ec13").unwrap().unwrap();
    assert_eq!(got.summary, "recreated");
}

// ═══════════════════════════════════════════════════════════════════════════════
// EC-14: Many tags (100+) roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ec_14_many_tags() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("ec14");
    mem.tags = (0..200).map(|i| format!("tag-{i}")).collect();
    storage.create(&mem).unwrap();

    let got = storage.get("ec14").unwrap().unwrap();
    assert_eq!(got.tags.len(), 200, "200 tags should roundtrip");
}

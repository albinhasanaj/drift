//! Cat 5: Query Module Correctness (QM-01 through QM-12)
//!
//! Tests query_by_type, importance, confidence_range, date_range, tags,
//! count_by_type, average_confidence, stale_count, storage_stats.

use chrono::{Duration, Utc};

use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

// ─── Fixtures ────────────────────────────────────────────────────────────────

fn make_memory_typed(id: &str, mtype: MemoryType, conf: f64, importance: Importance) -> BaseMemory {
    let now = Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: format!("obs {id}"),
        evidence: vec![],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: mtype,
        content: tc.clone(),
        summary: format!("summary {id}"),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(conf),
        importance,
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

fn make_memory(id: &str) -> BaseMemory {
    make_memory_typed(id, MemoryType::Insight, 0.8, Importance::Normal)
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-01: query_by_type excludes archived memories
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_01_query_by_type_excludes_archived() {
    let storage = StorageEngine::open_in_memory().unwrap();

    for i in 0..3 {
        let mut mem = make_memory_typed(&format!("qm01-{i}"), MemoryType::Core, 0.8, Importance::Normal);
        mem.memory_type = MemoryType::Core;
        if i == 2 {
            mem.archived = true;
        }
        storage.create(&mem).unwrap();
    }

    let results = storage.query_by_type(MemoryType::Core).unwrap();
    assert_eq!(results.len(), 2, "should exclude 1 archived Core memory");
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-02: query_by_type with namespace filter
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_02_query_by_type_namespace_filter() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let ns1 = cortex_core::models::namespace::NamespaceId {
        scope: cortex_core::models::namespace::NamespaceScope::Agent(
            cortex_core::models::agent::AgentId::from("bot1"),
        ),
        name: "ns1".into(),
    };
    let ns2 = cortex_core::models::namespace::NamespaceId {
        scope: cortex_core::models::namespace::NamespaceScope::Agent(
            cortex_core::models::agent::AgentId::from("bot2"),
        ),
        name: "ns2".into(),
    };

    for i in 0..3 {
        let mut mem = make_memory(&format!("qm02-ns1-{i}"));
        mem.memory_type = MemoryType::Core;
        mem.namespace = ns1.clone();
        storage.create(&mem).unwrap();
    }
    for i in 0..2 {
        let mut mem = make_memory(&format!("qm02-ns2-{i}"));
        mem.memory_type = MemoryType::Core;
        mem.namespace = ns2.clone();
        storage.create(&mem).unwrap();
    }

    // Query with ns1 filter via raw query.
    let results = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::memory_query::query_by_type(conn, MemoryType::Core, Some(&ns1))
    }).unwrap();
    assert_eq!(results.len(), 3, "should only return ns1 memories");
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-03: query_by_importance — Low returns all 4 tiers
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_03_query_by_importance_low_returns_all() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let levels = [Importance::Low, Importance::Normal, Importance::High, Importance::Critical];
    for (i, imp) in levels.iter().enumerate() {
        let mut mem = make_memory(&format!("qm03-{i}"));
        mem.importance = imp.clone();
        storage.create(&mem).unwrap();
    }

    let results = storage.query_by_importance(Importance::Low).unwrap();
    assert_eq!(results.len(), 4, "Low should return all 4 tiers");
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-04: query_by_confidence_range — boundary inclusive
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_04_confidence_range_boundary_inclusive() {
    let storage = StorageEngine::open_in_memory().unwrap();

    for (i, conf) in [0.0, 0.5, 0.8, 1.0].iter().enumerate() {
        let mut mem = make_memory(&format!("qm04-{i}"));
        mem.confidence = Confidence::new(*conf);
        storage.create(&mem).unwrap();
    }

    let results = storage.query_by_confidence_range(0.5, 0.8).unwrap();
    assert_eq!(results.len(), 2, "should include 0.5 and 0.8 (inclusive)");
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-05: query_by_date_range uses transaction_time
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_05_date_range_uses_transaction_time() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let jan1 = Utc::now() - Duration::days(30);
    let dec1 = Utc::now() + Duration::days(300);

    let mut mem = make_memory("qm05");
    mem.transaction_time = jan1;
    mem.valid_time = dec1;
    storage.create(&mem).unwrap();

    // Query Dec range — should NOT find it (transaction_time is Jan).
    let results = storage.query_by_date_range(dec1, dec1 + Duration::days(30)).unwrap();
    assert!(results.is_empty(), "should not find memory by valid_time date range");

    // Query Jan range — should find it.
    let results = storage.query_by_date_range(jan1 - Duration::hours(1), jan1 + Duration::hours(1)).unwrap();
    assert_eq!(results.len(), 1, "should find memory by transaction_time");
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-06: query_by_tags — OR semantics (any match)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_06_query_by_tags_or_semantics() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem_a = make_memory("qm06-a");
    mem_a.tags = vec!["rust".into(), "web".into()];
    storage.create(&mem_a).unwrap();

    let mut mem_b = make_memory("qm06-b");
    mem_b.tags = vec!["python".into()];
    storage.create(&mem_b).unwrap();

    let results = storage.query_by_tags(&["rust".into(), "python".into()]).unwrap();
    assert_eq!(results.len(), 2, "OR semantics should return both");
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-07: query_by_tags — deduplication
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_07_query_by_tags_dedup() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("qm07");
    mem.tags = vec!["rust".into(), "web".into()];
    storage.create(&mem).unwrap();

    let results = storage.query_by_tags(&["rust".into(), "web".into()]).unwrap();
    assert_eq!(results.len(), 1, "should deduplicate — 1 memory, not 2");
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-08: count_by_type excludes archived
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_08_count_by_type_excludes_archived() {
    let storage = StorageEngine::open_in_memory().unwrap();

    for i in 0..5 {
        let mut mem = make_memory(&format!("qm08-core-{i}"));
        mem.memory_type = MemoryType::Core;
        if i >= 3 {
            mem.archived = true;
        }
        storage.create(&mem).unwrap();
    }
    for i in 0..3 {
        let mut mem = make_memory(&format!("qm08-sem-{i}"));
        mem.memory_type = MemoryType::Semantic;
        storage.create(&mem).unwrap();
    }

    let counts = storage.count_by_type().unwrap();
    let core_count = counts.iter().find(|(t, _)| *t == MemoryType::Core).map(|(_, c)| *c).unwrap_or(0);
    let sem_count = counts.iter().find(|(t, _)| *t == MemoryType::Semantic).map(|(_, c)| *c).unwrap_or(0);

    assert_eq!(core_count, 3, "Core count should exclude 2 archived");
    assert_eq!(sem_count, 3);
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-09: average_confidence handles empty DB
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_09_average_confidence_empty_db() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let avg = storage.average_confidence().unwrap();
    assert!((avg - 0.0).abs() < 1e-10, "empty DB should have avg confidence 0.0");
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-10: stale_count uses julianday correctly
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_10_stale_count_julianday() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Create a memory accessed now.
    let mem = make_memory("qm10-fresh");
    storage.create(&mem).unwrap();

    // Create a memory with old last_accessed (via raw SQL).
    let mut mem_old = make_memory("qm10-stale");
    mem_old.last_accessed = Utc::now() - Duration::days(60);
    storage.create(&mem_old).unwrap();

    let stale = storage.stale_count(30).unwrap();
    assert_eq!(stale, 1, "should have 1 stale memory (>30 days)");
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-11: storage_stats counts all entity types
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_11_storage_stats() {
    let storage = StorageEngine::open_in_memory().unwrap();

    for i in 0..3 {
        let mut mem = make_memory(&format!("qm11-{i}"));
        if i == 2 {
            mem.archived = true;
        }
        storage.create(&mem).unwrap();
    }

    let stats = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::aggregation::storage_stats(conn)
    }).unwrap();

    assert_eq!(stats.total_memories, 3);
    assert_eq!(stats.active_memories, 2);
    assert_eq!(stats.archived_memories, 1);
}

// ═══════════════════════════════════════════════════════════════════════════════
// QM-12: All query functions load links
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn qm_12_get_and_get_bulk_load_links() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("qm12");
    mem.memory_type = MemoryType::Core;
    mem.linked_patterns = vec![PatternLink { pattern_id: "p1".into(), pattern_name: "pat1".into() }];
    mem.linked_files = vec![FileLink { file_path: "/a.rs".into(), line_start: None, line_end: None, content_hash: None }];
    storage.create(&mem).unwrap();

    // get() loads links.
    let got = storage.get("qm12").unwrap().unwrap();
    assert!(!got.linked_patterns.is_empty(), "get() should load patterns");
    assert!(!got.linked_files.is_empty(), "get() should load files");

    // get_bulk() loads links.
    let bulk = storage.get_bulk(&["qm12".into()]).unwrap();
    assert_eq!(bulk.len(), 1);
    assert!(!bulk[0].linked_patterns.is_empty(), "get_bulk() should load patterns");
    assert!(!bulk[0].linked_files.is_empty(), "get_bulk() should load files");
}

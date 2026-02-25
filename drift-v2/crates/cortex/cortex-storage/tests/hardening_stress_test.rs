//! Enterprise stress tests for Cortex Storage hardening fixes.
//!
//! Covers:
//! - P2-11/E-04: Atomic link remove operations — no read-modify-write race.
//! - P2-15/D-03: Content hash change detection for re-embedding trigger.
//!
//! Every test targets a specific production failure mode.

use chrono::Utc;
use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

fn make_memory(id: &str) -> BaseMemory {
    let now = Utc::now();
    let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: format!("observation for {id}"),
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
// P2-11/E-04: ATOMIC LINK OPS — remove without read-modify-write
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: The TS link/unlink tools did read→modify→write which is racy.
/// The new atomic remove_*_link SQL ops use direct DELETE statements.
/// Verify add + remove roundtrip works.
#[test]
fn hst_e04_01_add_then_remove_pattern_link() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("link-pat-01");
    storage.create(&mem).unwrap();

    let link = PatternLink {
        pattern_id: "pat-001".to_string(),
        pattern_name: "singleton".to_string(),
    };

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::add_pattern_link(conn, &mem.id, &link)
    }).unwrap();

    // Verify link exists.
    let fetched = storage.get(&mem.id).unwrap().unwrap();
    assert!(fetched.linked_patterns.iter().any(|p| p.pattern_id == "pat-001"));

    // Remove atomically.
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_pattern_link(conn, &mem.id, "pat-001")
    }).unwrap();

    // Verify link removed.
    let fetched = storage.get(&mem.id).unwrap().unwrap();
    assert!(!fetched.linked_patterns.iter().any(|p| p.pattern_id == "pat-001"));
}

/// Remove a nonexistent link — must not error (idempotent delete).
#[test]
fn hst_e04_02_remove_nonexistent_link_no_error() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("link-noexist-01");
    storage.create(&mem).unwrap();

    // Remove a link that was never added.
    let result = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_pattern_link(conn, &mem.id, "nonexistent-pattern")
    });
    assert!(result.is_ok(), "Removing nonexistent link should succeed");
}

/// Double-remove — idempotent, second remove is a no-op.
#[test]
fn hst_e04_03_double_remove_idempotent() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("link-double-01");
    storage.create(&mem).unwrap();

    let link = PatternLink {
        pattern_id: "pat-dbl".to_string(),
        pattern_name: "test".to_string(),
    };

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::add_pattern_link(conn, &mem.id, &link)
    }).unwrap();

    // First remove.
    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_pattern_link(conn, &mem.id, "pat-dbl")
    }).unwrap();

    // Second remove — should be no-op.
    let result = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_pattern_link(conn, &mem.id, "pat-dbl")
    });
    assert!(result.is_ok());
}

/// Add + remove file link roundtrip.
#[test]
fn hst_e04_04_add_remove_file_link() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("link-file-01");
    storage.create(&mem).unwrap();

    let link = FileLink {
        file_path: "src/main.rs".to_string(),
        line_start: Some(1),
        line_end: Some(50),
        content_hash: Some("abc123".to_string()),
    };

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::add_file_link(conn, &mem.id, &link)
    }).unwrap();

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_file_link(conn, &mem.id, "src/main.rs")
    }).unwrap();

    let fetched = storage.get(&mem.id).unwrap().unwrap();
    assert!(fetched.linked_files.is_empty());
}

/// Add + remove constraint link roundtrip.
#[test]
fn hst_e04_05_add_remove_constraint_link() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("link-const-01");
    storage.create(&mem).unwrap();

    let link = ConstraintLink {
        constraint_id: "const-001".to_string(),
        constraint_name: "no-raw-sql".to_string(),
    };

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::add_constraint_link(conn, &mem.id, &link)
    }).unwrap();

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_constraint_link(conn, &mem.id, "const-001")
    }).unwrap();

    let fetched = storage.get(&mem.id).unwrap().unwrap();
    assert!(fetched.linked_constraints.is_empty());
}

/// Add + remove function link roundtrip.
#[test]
fn hst_e04_06_add_remove_function_link() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("link-func-01");
    storage.create(&mem).unwrap();

    let link = FunctionLink {
        function_name: "process_payment".to_string(),
        file_path: "src/payments.rs".to_string(),
        signature: Some("fn process_payment(amount: f64) -> Result<()>".to_string()),
    };

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::add_function_link(conn, &mem.id, &link)
    }).unwrap();

    storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_function_link(conn, &mem.id, "process_payment")
    }).unwrap();

    let fetched = storage.get(&mem.id).unwrap().unwrap();
    assert!(fetched.linked_functions.is_empty());
}

/// Stress: add 100 pattern links, remove 50, verify 50 remain.
#[test]
fn hst_e04_07_stress_100_add_50_remove() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory("link-stress-01");
    storage.create(&mem).unwrap();

    // Add 100 links.
    for i in 0..100 {
        let link = PatternLink {
            pattern_id: format!("pat-{i:03}"),
            pattern_name: format!("pattern-{i}"),
        };
        storage.pool().writer.with_conn_sync(|conn| {
            cortex_storage::queries::link_ops::add_pattern_link(conn, &mem.id, &link)
        }).unwrap();
    }

    // Remove odd-numbered links (50 total).
    for i in (1..100).step_by(2) {
        storage.pool().writer.with_conn_sync(|conn| {
            cortex_storage::queries::link_ops::remove_pattern_link(conn, &mem.id, &format!("pat-{i:03}"))
        }).unwrap();
    }

    let fetched = storage.get(&mem.id).unwrap().unwrap();
    assert_eq!(fetched.linked_patterns.len(), 50, "Should have 50 remaining");
    // All remaining should have even IDs.
    for link in &fetched.linked_patterns {
        let num: usize = link.pattern_id.strip_prefix("pat-").unwrap().parse().unwrap();
        assert_eq!(num % 2, 0, "Remaining link {} should be even", link.pattern_id);
    }
}

/// Remove from nonexistent memory — must not error.
#[test]
fn hst_e04_08_remove_from_nonexistent_memory() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let result = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::link_ops::remove_pattern_link(conn, "nonexistent-mem", "pat-001")
    });
    assert!(result.is_ok(), "Remove from nonexistent memory should not error");
}

// ═══════════════════════════════════════════════════════════════════════════════
// P2-15/D-03: CONTENT HASH CHANGE DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: cortex_memory_update didn't regenerate embeddings when
/// content changed. Verify content_hash actually changes when content changes.
#[test]
fn hst_d03_01_content_hash_changes_with_content() {
    let content1 = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "first observation".to_string(),
        evidence: vec![],
    });
    let content2 = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "completely different observation".to_string(),
        evidence: vec![],
    });

    let hash1 = BaseMemory::compute_content_hash(&content1).unwrap();
    let hash2 = BaseMemory::compute_content_hash(&content2).unwrap();

    assert_ne!(hash1, hash2, "Different content must produce different hashes");
}

/// Same content → same hash (deterministic).
#[test]
fn hst_d03_02_same_content_same_hash() {
    let content = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "identical observation".to_string(),
        evidence: vec![],
    });

    let hash1 = BaseMemory::compute_content_hash(&content).unwrap();
    let hash2 = BaseMemory::compute_content_hash(&content).unwrap();

    assert_eq!(hash1, hash2, "Same content must produce same hash");
}

/// Update with changed content → can detect via hash comparison.
#[test]
fn hst_d03_03_update_detects_content_change() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("d03-detect-01");
    storage.create(&mem).unwrap();

    let old_hash = mem.content_hash.clone();

    // Change content.
    mem.content = TypedContent::Insight(cortex_core::memory::types::InsightContent {
        observation: "updated observation with new facts".to_string(),
        evidence: vec![],
    });
    mem.content_hash = BaseMemory::compute_content_hash(&mem.content).unwrap();

    assert_ne!(old_hash, mem.content_hash, "Hash should change");

    // Verify the stored version has the old hash.
    let stored = storage.get(&mem.id).unwrap().unwrap();
    assert_eq!(stored.content_hash, old_hash);

    // Update.
    storage.update(&mem).unwrap();

    // Verify stored version now has new hash.
    let updated = storage.get(&mem.id).unwrap().unwrap();
    assert_eq!(updated.content_hash, mem.content_hash);
}

/// Metadata-only update (confidence change) → hash stays the same.
#[test]
fn hst_d03_04_metadata_change_no_hash_change() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("d03-meta-01");
    storage.create(&mem).unwrap();

    let old_hash = mem.content_hash.clone();

    // Only change confidence — no content change.
    mem.confidence = Confidence::new(0.95);
    mem.summary = "updated summary only".to_string();

    // Hash should NOT change because content didn't change.
    assert_eq!(old_hash, mem.content_hash);

    storage.update(&mem).unwrap();
    let updated = storage.get(&mem.id).unwrap().unwrap();
    assert_eq!(updated.content_hash, old_hash, "Hash should not change for metadata-only update");
}

/// Stress: 200 content updates, each with different hash.
#[test]
fn hst_d03_05_stress_200_content_updates() {
    let storage = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory("d03-stress-01");
    storage.create(&mem).unwrap();

    let mut seen_hashes = std::collections::HashSet::new();
    seen_hashes.insert(mem.content_hash.clone());

    for i in 0..200 {
        let new_content = TypedContent::Insight(cortex_core::memory::types::InsightContent {
            observation: format!("updated observation number {i} with unique content {}", i * 31),
            evidence: vec![],
        });
        mem.content = new_content.clone();
        mem.content_hash = BaseMemory::compute_content_hash(&new_content).unwrap();

        assert!(
            seen_hashes.insert(mem.content_hash.clone()),
            "Hash collision at iteration {i}"
        );

        storage.update(&mem).unwrap();
        let stored = storage.get(&mem.id).unwrap().unwrap();
        assert_eq!(stored.content_hash, mem.content_hash);
    }

    assert_eq!(seen_hashes.len(), 201, "Should have 201 unique hashes (1 original + 200 updates)");
}

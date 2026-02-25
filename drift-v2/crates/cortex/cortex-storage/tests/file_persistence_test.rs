//! File-backed persistence tests: restart survival, WAL mode, integrity checks,
//! pragma verification, recovery operations.
//!
//! These tests use tempdir to create real file-backed databases and verify
//! data survives engine close + reopen cycles.

use chrono::Utc;
use cortex_core::memory::types::*;
use cortex_core::memory::*;
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
        linked_constraints: vec![],
        linked_files: vec![FileLink {
            file_path: format!("/src/{id}.rs"),
            line_start: Some(1),
            line_end: Some(10),
            content_hash: Some("hash123".to_string()),
        }],
        linked_functions: vec![],
        tags: vec!["persistent".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RESTART SURVIVAL: data persists across engine close + reopen
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn memory_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("survive.db");

    // Session 1: create data
    {
        let engine = StorageEngine::open(&db_path).unwrap();
        engine.create(&make_memory("persist-1")).unwrap();
        engine.create(&make_memory("persist-2")).unwrap();
        // Engine drops here, connections close
    }

    // Session 2: verify data survived
    {
        let engine = StorageEngine::open(&db_path).unwrap();
        let m1 = engine.get("persist-1").unwrap();
        assert!(m1.is_some(), "memory must survive restart");
        let m1 = m1.unwrap();
        assert_eq!(m1.summary, "Summary of persist-1");
        assert_eq!(m1.linked_patterns.len(), 1);
        assert_eq!(m1.linked_files.len(), 1);
        assert_eq!(m1.tags, vec!["persistent"]);

        let m2 = engine.get("persist-2").unwrap();
        assert!(m2.is_some(), "second memory must survive restart");
    }

    dir.close().unwrap();
}

#[test]
fn update_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("update-survive.db");

    // Session 1: create and update
    {
        let engine = StorageEngine::open(&db_path).unwrap();
        let mut mem = make_memory("upd-persist");
        engine.create(&mem).unwrap();
        mem.summary = "Updated summary".to_string();
        mem.confidence = Confidence::new(0.95);
        engine.update(&mem).unwrap();
    }

    // Session 2: verify updated state
    {
        let engine = StorageEngine::open(&db_path).unwrap();
        let loaded = engine.get("upd-persist").unwrap().unwrap();
        assert_eq!(loaded.summary, "Updated summary");
        assert!((loaded.confidence.value() - 0.95).abs() < f64::EPSILON);
    }

    dir.close().unwrap();
}

#[test]
fn delete_persists_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("delete-persist.db");

    // Session 1: create then delete
    {
        let engine = StorageEngine::open(&db_path).unwrap();
        engine.create(&make_memory("del-persist")).unwrap();
        engine.delete("del-persist").unwrap();
    }

    // Session 2: verify deleted
    {
        let engine = StorageEngine::open(&db_path).unwrap();
        assert!(
            engine.get("del-persist").unwrap().is_none(),
            "deleted memory must not resurrect"
        );
    }

    dir.close().unwrap();
}

#[test]
fn causal_edges_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("causal-persist.db");

    {
        let engine = StorageEngine::open(&db_path).unwrap();
        engine.create(&make_memory("cause-p")).unwrap();
        engine.create(&make_memory("effect-p")).unwrap();
        engine
            .add_edge(&CausalEdge {
                source_id: "cause-p".to_string(),
                target_id: "effect-p".to_string(),
                relation: "causes".to_string(),
                strength: 0.9,
                evidence: vec![CausalEvidence {
                    description: "Persistent evidence".to_string(),
                    source: "test".to_string(),
                    timestamp: Utc::now(),
                }],
                source_agent: None,
            })
            .unwrap();
    }

    {
        let engine = StorageEngine::open(&db_path).unwrap();
        let edges = engine.get_edges("cause-p").unwrap();
        assert_eq!(edges.len(), 1, "causal edge must survive restart");
        assert_eq!(edges[0].evidence.len(), 1);
        assert!((edges[0].strength - 0.9).abs() < f64::EPSILON);
    }

    dir.close().unwrap();
}

#[test]
fn version_history_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("version-persist.db");

    {
        let engine = StorageEngine::open(&db_path).unwrap();
        let mut mem = make_memory("ver-persist");
        engine.create(&mem).unwrap();

        // Generate 3 updates = 3 version snapshots
        for i in 1..=3 {
            mem.summary = format!("Version {i}");
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
    }

    {
        let engine = StorageEngine::open(&db_path).unwrap();
        let versions = engine
            .pool()
            .writer
            .with_conn_sync(|conn| version_ops::get_version_history(conn, "ver-persist"))
            .unwrap();
        assert_eq!(versions.len(), 3, "version history must survive restart");
    }

    dir.close().unwrap();
}

#[test]
fn audit_log_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("audit-persist.db");

    {
        let engine = StorageEngine::open(&db_path).unwrap();
        engine.create(&make_memory("audit-persist")).unwrap();
    }

    {
        let engine = StorageEngine::open(&db_path).unwrap();
        let entries = engine
            .pool()
            .writer
            .with_conn_sync(|conn| audit_ops::query_by_memory(conn, "audit-persist"))
            .unwrap();
        assert!(
            !entries.is_empty(),
            "audit log must survive restart"
        );
    }

    dir.close().unwrap();
}

#[test]
fn temporal_events_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events-persist.db");

    {
        let engine = StorageEngine::open(&db_path).unwrap();
        engine.create(&make_memory("ev-persist")).unwrap();
    }

    {
        let engine = StorageEngine::open(&db_path).unwrap();
        let events = engine
            .pool()
            .writer
            .with_conn_sync(|conn| {
                event_ops::get_events_for_memory(conn, "ev-persist", None)
            })
            .unwrap();
        assert!(
            !events.is_empty(),
            "temporal events must survive restart"
        );
    }

    dir.close().unwrap();
}

#[test]
fn embeddings_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("emb-persist.db");

    {
        let engine = StorageEngine::open(&db_path).unwrap();
        engine.create(&make_memory("emb-persist")).unwrap();
        engine
            .pool()
            .writer
            .with_conn_sync(|conn| {
                cortex_storage::queries::vector_search::store_embedding(
                    conn,
                    "emb-persist",
                    "hash-p",
                    &[0.1, 0.2, 0.3],
                    "test-model",
                )
            })
            .unwrap();
    }

    {
        let engine = StorageEngine::open(&db_path).unwrap();
        let results = engine.search_vector(&[0.1, 0.2, 0.3], 5).unwrap();
        assert!(!results.is_empty(), "embeddings must survive restart");
        assert_eq!(results[0].0.id, "emb-persist");
    }

    dir.close().unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// WAL MODE & PRAGMAS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn wal_mode_active_on_file_db() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("wal-check.db");

    let engine = StorageEngine::open(&db_path).unwrap();
    let ok = engine
        .pool()
        .writer
        .with_conn_sync(cortex_storage::pool::pragmas::verify_wal_mode)
        .unwrap();
    assert!(ok, "WAL mode must be active on file-backed DB");

    // WAL file should exist
    let wal_path = dir.path().join("wal-check.db-wal");
    // WAL file is created on first write
    engine.create(&make_memory("wal-trigger")).unwrap();
    assert!(wal_path.exists(), "WAL file should exist after write");

    drop(engine);
    dir.close().unwrap();
}

#[test]
fn foreign_keys_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("fk-check.db");
    let engine = StorageEngine::open(&db_path).unwrap();

    let fk_enabled: bool = engine
        .pool()
        .writer
        .with_conn_sync(|conn| {
            let enabled: i32 = conn
                .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
                .map_err(|e| cortex_storage::to_storage_err(e.to_string()))?;
            Ok(enabled == 1)
        })
        .unwrap();

    assert!(fk_enabled, "foreign_keys pragma must be ON");

    drop(engine);
    dir.close().unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// INTEGRITY CHECK: verify DB health
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integrity_check_after_heavy_operations() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("integrity.db");

    let engine = StorageEngine::open(&db_path).unwrap();

    // Perform many operations
    for i in 0..50 {
        engine
            .create(&make_memory(&format!("int-{i}")))
            .unwrap();
    }
    for i in 0..25 {
        engine.delete(&format!("int-{i}")).unwrap();
    }
    for i in 25..50 {
        let mut mem = make_memory(&format!("int-{i}"));
        mem.summary = format!("Updated {i}");
        engine.update(&mem).unwrap();
    }

    // Run integrity check
    let ok = engine
        .pool()
        .writer
        .with_conn_sync(cortex_storage::queries::maintenance::integrity_check)
        .unwrap();
    assert!(ok, "integrity check must pass after heavy operations");

    // Run vacuum
    engine.vacuum().unwrap();

    // Re-check after vacuum
    let ok2 = engine
        .pool()
        .writer
        .with_conn_sync(cortex_storage::queries::maintenance::integrity_check)
        .unwrap();
    assert!(ok2, "integrity check must pass after vacuum");

    drop(engine);
    dir.close().unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// RECOVERY: FTS5 rebuild, WAL checkpoint
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fts5_rebuild_preserves_search() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("fts5-rebuild.db");

    let engine = StorageEngine::open(&db_path).unwrap();
    engine.create(&make_memory("fts-rebuild-1")).unwrap();

    // Rebuild FTS5 index
    engine
        .pool()
        .writer
        .with_conn_sync(cortex_storage::recovery::fts5_rebuild::rebuild_fts5_index)
        .unwrap();

    // Search should still work
    let results = engine.search_fts5("Knowledge", 10).unwrap();
    assert!(
        !results.is_empty(),
        "FTS5 search must work after rebuild"
    );

    drop(engine);
    dir.close().unwrap();
}

#[test]
fn wal_checkpoint_after_writes() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("checkpoint.db");

    let engine = StorageEngine::open(&db_path).unwrap();

    // Write some data
    for i in 0..10 {
        engine
            .create(&make_memory(&format!("ckpt-{i}")))
            .unwrap();
    }

    // Checkpoint
    engine
        .pool()
        .writer
        .with_conn_sync(cortex_storage::queries::maintenance::wal_checkpoint)
        .unwrap();

    // Verify data is still readable after checkpoint
    for i in 0..10 {
        assert!(
            engine.get(&format!("ckpt-{i}")).unwrap().is_some(),
            "data must survive WAL checkpoint"
        );
    }

    drop(engine);
    dir.close().unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// MULTIPLE REOPEN CYCLES: stress test persistence
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn five_reopen_cycles() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("multi-reopen.db");

    for cycle in 0..5 {
        let engine = StorageEngine::open(&db_path).unwrap();

        // Create new data each cycle
        engine
            .create(&make_memory(&format!("cycle-{cycle}")))
            .unwrap();

        // Verify ALL previous cycles' data exists
        for prev in 0..=cycle {
            let mem = engine.get(&format!("cycle-{prev}")).unwrap();
            assert!(
                mem.is_some(),
                "data from cycle {prev} must survive through cycle {cycle}"
            );
        }

        // Drop engine to close connections
    }

    // Final verification: open one more time and check everything
    {
        let engine = StorageEngine::open(&db_path).unwrap();
        for i in 0..5 {
            assert!(
                engine.get(&format!("cycle-{i}")).unwrap().is_some(),
                "cycle-{i} must survive 5 reopen cycles"
            );
        }

        // Integrity check
        let ok = engine
            .pool()
            .writer
            .with_conn_sync(cortex_storage::queries::maintenance::integrity_check)
            .unwrap();
        assert!(ok, "integrity must pass after 5 reopen cycles");
    }

    dir.close().unwrap();
}

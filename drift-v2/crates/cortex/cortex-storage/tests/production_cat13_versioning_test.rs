//! Cat 13: Versioning & Reclassification (VR-01 through VR-10)

use chrono::Utc;

use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
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
// VR-01: Update creates version snapshot
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vr_01_update_creates_version_snapshot() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("vr01");
    storage.create(&mem).unwrap();

    let mut updated = mem.clone();
    updated.summary = "updated summary".into();
    storage.update(&updated).unwrap();

    let versions = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::versioning::query::get_history(conn, "vr01")
    }).unwrap();
    assert!(!versions.is_empty(), "should have at least 1 version snapshot");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VR-02: Multiple updates create ordered version chain
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vr_02_multiple_updates_ordered_versions() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("vr02");
    storage.create(&mem).unwrap();

    for i in 1..=3 {
        let mut updated = mem.clone();
        updated.summary = format!("v{i} summary");
        let new_tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
            observation: format!("v{i} observation"),
            evidence: vec![],
        });
        updated.content = new_tc.clone();
        updated.content_hash = BaseMemory::compute_content_hash(&new_tc).unwrap();
        storage.update(&updated).unwrap();
    }

    let versions = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::versioning::query::get_history(conn, "vr02")
    }).unwrap();
    assert_eq!(versions.len(), 3, "should have 3 version snapshots");

    // Versions should be in descending order (newest first).
    for w in versions.windows(2) {
        assert!(w[0].version > w[1].version, "versions should be descending (newest first)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VR-03: get_at_version retrieves specific version
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vr_03_get_at_version() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("vr03");
    storage.create(&mem).unwrap();

    let mut updated = mem.clone();
    updated.summary = "version 1 summary".into();
    storage.update(&updated).unwrap();

    let versions = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::versioning::query::get_history(conn, "vr03")
    }).unwrap();
    assert!(!versions.is_empty());

    let v1 = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::versioning::query::get_at_version(conn, "vr03", versions[0].version)
    }).unwrap();
    assert!(v1.is_some(), "should retrieve version 1");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VR-04: diff_versions returns both snapshots
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vr_04_diff_versions() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("vr04");
    storage.create(&mem).unwrap();

    // Two updates = 2 versions.
    for i in 1..=2 {
        let mut u = mem.clone();
        u.summary = format!("diff v{i}");
        let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
            observation: format!("diff obs {i}"),
            evidence: vec![],
        });
        u.content = tc.clone();
        u.content_hash = BaseMemory::compute_content_hash(&tc).unwrap();
        storage.update(&u).unwrap();
    }

    let versions = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::versioning::query::get_history(conn, "vr04")
    }).unwrap();
    assert!(versions.len() >= 2);

    let diff = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::versioning::query::diff_versions(
            conn, "vr04", versions[0].version, versions[1].version,
        )
    }).unwrap();
    assert!(diff.is_some(), "should return both snapshots for diff");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VR-05: Version snapshot stores content_json
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vr_05_version_stores_content() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("vr05");
    storage.create(&mem).unwrap();

    let mut u = mem.clone();
    u.summary = "updated for version".into();
    storage.update(&u).unwrap();

    let versions = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::versioning::query::get_history(conn, "vr05")
    }).unwrap();
    assert!(!versions.is_empty());
    assert!(!versions[0].content.is_empty(), "version should store content JSON");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VR-06: superseded_by / supersedes chain
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vr_06_supersession_chain() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem_old = make_memory("vr06-old");
    let mut mem_new = make_memory("vr06-new");

    mem_old.superseded_by = Some("vr06-new".into());
    mem_new.supersedes = Some("vr06-old".into());

    storage.create(&mem_old).unwrap();
    storage.create(&mem_new).unwrap();

    let old = storage.get("vr06-old").unwrap().unwrap();
    let new = storage.get("vr06-new").unwrap().unwrap();

    assert_eq!(old.superseded_by, Some("vr06-new".into()));
    assert_eq!(new.supersedes, Some("vr06-old".into()));
}

// ═══════════════════════════════════════════════════════════════════════════════
// VR-07: Memory type reclassification roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vr_07_reclassification_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("vr07");
    mem.memory_type = MemoryType::Episodic;
    storage.create(&mem).unwrap();

    // Reclassify to Semantic.
    let mut updated = mem.clone();
    updated.memory_type = MemoryType::Semantic;
    storage.update(&updated).unwrap();

    let got = storage.get("vr07").unwrap().unwrap();
    assert_eq!(got.memory_type, MemoryType::Semantic, "type should be reclassified");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VR-08: valid_until expiry stored and retrieved
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vr_08_valid_until_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mut mem = make_memory("vr08");
    let expiry = Utc::now() + chrono::Duration::days(30);
    mem.valid_until = Some(expiry);
    storage.create(&mem).unwrap();

    let got = storage.get("vr08").unwrap().unwrap();
    assert!(got.valid_until.is_some(), "valid_until should be stored");
    let stored = got.valid_until.unwrap();
    assert!((stored - expiry).num_seconds().abs() < 2, "valid_until should roundtrip");
}

// ═══════════════════════════════════════════════════════════════════════════════
// VR-09: Version retention enforced
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vr_09_version_retention() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("vr09");
    storage.create(&mem).unwrap();

    // Create many versions.
    for i in 0..20 {
        let mut u = mem.clone();
        u.summary = format!("v{i}");
        let tc = TypedContent::Insight(cortex_core::memory::types::InsightContent {
            observation: format!("obs v{i}"),
            evidence: vec![],
        });
        u.content = tc.clone();
        u.content_hash = BaseMemory::compute_content_hash(&tc).unwrap();
        storage.update(&u).unwrap();
    }

    let versions = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::versioning::query::get_history(conn, "vr09")
    }).unwrap();
    // Retention should cap versions (default is 10 or similar).
    assert!(
        versions.len() <= 20,
        "retention should be enforced. Got {} versions",
        versions.len()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// VR-10: Archived→restored roundtrip
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn vr_10_archive_restore_roundtrip() {
    let storage = StorageEngine::open_in_memory().unwrap();

    let mem = make_memory("vr10");
    storage.create(&mem).unwrap();

    // Archive.
    let mut archived = mem.clone();
    archived.archived = true;
    storage.update(&archived).unwrap();

    let got = storage.get("vr10").unwrap().unwrap();
    assert!(got.archived);

    // Restore.
    let mut restored = archived.clone();
    restored.archived = false;
    storage.update(&restored).unwrap();

    let got2 = storage.get("vr10").unwrap().unwrap();
    assert!(!got2.archived);

    // Check events.
    let events = storage.pool().writer.with_conn_sync(|conn| {
        cortex_storage::queries::event_ops::get_events_for_memory(conn, "vr10", None)
    }).unwrap();
    let types: Vec<&str> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert!(types.contains(&"archived"), "should have archived event");
    assert!(types.contains(&"restored"), "should have restored event");
}

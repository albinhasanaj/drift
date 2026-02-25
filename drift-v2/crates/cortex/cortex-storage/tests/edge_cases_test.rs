//! Edge case tests: SQL injection resistance, empty strings, huge content,
//! Unicode extremes, boundary values, adversarial inputs.
//!
//! These tests verify the storage layer handles ALL edge cases without
//! data corruption, silent truncation, or panics.

use chrono::Utc;
use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::traits::{CausalEdge, ICausalStorage, IMemoryStorage};
use cortex_storage::StorageEngine;

fn make_memory_with_content(id: &str, knowledge: &str) -> BaseMemory {
    let content = TypedContent::Tribal(TribalContent {
        knowledge: knowledge.to_string(),
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
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SQL INJECTION RESISTANCE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sql_injection_in_memory_id() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let id = "'; DROP TABLE memories; --";
    let mem = make_memory_with_content(id, "test");
    engine.create(&mem).unwrap();

    let loaded = engine.get(id).unwrap().unwrap();
    assert_eq!(loaded.id, id);

    // Verify memories table still works
    let other = make_memory_with_content("normal", "test");
    engine.create(&other).unwrap();
    assert!(engine.get("normal").unwrap().is_some());
}

#[test]
fn sql_injection_in_content() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let malicious = r#"'; INSERT INTO memories VALUES('hacked','','','','','',NULL,1.0,'critical','',0,'[]',0,NULL,NULL,'','','')); --"#;
    let mem = make_memory_with_content("inject-content", malicious);
    engine.create(&mem).unwrap();

    let loaded = engine.get("inject-content").unwrap().unwrap();
    if let TypedContent::Tribal(ref tc) = loaded.content {
        assert_eq!(tc.knowledge, malicious);
    }

    // Verify no "hacked" row was injected
    assert!(engine.get("hacked").unwrap().is_none());
}

#[test]
fn sql_injection_in_tags() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory_with_content("inject-tags", "test");
    mem.tags = vec![
        "normal".to_string(),
        "'; DROP TABLE memories; --".to_string(),
        "Robert'); DROP TABLE memories;--".to_string(),
    ];
    engine.create(&mem).unwrap();

    let loaded = engine.get("inject-tags").unwrap().unwrap();
    assert_eq!(loaded.tags.len(), 3);
    assert_eq!(loaded.tags[1], "'; DROP TABLE memories; --");
}

#[test]
fn sql_injection_in_search() {
    let engine = StorageEngine::open_in_memory().unwrap();
    engine
        .create(&make_memory_with_content("search-1", "findable content"))
        .unwrap();

    // FTS5 has its own query syntax — malformed queries may error, but must NEVER
    // corrupt the database or execute injected SQL.
    let _result = engine.search_fts5("'; DROP TABLE memories; --", 10);
    // Whether it returns Ok or Err, the DB must still be intact:
    assert!(
        engine.get("search-1").unwrap().is_some(),
        "database must survive malformed FTS5 query"
    );
    // And no injected table drop:
    engine
        .create(&make_memory_with_content("after-fts-inject", "still works"))
        .unwrap();
    assert!(engine.get("after-fts-inject").unwrap().is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// EMPTY STRING EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn empty_string_id() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory_with_content("", "content for empty id");
    // Empty ID should still work (SQLite allows empty string as PK)
    engine.create(&mem).unwrap();
    let loaded = engine.get("").unwrap().unwrap();
    assert_eq!(loaded.id, "");
}

#[test]
fn empty_string_summary() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory_with_content("empty-summary", "test");
    mem.summary = String::new();
    engine.create(&mem).unwrap();

    let loaded = engine.get("empty-summary").unwrap().unwrap();
    assert_eq!(loaded.summary, "");
}

#[test]
fn empty_tags_array() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory_with_content("empty-tags", "test");
    mem.tags = vec![];
    engine.create(&mem).unwrap();

    let loaded = engine.get("empty-tags").unwrap().unwrap();
    assert!(loaded.tags.is_empty());
}

#[test]
fn empty_string_in_tags() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory_with_content("empty-tag-item", "test");
    mem.tags = vec!["".to_string(), "nonempty".to_string(), "".to_string()];
    engine.create(&mem).unwrap();

    let loaded = engine.get("empty-tag-item").unwrap().unwrap();
    assert_eq!(loaded.tags.len(), 3);
}

// ═══════════════════════════════════════════════════════════════════════════
// UNICODE EXTREMES
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn unicode_emoji_in_all_fields() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory_with_content("emoji-🎉", "Knowledge 🚀🔥💯");
    mem.summary = "Summary 🎯 with emoji 🌍".to_string();
    mem.tags = vec!["tag-🏷️".to_string(), "🦀-rust".to_string()];
    engine.create(&mem).unwrap();

    let loaded = engine.get("emoji-🎉").unwrap().unwrap();
    assert_eq!(loaded.id, "emoji-🎉");
    assert_eq!(loaded.summary, "Summary 🎯 with emoji 🌍");
    assert_eq!(loaded.tags, vec!["tag-🏷️", "🦀-rust"]);
}

#[test]
fn unicode_cjk_characters() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory_with_content("cjk-test", "日本語テスト 中文测试 한국어시험");
    engine.create(&mem).unwrap();

    let loaded = engine.get("cjk-test").unwrap().unwrap();
    if let TypedContent::Tribal(ref tc) = loaded.content {
        assert_eq!(tc.knowledge, "日本語テスト 中文测试 한국어시험");
    }
}

#[test]
fn unicode_rtl_and_bidi() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mem = make_memory_with_content("rtl-test", "مرحبا بالعالم שלום עולם");
    engine.create(&mem).unwrap();

    let loaded = engine.get("rtl-test").unwrap().unwrap();
    if let TypedContent::Tribal(ref tc) = loaded.content {
        assert_eq!(tc.knowledge, "مرحبا بالعالم שלום עולם");
    }
}

#[test]
fn unicode_zero_width_characters() {
    let engine = StorageEngine::open_in_memory().unwrap();
    // Zero-width space, zero-width joiner, zero-width non-joiner
    let content = "before\u{200B}after\u{200C}end\u{200D}final";
    let mem = make_memory_with_content("zwc-test", content);
    engine.create(&mem).unwrap();

    let loaded = engine.get("zwc-test").unwrap().unwrap();
    if let TypedContent::Tribal(ref tc) = loaded.content {
        assert_eq!(tc.knowledge, content, "zero-width chars must survive roundtrip");
    }
}

#[test]
fn unicode_combining_characters() {
    let engine = StorageEngine::open_in_memory().unwrap();
    // é as e + combining acute accent
    let content = "cafe\u{0301} naïve";
    let mem = make_memory_with_content("combining-test", content);
    engine.create(&mem).unwrap();

    let loaded = engine.get("combining-test").unwrap().unwrap();
    if let TypedContent::Tribal(ref tc) = loaded.content {
        assert_eq!(tc.knowledge, content);
    }
}

#[test]
fn unicode_surrogate_pair_emoji() {
    let engine = StorageEngine::open_in_memory().unwrap();
    // Multi-codepoint emoji: family emoji (👨‍👩‍👧‍👦), flag emoji (🇺🇸)
    let content = "Family: 👨\u{200D}👩\u{200D}👧\u{200D}👦 Flag: 🇺🇸";
    let mem = make_memory_with_content("surrogate-test", content);
    engine.create(&mem).unwrap();

    let loaded = engine.get("surrogate-test").unwrap().unwrap();
    if let TypedContent::Tribal(ref tc) = loaded.content {
        assert_eq!(tc.knowledge, content);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LARGE CONTENT
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn large_content_1mb() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let large = "x".repeat(1_000_000); // 1MB
    let mem = make_memory_with_content("large-1mb", &large);
    engine.create(&mem).unwrap();

    let loaded = engine.get("large-1mb").unwrap().unwrap();
    if let TypedContent::Tribal(ref tc) = loaded.content {
        assert_eq!(tc.knowledge.len(), 1_000_000);
    }
}

#[test]
fn many_tags_100() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory_with_content("many-tags", "test");
    mem.tags = (0..100).map(|i| format!("tag-{i}")).collect();
    engine.create(&mem).unwrap();

    let loaded = engine.get("many-tags").unwrap().unwrap();
    assert_eq!(loaded.tags.len(), 100);
}

#[test]
fn many_links_50_each() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory_with_content("many-links", "test");
    mem.linked_patterns = (0..50)
        .map(|i| PatternLink {
            pattern_id: format!("p-{i}"),
            pattern_name: format!("Pattern {i}"),
        })
        .collect();
    mem.linked_files = (0..50)
        .map(|i| FileLink {
            file_path: format!("/src/file{i}.rs"),
            line_start: Some(i as u32),
            line_end: Some((i + 10) as u32),
            content_hash: None,
        })
        .collect();
    engine.create(&mem).unwrap();

    let loaded = engine.get("many-links").unwrap().unwrap();
    assert_eq!(loaded.linked_patterns.len(), 50);
    assert_eq!(loaded.linked_files.len(), 50);
}

// ═══════════════════════════════════════════════════════════════════════════
// BOUNDARY VALUES
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn confidence_boundary_values() {
    let engine = StorageEngine::open_in_memory().unwrap();

    // Confidence at exact boundaries
    for (id, conf) in &[("conf-0", 0.0), ("conf-1", 1.0), ("conf-half", 0.5)] {
        let mut mem = make_memory_with_content(id, "test");
        mem.confidence = Confidence::new(*conf);
        engine.create(&mem).unwrap();

        let loaded = engine.get(id).unwrap().unwrap();
        assert!(
            (loaded.confidence.value() - conf).abs() < f64::EPSILON,
            "confidence {conf} should roundtrip exactly"
        );
    }
}

#[test]
fn access_count_large_value() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let mut mem = make_memory_with_content("access-big", "test");
    mem.access_count = u64::MAX / 2; // Very large but safe for i64
    engine.create(&mem).unwrap();

    let loaded = engine.get("access-big").unwrap().unwrap();
    assert_eq!(loaded.access_count, u64::MAX / 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// SPECIAL CHARACTERS IN VARIOUS CONTEXTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn null_bytes_in_content() {
    let engine = StorageEngine::open_in_memory().unwrap();
    // SQLite TEXT doesn't support embedded NUL bytes, but our JSON serialization should handle it
    let content = "before\0after";
    let mem = make_memory_with_content("null-byte", content);
    // This might fail at the JSON serialization level or SQLite level
    // Either way, it should not corrupt the database
    let result = engine.create(&mem);
    if result.is_ok() {
        // If it succeeded, verify we can still read other data
        engine
            .create(&make_memory_with_content("after-null", "test"))
            .unwrap();
        assert!(engine.get("after-null").unwrap().is_some());
    }
}

#[test]
fn backslash_and_quotes() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let content = r#"path: C:\Users\test "quoted" 'single' `backtick`"#;
    let mem = make_memory_with_content("special-chars", content);
    engine.create(&mem).unwrap();

    let loaded = engine.get("special-chars").unwrap().unwrap();
    if let TypedContent::Tribal(ref tc) = loaded.content {
        assert_eq!(tc.knowledge, content);
    }
}

#[test]
fn newlines_and_tabs() {
    let engine = StorageEngine::open_in_memory().unwrap();
    let content = "line1\nline2\tindented\r\nwindows\rold_mac";
    let mem = make_memory_with_content("whitespace", content);
    engine.create(&mem).unwrap();

    let loaded = engine.get("whitespace").unwrap().unwrap();
    if let TypedContent::Tribal(ref tc) = loaded.content {
        assert_eq!(tc.knowledge, content);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONCURRENT-STYLE: rapid sequential operations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn rapid_create_update_delete_cycle_100x() {
    let engine = StorageEngine::open_in_memory().unwrap();

    for i in 0..100 {
        let id = format!("rapid-{i}");
        let mut mem = make_memory_with_content(&id, &format!("content {i}"));
        engine.create(&mem).unwrap();

        mem.summary = format!("updated {i}");
        engine.update(&mem).unwrap();

        engine.delete(&id).unwrap();
        assert!(engine.get(&id).unwrap().is_none());
    }

    // Verify DB is still healthy
    engine
        .create(&make_memory_with_content("after-rapid", "still works"))
        .unwrap();
    assert!(engine.get("after-rapid").unwrap().is_some());
}

#[test]
fn rapid_causal_edge_operations() {
    let engine = StorageEngine::open_in_memory().unwrap();

    // Create 10 nodes
    for i in 0..10 {
        engine
            .create(&make_memory_with_content(&format!("node-{i}"), "node"))
            .unwrap();
    }

    // Create edges between consecutive nodes
    for i in 0..9 {
        engine
            .add_edge(&CausalEdge {
                source_id: format!("node-{i}"),
                target_id: format!("node-{}", i + 1),
                relation: "follows".to_string(),
                strength: 0.5 + (i as f64 * 0.05),
                evidence: vec![],
                source_agent: None,
            })
            .unwrap();
    }

    assert_eq!(engine.edge_count().unwrap(), 9);

    // Update all strengths
    for i in 0..9 {
        engine
            .update_strength(&format!("node-{i}"), &format!("node-{}", i + 1), 0.99)
            .unwrap();
    }

    // Remove all edges
    for i in 0..9 {
        engine
            .remove_edge(&format!("node-{i}"), &format!("node-{}", i + 1))
            .unwrap();
    }

    assert_eq!(engine.edge_count().unwrap(), 0);
}

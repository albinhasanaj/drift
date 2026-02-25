use chrono::Utc;
use cortex_compression::{CompressionEngine, CompressionLevel};
use cortex_core::memory::*;
use cortex_core::traits::ICompressor;

fn make_test_memory(importance: Importance) -> BaseMemory {
    BaseMemory {
        id: uuid::Uuid::new_v4().to_string(),
        memory_type: MemoryType::Tribal,
        content: TypedContent::Tribal(cortex_core::memory::types::TribalContent {
            knowledge: "Always use bcrypt for password hashing, never MD5.".to_string(),
            severity: "high".to_string(),
            warnings: vec!["MD5 is cryptographically broken".to_string()],
            consequences: vec!["Security vulnerability if MD5 used".to_string()],
        }),
        summary: "Use bcrypt for password hashing".to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.95),
        importance,
        last_accessed: Utc::now(),
        access_count: 42,
        linked_patterns: vec![PatternLink {
            pattern_id: "pat-001".to_string(),
            pattern_name: "secure-hashing".to_string(),
        }],
        linked_constraints: vec![ConstraintLink {
            constraint_id: "con-001".to_string(),
            constraint_name: "no-md5".to_string(),
        }],
        linked_files: vec![FileLink {
            file_path: "src/auth/hasher.rs".to_string(),
            line_start: Some(10),
            line_end: Some(25),
            content_hash: Some("abc123".to_string()),
        }],
        linked_functions: vec![FunctionLink {
            function_name: "hash_password".to_string(),
            file_path: "src/auth/hasher.rs".to_string(),
            signature: Some("fn hash_password(pwd: &str) -> String".to_string()),
        }],
        tags: vec![
            "security".to_string(),
            "auth".to_string(),
            "bcrypt".to_string(),
        ],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: "deadbeef".to_string(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ── T4-COMP-01: Level ordering ────────────────────────────────────────────

#[test]
fn level_ordering_tokens_l0_lt_l1_lt_l2_lt_l3() {
    let engine = CompressionEngine::new();
    let memory = make_test_memory(Importance::Normal);

    let l0 = engine.compress(&memory, 0).unwrap();
    let l1 = engine.compress(&memory, 1).unwrap();
    let l2 = engine.compress(&memory, 2).unwrap();
    let l3 = engine.compress(&memory, 3).unwrap();

    assert!(
        l0.token_count < l1.token_count,
        "L0 ({}) should be < L1 ({})",
        l0.token_count,
        l1.token_count
    );
    assert!(
        l1.token_count < l2.token_count,
        "L1 ({}) should be < L2 ({})",
        l1.token_count,
        l2.token_count
    );
    assert!(
        l2.token_count < l3.token_count,
        "L2 ({}) should be < L3 ({})",
        l2.token_count,
        l3.token_count
    );
}

// ── T4-COMP-02: Level 3 is lossless ──────────────────────────────────────

#[test]
fn level3_preserves_all_content() {
    let engine = CompressionEngine::new();
    let memory = make_test_memory(Importance::Normal);

    let l3 = engine.compress(&memory, 3).unwrap();

    // L3 should contain the full content, summary, tags, files, functions, etc.
    assert!(
        l3.text.contains("bcrypt"),
        "L3 missing content keyword 'bcrypt'"
    );
    assert!(l3.text.contains(&memory.summary), "L3 missing summary");
    assert!(l3.text.contains("security"), "L3 missing tag 'security'");
    assert!(
        l3.text.contains("src/auth/hasher.rs"),
        "L3 missing file link"
    );
    assert!(
        l3.text.contains("hash_password"),
        "L3 missing function link"
    );
    assert!(
        l3.text.contains("secure-hashing"),
        "L3 missing pattern link"
    );
    assert!(l3.text.contains("no-md5"), "L3 missing constraint link");
    assert!(l3.text.contains(&memory.id), "L3 missing memory ID");
}

// ── T4-COMP-03: Level 0 contains only ID ─────────────────────────────────

#[test]
fn level0_minimal_representation() {
    let engine = CompressionEngine::new();
    let memory = make_test_memory(Importance::Normal);

    let l0 = engine.compress(&memory, 0).unwrap();

    // L0 should be very short — just type + truncated ID
    assert!(
        l0.token_count <= 10,
        "L0 should be ≤10 tokens, got {}",
        l0.token_count
    );
    assert!(l0.text.contains("tribal"), "L0 should contain type label");
}

// ── T4-COMP-04: compressToFit never exceeds budget ───────────────────────

#[test]
fn compress_to_fit_respects_budget() {
    let engine = CompressionEngine::new();
    let memory = make_test_memory(Importance::Normal);

    // L0 is the minimum — test budgets that can fit at least L0
    for budget in [15, 50, 100, 200, 500, 1000] {
        let result = engine.compress_to_fit(&memory, budget).unwrap();
        assert!(
            result.token_count <= budget,
            "compress_to_fit exceeded budget {}: got {} tokens",
            budget,
            result.token_count
        );
    }
}

// ── T4-COMP-05: compressBatchToFit respects total budget ─────────────────

#[test]
fn compress_batch_to_fit_respects_total_budget() {
    let engine = CompressionEngine::new();
    let memories: Vec<BaseMemory> = (0..10)
        .map(|_| make_test_memory(Importance::Normal))
        .collect();

    for budget in [50, 100, 200, 500, 1000] {
        let results = engine.compress_batch_to_fit(&memories, budget).unwrap();
        let total_tokens: usize = results.iter().map(|r| r.token_count).sum();
        assert!(
            total_tokens <= budget,
            "Batch exceeded budget {}: got {} tokens",
            budget,
            total_tokens
        );
    }
}

// ── T4-COMP-06: Critical memories get at least L1 ───────────────────────

#[test]
fn critical_memories_get_at_least_l1() {
    let engine = CompressionEngine::new();

    let mut memories = Vec::new();
    // Add a critical memory
    memories.push(make_test_memory(Importance::Critical));
    // Add several normal memories to compete for budget
    for _ in 0..5 {
        memories.push(make_test_memory(Importance::Low));
    }

    // Give enough budget for at least the critical memory at L1
    let results = engine.compress_batch_to_fit(&memories, 200).unwrap();

    // Find the critical memory in results
    let critical_result = results
        .iter()
        .find(|r| r.importance == Importance::Critical);

    if let Some(critical) = critical_result {
        assert!(
            critical.level >= 1,
            "Critical memory should get at least L1, got L{}",
            critical.level
        );
    }
}

// ── Additional tests ──────────────────────────────────────────────────────

#[test]
fn compression_level_ordering() {
    assert!(CompressionLevel::L0 < CompressionLevel::L1);
    assert!(CompressionLevel::L1 < CompressionLevel::L2);
    assert!(CompressionLevel::L2 < CompressionLevel::L3);
}

#[test]
fn compression_level_max_tokens() {
    assert_eq!(CompressionLevel::L0.max_tokens(), 10);
    assert_eq!(CompressionLevel::L1.max_tokens(), 75);
    assert_eq!(CompressionLevel::L2.max_tokens(), 300);
    assert_eq!(CompressionLevel::L3.max_tokens(), 1000);
}

#[test]
fn empty_batch_returns_empty() {
    let engine = CompressionEngine::new();
    let results = engine.compress_batch_to_fit(&[], 1000).unwrap();
    assert!(results.is_empty());
}

#[test]
fn zero_budget_returns_empty() {
    let engine = CompressionEngine::new();
    let memories = vec![make_test_memory(Importance::Normal)];
    let results = engine.compress_batch_to_fit(&memories, 0).unwrap();
    assert!(results.is_empty());
}

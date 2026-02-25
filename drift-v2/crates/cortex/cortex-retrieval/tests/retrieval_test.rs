//! cortex-retrieval integration tests.
//!
//! Tests T5-RET-01 through T5-RET-14 from the task tracker.

use std::collections::HashMap;

use chrono::Utc;

use cortex_core::config::RetrievalConfig;
use cortex_core::intent::Intent;
use cortex_core::memory::{
    BaseMemory, Confidence, Importance, MemoryType, PatternLink, TypedContent,
};
use cortex_core::models::RetrievalContext;
use cortex_core::traits::{IMemoryStorage, IRetriever};

use cortex_compression::CompressionEngine;
use cortex_storage::StorageEngine;

use cortex_retrieval::engine::RetrievalEngine;
use cortex_retrieval::generation::feedback::GenerationOutcome;
use cortex_retrieval::generation::GenerationOrchestrator;
use cortex_retrieval::intent::IntentEngine;
use cortex_retrieval::search::rrf_fusion;
use cortex_retrieval::why::WhySynthesizer;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_storage() -> StorageEngine {
    StorageEngine::open_in_memory().expect("failed to open in-memory storage")
}

fn test_compressor() -> CompressionEngine {
    CompressionEngine::new()
}

fn make_memory(
    id: &str,
    summary: &str,
    mem_type: MemoryType,
    importance: Importance,
) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: mem_type,
        content: TypedContent::Core(cortex_core::memory::types::CoreContent {
            project_name: String::new(),
            description: summary.to_string(),
            metadata: serde_json::Value::Null,
        }),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance,
        last_accessed: Utc::now(),
        access_count: 1,
        linked_patterns: Vec::new(),
        linked_constraints: Vec::new(),
        linked_files: Vec::new(),
        linked_functions: Vec::new(),
        tags: Vec::new(),
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: cortex_core::BaseMemory::compute_content_hash(&TypedContent::Core(
            cortex_core::memory::types::CoreContent {
                project_name: String::new(),
                description: summary.to_string(),
                metadata: serde_json::Value::Null,
            },
        ))
        .unwrap(),
    }
}

fn seed_test_memories(storage: &StorageEngine) {
    let memories = vec![
        {
            let mut m = make_memory(
                "mem-bcrypt-1",
                "Always use bcrypt for password hashing with cost factor 12",
                MemoryType::Tribal,
                Importance::Critical,
            );
            m.tags = vec!["security".into(), "passwords".into(), "bcrypt".into()];
            m
        },
        {
            let mut m = make_memory(
                "mem-pattern-1",
                "Repository pattern for database access layer",
                MemoryType::PatternRationale,
                Importance::High,
            );
            m.linked_patterns = vec![PatternLink {
                pattern_id: "pat-repo".into(),
                pattern_name: "repository-pattern".into(),
            }];
            m
        },
        make_memory(
            "mem-smell-1",
            "Avoid using string concatenation for SQL queries to prevent injection",
            MemoryType::CodeSmell,
            Importance::Critical,
        ),
        make_memory(
            "mem-decision-1",
            "Chose PostgreSQL over MySQL for JSON support and performance",
            MemoryType::DecisionContext,
            Importance::High,
        ),
        make_memory(
            "mem-constraint-1",
            "All API endpoints must validate input with JSON schema",
            MemoryType::ConstraintOverride,
            Importance::Critical,
        ),
        {
            let mut m = make_memory(
                "mem-incident-1",
                "Production outage caused by missing database index on users table",
                MemoryType::Incident,
                Importance::Critical,
            );
            m.tags = vec!["database".into(), "performance".into(), "outage".into()];
            m
        },
        make_memory(
            "mem-tribal-2",
            "The auth middleware must be applied before any route handler",
            MemoryType::Tribal,
            Importance::High,
        ),
    ];

    for m in &memories {
        storage.create(m).expect("failed to create memory");
    }
}

// ---------------------------------------------------------------------------
// T5-RET-01: Hybrid search returns results for keyword query
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_01_keyword_search_finds_bcrypt() {
    let storage = test_storage();
    seed_test_memories(&storage);

    let config = RetrievalConfig::default();
    let compressor = test_compressor();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    let context = RetrievalContext {
        focus: "bcrypt".to_string(),
        intent: None,
        active_files: Vec::new(),
        budget: 2000,
        sent_ids: Vec::new(),
    };

    let results = engine.retrieve(&context, 2000).unwrap();
    assert!(
        results.iter().any(|r| r.memory_id == "mem-bcrypt-1"),
        "should find bcrypt memory via keyword search"
    );
}

// ---------------------------------------------------------------------------
// T5-RET-02: Hybrid search returns results for semantic query
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_02_semantic_query_finds_related() {
    let storage = test_storage();
    seed_test_memories(&storage);

    let config = RetrievalConfig::default();
    let compressor = test_compressor();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    let context = RetrievalContext {
        focus: "password security hashing".to_string(),
        intent: None,
        active_files: Vec::new(),
        budget: 2000,
        sent_ids: Vec::new(),
    };

    let results = engine.retrieve(&context, 2000).unwrap();
    // FTS5 should match "password" in the bcrypt memory.
    assert!(
        results.iter().any(|r| r.memory_id == "mem-bcrypt-1"),
        "should find bcrypt memory via semantic query about password security"
    );
}

// ---------------------------------------------------------------------------
// T5-RET-03: RRF scores are monotonically decreasing
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_03_rrf_scores_monotonically_decreasing() {
    let mut memories = HashMap::new();
    for i in 0..10 {
        let id = format!("mem-{i}");
        memories.insert(
            id.clone(),
            make_memory(
                &id,
                &format!("Memory {i}"),
                MemoryType::Core,
                Importance::Normal,
            ),
        );
    }

    let list1: Vec<(String, usize)> = (0..10).map(|i| (format!("mem-{i}"), i)).collect();
    let list2: Vec<(String, usize)> = (0..10).rev().map(|i| (format!("mem-{i}"), 9 - i)).collect();

    let candidates = rrf_fusion::fuse(Some(&list1), Some(&list2), None, &memories, 60);

    for window in candidates.windows(2) {
        assert!(
            window[0].rrf_score >= window[1].rrf_score,
            "RRF scores must be monotonically decreasing: {} >= {}",
            window[0].rrf_score,
            window[1].rrf_score
        );
    }
}

// ---------------------------------------------------------------------------
// T5-RET-04: FTS5 results + vector results ⊆ RRF results
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_04_no_results_lost_in_fusion() {
    let mut memories = HashMap::new();
    for i in 0..6 {
        let id = format!("mem-{i}");
        memories.insert(
            id.clone(),
            make_memory(
                &id,
                &format!("Memory {i}"),
                MemoryType::Core,
                Importance::Normal,
            ),
        );
    }

    let fts_list: Vec<(String, usize)> = vec![
        ("mem-0".into(), 0),
        ("mem-1".into(), 1),
        ("mem-2".into(), 2),
    ];
    let vec_list: Vec<(String, usize)> = vec![
        ("mem-3".into(), 0),
        ("mem-4".into(), 1),
        ("mem-5".into(), 2),
    ];

    let candidates = rrf_fusion::fuse(Some(&fts_list), Some(&vec_list), None, &memories, 60);
    let fused_ids: Vec<&str> = candidates.iter().map(|c| c.memory.id.as_str()).collect();

    // All input IDs should appear in the fused results.
    for i in 0..6 {
        let id = format!("mem-{i}");
        assert!(
            fused_ids.contains(&id.as_str()),
            "mem-{i} should be in RRF results"
        );
    }
}

// ---------------------------------------------------------------------------
// T5-RET-05: Token budget never exceeded
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_05_token_budget_never_exceeded() {
    let storage = test_storage();
    seed_test_memories(&storage);

    let config = RetrievalConfig::default();
    let compressor = test_compressor();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    let budgets = [100, 500, 1000, 2000];
    for budget in budgets {
        let context = RetrievalContext {
            focus: "bcrypt password security database".to_string(),
            intent: None,
            active_files: Vec::new(),
            budget,
            sent_ids: Vec::new(),
        };

        let results = engine.retrieve(&context, budget).unwrap();
        let total_tokens: usize = results.iter().map(|r| r.token_count).sum();
        assert!(
            total_tokens <= budget,
            "total tokens {total_tokens} exceeds budget {budget}"
        );
    }
}

// ---------------------------------------------------------------------------
// T5-RET-06: Higher importance ranks above at equal similarity
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_06_higher_importance_ranks_above() {
    use cortex_retrieval::ranking::scorer::{score, ScorerWeights};
    use cortex_retrieval::search::rrf_fusion::RrfCandidate;

    // Test the scorer directly with controlled inputs to avoid FTS5
    // non-determinism for identically-ranked documents.
    let low = make_memory(
        "mem-low",
        "database query optimization",
        MemoryType::Core,
        Importance::Low,
    );
    let critical = make_memory(
        "mem-crit",
        "database query optimization",
        MemoryType::Core,
        Importance::Critical,
    );

    // Both candidates have identical RRF scores and FTS5 ranks —
    // only importance should differentiate them.
    let candidates = vec![
        RrfCandidate {
            memory: low,
            rrf_score: 0.5,
            fts5_rank: Some(0),
            vector_rank: None,
            entity_rank: None,
        },
        RrfCandidate {
            memory: critical,
            rrf_score: 0.5,
            fts5_rank: Some(0),
            vector_rank: None,
            entity_rank: None,
        },
    ];

    let weights = ScorerWeights::default();
    let intent_engine = IntentEngine::new();
    let scored = score(&candidates, Intent::Investigate, &[], &intent_engine, &weights);

    let crit = scored.iter().find(|s| s.memory.id == "mem-crit").unwrap();
    let low = scored.iter().find(|s| s.memory.id == "mem-low").unwrap();

    assert!(
        crit.score > low.score,
        "critical importance ({:.4}) should score above low importance ({:.4})",
        crit.score,
        low.score,
    );
}

// ---------------------------------------------------------------------------
// T5-RET-07: Session deduplication filters already-sent memories
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_07_session_dedup_filters_sent() {
    let storage = test_storage();
    seed_test_memories(&storage);

    let config = RetrievalConfig::default();
    let compressor = test_compressor();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    let context = RetrievalContext {
        focus: "bcrypt password".to_string(),
        intent: None,
        active_files: Vec::new(),
        budget: 2000,
        sent_ids: vec!["mem-bcrypt-1".to_string()],
    };

    let results = engine.retrieve(&context, 2000).unwrap();
    assert!(
        !results.iter().any(|r| r.memory_id == "mem-bcrypt-1"),
        "already-sent memory should be filtered out"
    );
}

// ---------------------------------------------------------------------------
// T5-RET-08: Intent weighting boosts correct types
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_08_intent_boosts_correct_types() {
    let intent_engine = IntentEngine::new();

    // FixBug should boost Tribal and Incident.
    let tribal_boost = intent_engine.boost(Intent::FixBug, MemoryType::Tribal);
    let core_boost = intent_engine.boost(Intent::FixBug, MemoryType::Core);
    assert!(
        tribal_boost > core_boost,
        "FixBug should boost Tribal ({tribal_boost}) more than Core ({core_boost})"
    );

    let incident_boost = intent_engine.boost(Intent::FixBug, MemoryType::Incident);
    assert!(
        incident_boost > 1.0,
        "FixBug should boost Incident ({incident_boost})"
    );
}

// ---------------------------------------------------------------------------
// T5-RET-09: Generation context respects budget allocation
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_09_generation_context_respects_budget() {
    let storage = test_storage();
    seed_test_memories(&storage);
    let compressor = test_compressor();

    let orchestrator = GenerationOrchestrator::new(&storage, &compressor);
    let output = orchestrator.build("database security", &[], 2000).unwrap();

    // Total tokens should not exceed budget.
    assert!(
        output.context.total_tokens <= output.context.total_budget,
        "total tokens {} exceeds budget {}",
        output.context.total_tokens,
        output.context.total_budget
    );

    // Should have pattern allocation at ~30%.
    let pattern_alloc = output
        .context
        .allocations
        .iter()
        .find(|a| a.category == "patterns");
    assert!(pattern_alloc.is_some(), "should have patterns allocation");
    if let Some(pa) = pattern_alloc {
        assert!(
            (pa.percentage - 0.30).abs() < 0.01,
            "patterns should be ~30%, got {}",
            pa.percentage
        );
    }
}

// ---------------------------------------------------------------------------
// T5-RET-10: Empty query returns empty results
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_10_empty_query_returns_empty() {
    let storage = test_storage();
    seed_test_memories(&storage);

    let config = RetrievalConfig::default();
    let compressor = test_compressor();
    let engine = RetrievalEngine::new(&storage, &compressor, config);

    let context = RetrievalContext {
        focus: "".to_string(),
        intent: None,
        active_files: Vec::new(),
        budget: 2000,
        sent_ids: Vec::new(),
    };

    let results = engine.retrieve(&context, 2000).unwrap();
    assert!(
        results.is_empty(),
        "empty query should return empty results"
    );
}

// ---------------------------------------------------------------------------
// T5-RET-11: Why synthesizer produces WhyContext
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_11_why_synthesizer_produces_context() {
    let storage = test_storage();
    seed_test_memories(&storage);

    let why = WhySynthesizer::new(&storage, &storage);
    let ctx = why.synthesize("database security", 500).unwrap();

    // Should have non-empty content.
    let has_content = !ctx.patterns.is_empty()
        || !ctx.decisions.is_empty()
        || !ctx.tribal.is_empty()
        || !ctx.warnings.is_empty();
    assert!(has_content, "WhyContext should have non-empty content");
}

// ---------------------------------------------------------------------------
// T5-RET-12: Provenance comments generated
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_12_provenance_comments_generated() {
    let storage = test_storage();
    seed_test_memories(&storage);
    let compressor = test_compressor();

    let orchestrator = GenerationOrchestrator::new(&storage, &compressor);
    let output = orchestrator
        .build("database security bcrypt", &[], 2000)
        .unwrap();

    // Should have provenance records.
    assert!(
        !output.provenance.is_empty(),
        "should generate provenance records"
    );

    // Inline comments should contain drift tags.
    let has_drift_tag = output.inline_comments.contains("[drift:");
    assert!(
        has_drift_tag,
        "inline comments should contain [drift:*] tags"
    );
}

// ---------------------------------------------------------------------------
// T5-RET-13: Generation feedback adjusts confidence
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_13_feedback_adjusts_confidence() {
    let storage = test_storage();
    seed_test_memories(&storage);
    let compressor = test_compressor();

    let orchestrator = GenerationOrchestrator::new(&storage, &compressor);

    // Get original confidence.
    let original = storage.get("mem-bcrypt-1").unwrap().unwrap();
    let original_conf = original.confidence.value();

    // Apply rejected feedback.
    let updated = orchestrator
        .apply_feedback(&["mem-bcrypt-1".to_string()], GenerationOutcome::Rejected)
        .unwrap();

    assert_eq!(updated, 1, "should update 1 memory");

    let after = storage.get("mem-bcrypt-1").unwrap().unwrap();
    assert!(
        after.confidence.value() < original_conf,
        "rejected feedback should decrease confidence: {} < {}",
        after.confidence.value(),
        original_conf
    );
}

// ---------------------------------------------------------------------------
// T5-RET-14: Pre-generation validation catches pattern violations
// ---------------------------------------------------------------------------
#[test]
fn t5_ret_14_validation_catches_violations() {
    let storage = test_storage();
    seed_test_memories(&storage);

    // Use "concatenation" which appears in the CodeSmell memory summary:
    // "Avoid using string concatenation for SQL queries to prevent injection"
    let report = cortex_retrieval::generation::validation::validate_pre_generation(
        &storage,
        "string concatenation SQL queries",
    )
    .unwrap();

    // Should have warnings about the SQL injection anti-pattern or constraints.
    assert!(
        !report.warnings.is_empty(),
        "should detect warnings for SQL-related query"
    );
}

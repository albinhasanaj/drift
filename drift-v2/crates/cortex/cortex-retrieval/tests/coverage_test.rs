//! Targeted coverage tests for cortex-retrieval uncovered paths.
//!
//! Focuses on: query expansion (synonym, HyDE), RRF fusion, scoring,
//! deduplication, reranker, intent classification, weight matrix,
//! generation (provenance, feedback, validation), why aggregator.

use std::collections::HashMap;

use chrono::Utc;
use cortex_core::intent::Intent;
use cortex_core::memory::*;
use cortex_core::models::RetrievalContext;

use cortex_retrieval::intent::IntentEngine;

// ─── Helper ──────────────────────────────────────────────────────────────────

fn make_memory(id: &str, summary: &str, mem_type: MemoryType) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: mem_type,
        content: TypedContent::Semantic(cortex_core::memory::types::SemanticContent {
            knowledge: summary.to_string(),
            source_episodes: vec![],
            consolidation_confidence: 0.8,
        }),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 1,
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
        content_hash: format!("hash-{id}"),
    }
}

// ─── Synonym Expansion ───────────────────────────────────────────────────────

#[test]
fn synonym_expand_known_term() {
    let expanded = cortex_retrieval::expansion::synonym_expander::expand("auth middleware");
    assert!(expanded.contains("authentication") || expanded.contains("login"));
    assert!(expanded.contains("auth")); // Original preserved.
}

#[test]
fn synonym_expand_unknown_term() {
    let expanded = cortex_retrieval::expansion::synonym_expander::expand("foobar baz");
    assert_eq!(expanded, "foobar baz"); // No expansion.
}

#[test]
fn synonym_expand_multiple_terms() {
    let expanded = cortex_retrieval::expansion::synonym_expander::expand("auth db");
    assert!(expanded.contains("authentication") || expanded.contains("database"));
}

// ─── HyDE ────────────────────────────────────────────────────────────────────

#[test]
fn hyde_fix_bug_intent() {
    let doc =
        cortex_retrieval::expansion::hyde::generate_hypothetical("null pointer", Intent::FixBug);
    assert!(doc.contains("Bug fix"));
    assert!(doc.contains("null pointer"));
}

#[test]
fn hyde_add_feature_intent() {
    let doc =
        cortex_retrieval::expansion::hyde::generate_hypothetical("auth module", Intent::AddFeature);
    assert!(doc.contains("Feature implementation"));
}

#[test]
fn hyde_generic_intent() {
    let doc = cortex_retrieval::expansion::hyde::generate_hypothetical("something", Intent::Create);
    assert!(doc.contains("Context:"));
}

// ─── Query Expansion (combined) ──────────────────────────────────────────────

#[test]
fn expand_query_produces_both_fields() {
    let result = cortex_retrieval::expansion::expand_query("auth issue", Intent::FixBug);
    assert!(!result.expanded_text.is_empty());
    assert!(!result.hypothetical_doc.is_empty());
}

// ─── RRF Fusion ──────────────────────────────────────────────────────────────

#[test]
fn rrf_fuse_empty_lists() {
    let memories: HashMap<String, BaseMemory> = HashMap::new();
    let result = cortex_retrieval::search::rrf_fusion::fuse(None, None, None, &memories, 60);
    assert!(result.is_empty());
}

#[test]
fn rrf_fuse_single_list() {
    let m1 = make_memory("m1", "first", MemoryType::Semantic);
    let m2 = make_memory("m2", "second", MemoryType::Semantic);
    let mut memories = HashMap::new();
    memories.insert("m1".to_string(), m1);
    memories.insert("m2".to_string(), m2);

    let list = vec![("m1".to_string(), 1), ("m2".to_string(), 2)];
    let result = cortex_retrieval::search::rrf_fusion::fuse(Some(&list), None, None, &memories, 60);
    assert_eq!(result.len(), 2);
    // m1 at rank 1 should score higher than m2 at rank 2.
    assert!(result[0].rrf_score >= result[1].rrf_score);
}

#[test]
fn rrf_fuse_multiple_lists_boosts_overlap() {
    let m1 = make_memory("m1", "overlap", MemoryType::Semantic);
    let m2 = make_memory("m2", "unique", MemoryType::Semantic);
    let mut memories = HashMap::new();
    memories.insert("m1".to_string(), m1);
    memories.insert("m2".to_string(), m2);

    let list1 = vec![("m1".to_string(), 1), ("m2".to_string(), 2)];
    let list2 = vec![("m1".to_string(), 1)]; // m1 appears in both.
    let result =
        cortex_retrieval::search::rrf_fusion::fuse(Some(&list1), Some(&list2), None, &memories, 60);
    assert_eq!(result[0].memory.id, "m1"); // m1 should be ranked first.
}

// ─── Scorer ──────────────────────────────────────────────────────────────────

#[test]
fn scorer_default_weights_sum_to_one() {
    let w = cortex_retrieval::ranking::scorer::ScorerWeights::default();
    let sum = w.semantic_similarity + w.keyword_match + w.file_proximity
        + w.pattern_alignment + w.recency + w.confidence + w.importance + w.intent_type_match
        + w.evidence_freshness + w.epistemic_status;
    assert!((sum - 1.0).abs() < 0.01);
}

#[test]
fn scorer_scores_candidates() {
    use cortex_retrieval::search::rrf_fusion::RrfCandidate;
    let m1 = make_memory("s1", "test memory", MemoryType::Semantic);
    let candidates = vec![RrfCandidate {
        memory: m1,
        rrf_score: 0.5,
        fts5_rank: Some(0),
        vector_rank: Some(0),
        entity_rank: None,
    }];
    let weights = cortex_retrieval::ranking::scorer::ScorerWeights::default();
    let intent_engine = IntentEngine::new();
    let scored = cortex_retrieval::ranking::scorer::score(
        &candidates,
        Intent::Investigate,
        &[],
        &intent_engine,
        &weights,
    );
    assert_eq!(scored.len(), 1);
    assert!(scored[0].score > 0.0);
}

#[test]
fn scorer_file_proximity_boosts_score() {
    use cortex_retrieval::search::rrf_fusion::RrfCandidate;
    let mut m1 = make_memory("fp1", "file linked", MemoryType::PatternRationale);
    m1.linked_files = vec![cortex_core::memory::links::FileLink {
        file_path: "src/auth.rs".to_string(),
        line_start: Some(1),
        line_end: Some(10),
        content_hash: None,
    }];
    let m2 = make_memory("fp2", "no files", MemoryType::Semantic);

    let candidates = vec![
        RrfCandidate {
            memory: m1,
            rrf_score: 0.5,
            fts5_rank: Some(0),
            vector_rank: Some(0),
            entity_rank: None,
        },
        RrfCandidate {
            memory: m2,
            rrf_score: 0.5,
            fts5_rank: None,
            vector_rank: Some(1),
            entity_rank: None,
        },
    ];
    let weights = cortex_retrieval::ranking::scorer::ScorerWeights::default();
    let intent_engine = IntentEngine::new();
    let scored = cortex_retrieval::ranking::scorer::score(
        &candidates,
        Intent::Investigate,
        &["src/auth.rs".to_string()],
        &intent_engine,
        &weights,
    );
    // The file-linked memory should score higher.
    let fp1_score = scored.iter().find(|s| s.memory.id == "fp1").unwrap().score;
    let fp2_score = scored.iter().find(|s| s.memory.id == "fp2").unwrap().score;
    assert!(fp1_score > fp2_score);
}

// ─── Deduplication ───────────────────────────────────────────────────────────

#[test]
fn dedup_removes_sent_ids() {
    use cortex_retrieval::ranking::scorer::ScoredCandidate;
    let candidates = vec![
        ScoredCandidate {
            memory: make_memory("d1", "a", MemoryType::Semantic),
            score: 0.9,
            rrf_score: 0.5,
        },
        ScoredCandidate {
            memory: make_memory("d2", "b", MemoryType::Semantic),
            score: 0.8,
            rrf_score: 0.4,
        },
    ];
    let result =
        cortex_retrieval::ranking::deduplication::deduplicate(candidates, &["d1".to_string()]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].memory.id, "d2");
}

#[test]
fn dedup_removes_duplicate_ids() {
    use cortex_retrieval::ranking::scorer::ScoredCandidate;
    let candidates = vec![
        ScoredCandidate {
            memory: make_memory("d3", "a", MemoryType::Semantic),
            score: 0.9,
            rrf_score: 0.5,
        },
        ScoredCandidate {
            memory: make_memory("d3", "a dup", MemoryType::Semantic),
            score: 0.7,
            rrf_score: 0.3,
        },
    ];
    let result = cortex_retrieval::ranking::deduplication::deduplicate(candidates, &[]);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].score, 0.9); // Keeps highest-scored.
}

// ─── Reranker ────────────────────────────────────────────────────────────────

#[test]
fn reranker_passthrough() {
    use cortex_retrieval::ranking::scorer::ScoredCandidate;
    let candidates = vec![ScoredCandidate {
        memory: make_memory("rr1", "a", MemoryType::Semantic),
        score: 0.9,
        rrf_score: 0.5,
    }];
    // Without the `reranker` feature, rerank is a no-op passthrough.
    let result = cortex_retrieval::ranking::reranker::rerank(candidates, 10);
    assert_eq!(result.len(), 1);
}

// ─── Intent Engine ───────────────────────────────────────────────────────────

#[test]
fn intent_engine_classify_fix_bug() {
    let engine = IntentEngine::new();
    let ctx = RetrievalContext {
        focus: "fix the null pointer bug in auth".to_string(),
        intent: None,
        active_files: vec!["src/auth.rs".to_string()],
        sent_ids: vec![],
        budget: 2000,
    };
    let intent = engine.classify(&ctx);
    assert_eq!(intent, Intent::FixBug);
}

#[test]
fn intent_engine_boost_returns_positive() {
    let engine = IntentEngine::new();
    let boost = engine.boost(Intent::FixBug, MemoryType::PatternRationale);
    assert!(boost >= 0.0);
}

#[test]
fn intent_engine_default() {
    let engine = IntentEngine::default();
    let boost = engine.boost(Intent::Investigate, MemoryType::Semantic);
    assert!(boost >= 0.0);
}

// ─── Why Aggregator ──────────────────────────────────────────────────────────

#[test]
fn aggregator_empty() {
    let result = cortex_retrieval::why::aggregator::aggregate(vec![]);
    assert!(result.is_empty());
}

#[test]
fn aggregator_dedup_same_message() {
    use cortex_retrieval::why::aggregator::WarningSeverity;
    let warnings = vec![
        (
            "Stale pattern".to_string(),
            WarningSeverity::Low,
            "m1".to_string(),
        ),
        (
            "Stale pattern".to_string(),
            WarningSeverity::High,
            "m2".to_string(),
        ),
    ];
    let result = cortex_retrieval::why::aggregator::aggregate(warnings);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].severity, WarningSeverity::High); // Keeps highest.
    assert_eq!(result[0].source_memory_ids.len(), 2);
}

#[test]
fn aggregator_sorts_by_severity() {
    use cortex_retrieval::why::aggregator::WarningSeverity;
    let warnings = vec![
        (
            "Low warning".to_string(),
            WarningSeverity::Low,
            "m1".to_string(),
        ),
        (
            "Critical warning".to_string(),
            WarningSeverity::Critical,
            "m2".to_string(),
        ),
        (
            "Medium warning".to_string(),
            WarningSeverity::Medium,
            "m3".to_string(),
        ),
    ];
    let result = cortex_retrieval::why::aggregator::aggregate(warnings);
    assert_eq!(result[0].severity, WarningSeverity::Critical);
    assert_eq!(result.last().unwrap().severity, WarningSeverity::Low);
}

// ─── Generation: Provenance ──────────────────────────────────────────────────

#[test]
fn provenance_empty_context() {
    use cortex_core::models::GenerationContext;
    let ctx = GenerationContext {
        allocations: vec![],
        total_budget: 2000,
        total_tokens: 0,
    };
    let records = cortex_retrieval::generation::provenance::generate_provenance(&ctx);
    assert!(records.is_empty());
}

#[test]
fn provenance_generates_tags() {
    use cortex_core::memory::Importance;
    use cortex_core::models::{BudgetAllocation, CompressedMemory, GenerationContext};
    let ctx = GenerationContext {
        allocations: vec![BudgetAllocation {
            category: "patterns".to_string(),
            percentage: 0.25,
            memories: vec![CompressedMemory {
                memory_id: "m1".to_string(),
                memory_type: MemoryType::PatternRationale,
                text: "Use dependency injection".to_string(),
                token_count: 10,
                level: 0,
                importance: Importance::Normal,
                relevance_score: 0.9,
            }],
            tokens_used: 10,
        }],
        total_budget: 2000,
        total_tokens: 10,
    };
    let records = cortex_retrieval::generation::provenance::generate_provenance(&ctx);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].tag, "[drift:pattern]");
}

#[test]
fn provenance_inline_comments() {
    use cortex_core::memory::Importance;
    use cortex_core::models::{BudgetAllocation, CompressedMemory, GenerationContext};
    let ctx = GenerationContext {
        allocations: vec![BudgetAllocation {
            category: "tribal".to_string(),
            percentage: 0.15,
            memories: vec![CompressedMemory {
                memory_id: "m2".to_string(),
                memory_type: MemoryType::Tribal,
                text: "Always review auth changes".to_string(),
                token_count: 8,
                level: 0,
                importance: Importance::Normal,
                relevance_score: 0.85,
            }],
            tokens_used: 8,
        }],
        total_budget: 2000,
        total_tokens: 8,
    };
    let comments = cortex_retrieval::generation::provenance::generate_inline_comments(&ctx);
    assert!(comments.contains("[drift:tribal]"));
}

// ─── Ranking Pipeline ────────────────────────────────────────────────────────

#[test]
fn ranking_pipeline_default() {
    let pipeline = cortex_retrieval::RankingPipeline::default();
    // Just ensure it doesn't panic.
    let _ = pipeline;
}

// ─── Issue 1: RRF Provenance & Real Keyword Factor ──────────────────────────

#[test]
fn rrf_fuse_preserves_fts5_rank() {
    let m1 = make_memory("m1", "first", MemoryType::Semantic);
    let mut memories = HashMap::new();
    memories.insert("m1".to_string(), m1);

    let fts5 = vec![("m1".to_string(), 3)];
    let result = cortex_retrieval::search::rrf_fusion::fuse(Some(&fts5), None, None, &memories, 60);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].fts5_rank, Some(3));
    assert_eq!(result[0].vector_rank, None);
    assert_eq!(result[0].entity_rank, None);
}

#[test]
fn rrf_fuse_preserves_all_source_ranks() {
    let m1 = make_memory("m1", "multi-source", MemoryType::Semantic);
    let mut memories = HashMap::new();
    memories.insert("m1".to_string(), m1);

    let fts5 = vec![("m1".to_string(), 0)];
    let vector = vec![("m1".to_string(), 2)];
    let entity = vec![("m1".to_string(), 5)];
    let result = cortex_retrieval::search::rrf_fusion::fuse(
        Some(&fts5),
        Some(&vector),
        Some(&entity),
        &memories,
        60,
    );
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].fts5_rank, Some(0));
    assert_eq!(result[0].vector_rank, Some(2));
    assert_eq!(result[0].entity_rank, Some(5));
    // Score should be sum of 3 RRF contributions.
    assert!(result[0].rrf_score > 1.0 / 61.0); // More than a single source.
}

#[test]
fn rrf_fuse_partial_source_coverage() {
    let m1 = make_memory("m1", "fts only", MemoryType::Semantic);
    let m2 = make_memory("m2", "vector only", MemoryType::Semantic);
    let mut memories = HashMap::new();
    memories.insert("m1".to_string(), m1);
    memories.insert("m2".to_string(), m2);

    let fts5 = vec![("m1".to_string(), 0)];
    let vector = vec![("m2".to_string(), 0)];
    let result =
        cortex_retrieval::search::rrf_fusion::fuse(Some(&fts5), Some(&vector), None, &memories, 60);
    assert_eq!(result.len(), 2);

    let m1_candidate = result.iter().find(|c| c.memory.id == "m1").unwrap();
    let m2_candidate = result.iter().find(|c| c.memory.id == "m2").unwrap();

    assert_eq!(m1_candidate.fts5_rank, Some(0));
    assert_eq!(m1_candidate.vector_rank, None);
    assert_eq!(m2_candidate.fts5_rank, None);
    assert_eq!(m2_candidate.vector_rank, Some(0));
}

#[test]
fn scorer_keyword_factor_is_independent_of_semantic() {
    use cortex_retrieval::search::rrf_fusion::RrfCandidate;

    // Two candidates with same RRF score but different FTS5 ranks.
    let m1 = make_memory("kw1", "has fts5 match", MemoryType::Semantic);
    let m2 = make_memory("kw2", "no fts5 match", MemoryType::Semantic);

    let candidates = vec![
        RrfCandidate {
            memory: m1,
            rrf_score: 0.5,
            fts5_rank: Some(0),
            vector_rank: None,
            entity_rank: None,
        },
        RrfCandidate {
            memory: m2,
            rrf_score: 0.5,
            fts5_rank: None,
            vector_rank: Some(0),
            entity_rank: None,
        },
    ];

    let weights = cortex_retrieval::ranking::scorer::ScorerWeights::default();
    let intent_engine = IntentEngine::new();
    let scored = cortex_retrieval::ranking::scorer::score(
        &candidates,
        Intent::Investigate,
        &[],
        &intent_engine,
        &weights,
    );

    let kw1 = scored.iter().find(|s| s.memory.id == "kw1").unwrap();
    let kw2 = scored.iter().find(|s| s.memory.id == "kw2").unwrap();

    // The candidate with FTS5 rank should score differently from the one without,
    // proving the keyword factor is now independent.
    assert_ne!(
        (kw1.score * 1000.0).round(),
        (kw2.score * 1000.0).round(),
        "keyword factor should create score difference"
    );
}

#[test]
fn scorer_weights_still_sum_to_one() {
    let w = cortex_retrieval::ranking::scorer::ScorerWeights::default();
    let sum = w.semantic_similarity
        + w.keyword_match
        + w.file_proximity
        + w.pattern_alignment
        + w.recency
        + w.confidence
        + w.importance
        + w.intent_type_match
        + w.evidence_freshness
        + w.epistemic_status;
    assert!(
        (sum - 1.0).abs() < 0.01,
        "weights must sum to 1.0, got {sum}"
    );
}

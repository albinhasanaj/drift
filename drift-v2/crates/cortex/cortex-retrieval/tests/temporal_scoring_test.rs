//! Phase D3 tests — TTD3-01 through TTD3-04: Temporal scoring factors in retrieval.

use std::collections::HashMap;

use chrono::Utc;
use cortex_core::intent::Intent;
use cortex_core::memory::{BaseMemory, Confidence, Importance, MemoryType, TypedContent};
use cortex_core::models::EpistemicStatus;
use cortex_retrieval::intent::IntentEngine;
use cortex_retrieval::ranking::scorer::{
    self, ScorerWeights, TemporalScoringContext, epistemic_status_score,
};
use cortex_retrieval::search::rrf_fusion::RrfCandidate;

fn make_memory(id: &str, summary: &str) -> BaseMemory {
    let content = TypedContent::Core(cortex_core::memory::types::CoreContent {
        project_name: String::new(),
        description: summary.to_string(),
        metadata: serde_json::Value::Null,
    });
    let content_hash = BaseMemory::compute_content_hash(&content).unwrap();
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Semantic,
        content,
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance: Importance::Normal,
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
        content_hash,
    }
}

fn make_candidate(memory: BaseMemory) -> RrfCandidate {
    RrfCandidate {
        memory,
        rrf_score: 0.5,
        fts5_rank: None,
        vector_rank: None,
        entity_rank: None,
    }
}

// ─── TTD3-01: Retrieval scorer includes temporal factors ─────────────────────

#[test]
fn ttd3_01_scorer_includes_temporal_factors() {
    let m = make_memory("m1", "test memory");
    let candidates = vec![make_candidate(m)];
    let intent_engine = IntentEngine::new();
    let weights = ScorerWeights::default();

    // Score without temporal context.
    let scored_without = scorer::score(
        &candidates,
        Intent::Investigate,
        &[],
        &intent_engine,
        &weights,
    );

    // Score with temporal context (high freshness + Verified status).
    let mut freshness_map = HashMap::new();
    freshness_map.insert("m1".to_string(), 1.0);
    let mut epistemic_map = HashMap::new();
    epistemic_map.insert(
        "m1".to_string(),
        EpistemicStatus::Verified {
            verified_by: vec!["user".into()],
            verified_at: Utc::now(),
            evidence_refs: vec![],
        },
    );
    let temporal_ctx = TemporalScoringContext {
        evidence_freshness: freshness_map,
        epistemic_statuses: epistemic_map,
    };

    let scored_with = scorer::score_with_temporal(
        &candidates,
        Intent::Investigate,
        &[],
        &intent_engine,
        &weights,
        Some(&temporal_ctx),
    );

    // Scores should differ because temporal factors contribute.
    assert!(
        (scored_with[0].score - scored_without[0].score).abs() > f64::EPSILON,
        "Score with temporal factors ({}) should differ from without ({})",
        scored_with[0].score,
        scored_without[0].score
    );
}

// ─── TTD3-02: Verified memory scores higher than Conjecture ──────────────────

#[test]
fn ttd3_02_verified_scores_higher_than_conjecture() {
    let m1 = make_memory("verified", "same content");
    let m2 = make_memory("conjecture", "same content");
    let candidates = vec![make_candidate(m1), make_candidate(m2)];
    let intent_engine = IntentEngine::new();
    let weights = ScorerWeights::default();

    let mut freshness_map = HashMap::new();
    freshness_map.insert("verified".to_string(), 0.8);
    freshness_map.insert("conjecture".to_string(), 0.8);

    let mut epistemic_map = HashMap::new();
    epistemic_map.insert(
        "verified".to_string(),
        EpistemicStatus::Verified {
            verified_by: vec!["user".into()],
            verified_at: Utc::now(),
            evidence_refs: vec![],
        },
    );
    epistemic_map.insert(
        "conjecture".to_string(),
        EpistemicStatus::Conjecture {
            source: "agent".into(),
            created_at: Utc::now(),
        },
    );

    let temporal_ctx = TemporalScoringContext {
        evidence_freshness: freshness_map,
        epistemic_statuses: epistemic_map,
    };

    let scored = scorer::score_with_temporal(
        &candidates,
        Intent::Investigate,
        &[],
        &intent_engine,
        &weights,
        Some(&temporal_ctx),
    );

    let verified_score = scored.iter().find(|s| s.memory.id == "verified").unwrap().score;
    let conjecture_score = scored.iter().find(|s| s.memory.id == "conjecture").unwrap().score;

    assert!(
        verified_score > conjecture_score,
        "Verified ({}) should score higher than Conjecture ({})",
        verified_score,
        conjecture_score
    );
}

// ─── TTD3-03: Evidence freshness affects ranking ─────────────────────────────

#[test]
fn ttd3_03_fresh_evidence_ranks_above_stale() {
    let m_fresh = make_memory("fresh", "same content");
    let m_stale = make_memory("stale", "same content");
    let candidates = vec![make_candidate(m_fresh), make_candidate(m_stale)];
    let intent_engine = IntentEngine::new();
    let weights = ScorerWeights::default();

    let mut freshness_map = HashMap::new();
    freshness_map.insert("fresh".to_string(), 1.0);
    freshness_map.insert("stale".to_string(), 0.1);

    // Same epistemic status for both.
    let mut epistemic_map = HashMap::new();
    epistemic_map.insert(
        "fresh".to_string(),
        EpistemicStatus::Provisional {
            evidence_count: 3,
            last_validated: Utc::now(),
        },
    );
    epistemic_map.insert(
        "stale".to_string(),
        EpistemicStatus::Provisional {
            evidence_count: 3,
            last_validated: Utc::now(),
        },
    );

    let temporal_ctx = TemporalScoringContext {
        evidence_freshness: freshness_map,
        epistemic_statuses: epistemic_map,
    };

    let scored = scorer::score_with_temporal(
        &candidates,
        Intent::Investigate,
        &[],
        &intent_engine,
        &weights,
        Some(&temporal_ctx),
    );

    let fresh_score = scored.iter().find(|s| s.memory.id == "fresh").unwrap().score;
    let stale_score = scored.iter().find(|s| s.memory.id == "stale").unwrap().score;

    assert!(
        fresh_score > stale_score,
        "Fresh evidence ({}) should rank above stale evidence ({})",
        fresh_score,
        stale_score
    );
}

// ─── TTD3-04: Weights sum to 1.0 ────────────────────────────────────────────

#[test]
fn ttd3_04_weights_sum_to_one() {
    let w = ScorerWeights::default();
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
        (sum - 1.0).abs() < f64::EPSILON * 100.0,
        "All 10 weights must sum to 1.0, got {}",
        sum
    );

    // Also verify the epistemic status score mapping.
    assert!((epistemic_status_score(&EpistemicStatus::Verified {
        verified_by: vec![],
        verified_at: Utc::now(),
        evidence_refs: vec![],
    }) - 1.0).abs() < f64::EPSILON);

    assert!((epistemic_status_score(&EpistemicStatus::Provisional {
        evidence_count: 1,
        last_validated: Utc::now(),
    }) - 0.7).abs() < f64::EPSILON);

    assert!((epistemic_status_score(&EpistemicStatus::Conjecture {
        source: "test".into(),
        created_at: Utc::now(),
    }) - 0.4).abs() < f64::EPSILON);

    assert!((epistemic_status_score(&EpistemicStatus::Stale {
        was_verified_at: Utc::now(),
        staleness_detected_at: Utc::now(),
        reason: "test".into(),
    }) - 0.2).abs() < f64::EPSILON);
}

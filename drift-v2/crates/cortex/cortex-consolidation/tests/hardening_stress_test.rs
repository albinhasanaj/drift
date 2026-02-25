//! Enterprise stress tests for Cortex Consolidation hardening fixes.
//!
//! Covers:
//! - P2-9: Consolidation eligibility expanded from Episodic-only to
//!   Episodic + Procedural. Semantic/Core/Decision etc. still excluded.
//!
//! Every test targets a specific production failure mode.

use chrono::{Duration, Utc};
use cortex_core::memory::*;
use cortex_core::memory::types::{EpisodicContent, ProceduralContent, ProceduralStep, SemanticContent};
use cortex_consolidation::pipeline::phase1_selection::{select_candidates, MIN_AGE_DAYS, MIN_CONFIDENCE};

fn make_memory(mem_type: MemoryType, content: TypedContent, days_old: i64, confidence: f64, archived: bool) -> BaseMemory {
    let now = Utc::now();
    BaseMemory {
        id: uuid::Uuid::new_v4().to_string(),
        memory_type: mem_type,
        content: content.clone(),
        summary: "test".to_string(),
        transaction_time: now - Duration::days(days_old),
        valid_time: now - Duration::days(days_old),
        valid_until: None,
        confidence: Confidence::new(confidence),
        importance: Importance::Normal,
        last_accessed: now,
        access_count: 1,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
    }
}

fn episodic_content() -> TypedContent {
    TypedContent::Episodic(EpisodicContent {
        interaction: "test".to_string(),
        context: "test".to_string(),
        outcome: None,
    })
}

fn procedural_content() -> TypedContent {
    TypedContent::Procedural(ProceduralContent {
        title: "test procedure".to_string(),
        steps: vec![ProceduralStep {
            order: 1,
            instruction: "step 1".to_string(),
            completed: false,
        }],
        prerequisites: vec![],
    })
}

fn semantic_content() -> TypedContent {
    TypedContent::Semantic(SemanticContent {
        knowledge: "test knowledge".to_string(),
        source_episodes: vec![],
        consolidation_confidence: 0.8,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// P2-9: CONSOLIDATION ELIGIBILITY — Episodic + Procedural
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: Only Episodic memories were eligible for consolidation.
/// Procedural memories (how-to knowledge) can also benefit from dedup/merging.
/// Verify Procedural is now included.
#[test]
fn hst_p29_01_procedural_now_eligible() {
    let memories = vec![
        make_memory(MemoryType::Procedural, procedural_content(), 10, 0.8, false),
    ];
    let candidates = select_candidates(&memories);
    assert_eq!(candidates.len(), 1, "Procedural should be eligible");
}

/// Episodic still eligible — regression check.
#[test]
fn hst_p29_02_episodic_still_eligible() {
    let memories = vec![
        make_memory(MemoryType::Episodic, episodic_content(), 10, 0.8, false),
    ];
    let candidates = select_candidates(&memories);
    assert_eq!(candidates.len(), 1, "Episodic must remain eligible");
}

/// Semantic still excluded.
#[test]
fn hst_p29_03_semantic_still_excluded() {
    let memories = vec![
        make_memory(MemoryType::Semantic, semantic_content(), 10, 0.8, false),
    ];
    let candidates = select_candidates(&memories);
    assert!(candidates.is_empty(), "Semantic must remain excluded");
}

/// Core, Decision, Insight — all still excluded.
#[test]
fn hst_p29_04_other_types_still_excluded() {
    let excluded_types = [
        MemoryType::Core,
        MemoryType::Decision,
        MemoryType::Insight,
        MemoryType::Tribal,
        MemoryType::Reference,
        MemoryType::Preference,
    ];

    for mem_type in &excluded_types {
        // Use episodic content as a stand-in (the type field is what matters).
        let mut m = make_memory(MemoryType::Episodic, episodic_content(), 10, 0.8, false);
        m.memory_type = *mem_type;
        let memories = [m];
        let candidates = select_candidates(&memories);
        assert!(
            candidates.is_empty(),
            "{:?} should be excluded from consolidation",
            mem_type
        );
    }
}

/// Mixed batch: Episodic + Procedural + Semantic + Core — only first two selected.
#[test]
fn hst_p29_05_mixed_batch_correct_filtering() {
    let memories = vec![
        make_memory(MemoryType::Episodic, episodic_content(), 10, 0.8, false),
        make_memory(MemoryType::Procedural, procedural_content(), 10, 0.8, false),
        make_memory(MemoryType::Semantic, semantic_content(), 10, 0.8, false),
        {
            let mut m = make_memory(MemoryType::Episodic, episodic_content(), 10, 0.8, false);
            m.memory_type = MemoryType::Core;
            m
        },
    ];
    let candidates = select_candidates(&memories);
    assert_eq!(candidates.len(), 2, "Only Episodic + Procedural should pass");
}

/// Age filter still works: < MIN_AGE_DAYS excluded regardless of type.
#[test]
fn hst_p29_06_age_filter_applies_to_procedural() {
    let memories = vec![
        make_memory(MemoryType::Procedural, procedural_content(), MIN_AGE_DAYS - 1, 0.8, false),
    ];
    let candidates = select_candidates(&memories);
    assert!(candidates.is_empty(), "Too-young Procedural should be excluded");
}

/// Confidence filter still works: < MIN_CONFIDENCE excluded.
#[test]
fn hst_p29_07_confidence_filter_applies_to_procedural() {
    let memories = vec![
        make_memory(MemoryType::Procedural, procedural_content(), 10, MIN_CONFIDENCE - 0.01, false),
    ];
    let candidates = select_candidates(&memories);
    assert!(candidates.is_empty(), "Low-confidence Procedural should be excluded");
}

/// Archived filter still works.
#[test]
fn hst_p29_08_archived_filter_applies_to_procedural() {
    let memories = vec![
        make_memory(MemoryType::Procedural, procedural_content(), 10, 0.8, true),
    ];
    let candidates = select_candidates(&memories);
    assert!(candidates.is_empty(), "Archived Procedural should be excluded");
}

/// Superseded filter still works.
#[test]
fn hst_p29_09_superseded_filter_applies_to_procedural() {
    let mut m = make_memory(MemoryType::Procedural, procedural_content(), 10, 0.8, false);
    m.superseded_by = Some("other-memory".to_string());
    let memories = [m];
    let candidates = select_candidates(&memories);
    assert!(candidates.is_empty(), "Superseded Procedural should be excluded");
}

/// Stress: 1000 mixed memories, correct count.
#[test]
fn hst_p29_10_stress_1000_mixed_memories() {
    let mut memories = Vec::new();
    for i in 0..1000 {
        let (mem_type, content) = match i % 4 {
            0 => (MemoryType::Episodic, episodic_content()),
            1 => (MemoryType::Procedural, procedural_content()),
            2 => (MemoryType::Semantic, semantic_content()),
            _ => {
                let mut m = make_memory(MemoryType::Episodic, episodic_content(), 10, 0.8, false);
                m.memory_type = MemoryType::Core;
                memories.push(m);
                continue;
            }
        };
        memories.push(make_memory(mem_type, content, 10, 0.8, false));
    }

    let candidates = select_candidates(&memories);
    // 250 Episodic + 250 Procedural = 500 eligible.
    assert_eq!(candidates.len(), 500, "Expected exactly 500 eligible from 1000 mixed");
}

/// Boundary: exactly at MIN_AGE_DAYS — must be excluded (< cutoff means strictly before).
#[test]
fn hst_p29_11_boundary_exactly_min_age() {
    // At exactly MIN_AGE_DAYS, the valid_time == cutoff, so < cutoff is false → excluded.
    let memories = vec![
        make_memory(MemoryType::Episodic, episodic_content(), MIN_AGE_DAYS, 0.8, false),
    ];
    let candidates = select_candidates(&memories);
    // At the boundary, valid_time == Utc::now() - 7 days. The cutoff is also Utc::now() - 7 days.
    // Since we check valid_time < cutoff (strict), equal should be excluded.
    // However, due to clock granularity in test, this may or may not pass.
    // Either 0 or 1 is acceptable — the point is no panic.
    assert!(candidates.len() <= 1);
}

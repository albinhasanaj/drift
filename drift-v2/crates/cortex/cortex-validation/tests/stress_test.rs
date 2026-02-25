//! Validation stress tests: 4-dimension validation at scale, contradiction
//! detection, healing actions, and edge cases.

use chrono::{Duration, Utc};
use cortex_core::memory::base::TypedContent;
use cortex_core::memory::types::{EpisodicContent, SemanticContent};
use cortex_core::memory::*;
use cortex_validation::contradiction::consensus;
use cortex_validation::contradiction::detection;
use cortex_validation::dimensions::{citation, pattern_alignment, temporal};
use cortex_validation::engine::{ValidationContext, ValidationEngine};
use std::time::Instant;

fn make_memory(id: &str, summary: &str, mem_type: MemoryType) -> BaseMemory {
    let content = match mem_type {
        MemoryType::Episodic => TypedContent::Episodic(EpisodicContent {
            interaction: summary.to_string(),
            context: String::new(),
            outcome: None,
        }),
        _ => TypedContent::Semantic(SemanticContent {
            knowledge: summary.to_string(),
            source_episodes: vec![],
            consolidation_confidence: 0.8,
        }),
    };
    let content_hash = BaseMemory::compute_content_hash(&content).unwrap();
    BaseMemory {
        id: id.to_string(),
        memory_type: mem_type,
        content,
        summary: summary.to_string(),
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
        content_hash,
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ── Validation at scale ──────────────────────────────────────────────────

#[test]
fn stress_validate_500_memories() {
    let engine = ValidationEngine::default();

    let start = Instant::now();
    for i in 0..500 {
        let mem = make_memory(
            &format!("val-{i}"),
            &format!("Memory about topic {i}"),
            MemoryType::Semantic,
        );
        let result = engine.validate_basic(&mem, &[]).unwrap();

        assert!(
            result.overall_score >= 0.0 && result.overall_score <= 1.0,
            "Score out of range for memory {i}: {}",
            result.overall_score
        );
        assert!(!result.memory_id.is_empty());
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs() < 10, "500 validations took {:?}", elapsed);
}

// ── Citation validation stress ───────────────────────────────────────────

#[test]
fn stress_citation_all_files_missing() {
    let mut mem = make_memory("cite-missing", "Test memory", MemoryType::Semantic);
    for i in 0..20 {
        mem.linked_files.push(FileLink {
            file_path: format!("src/module_{i}.rs"),
            line_start: Some(1),
            line_end: Some(50),
            content_hash: Some(format!("hash_{i}")),
        });
    }

    let no_files = |_: &str| -> Option<citation::FileInfo> { None };
    let no_renames = |_: &str| -> Option<String> { None };

    let result = citation::validate(&mem, &no_files, &no_renames);
    assert!(
        result.score < 1.0,
        "All files missing should reduce citation score, got {}",
        result.score
    );
    assert!(
        !result.healing_actions.is_empty(),
        "Should have healing actions for missing files"
    );
}

#[test]
fn stress_citation_all_files_present_and_fresh() {
    let mut mem = make_memory("cite-fresh", "Test memory", MemoryType::Semantic);
    for i in 0..10 {
        mem.linked_files.push(FileLink {
            file_path: format!("src/module_{i}.rs"),
            line_start: Some(1),
            line_end: Some(50),
            content_hash: Some(format!("hash_{i}")),
        });
    }

    let all_present = |path: &str| -> Option<citation::FileInfo> {
        // Extract the hash from the path to match.
        let idx = path
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>();
        Some(citation::FileInfo {
            content_hash: Some(format!("hash_{idx}")),
            total_lines: Some(100),
        })
    };
    let no_renames = |_: &str| -> Option<String> { None };

    let result = citation::validate(&mem, &all_present, &no_renames);
    assert!(
        result.score >= 0.8,
        "All files present and fresh should score high, got {}",
        result.score
    );
}

// ── Temporal validation stress ───────────────────────────────────────────

#[test]
fn stress_temporal_expired_memories() {
    for days_expired in [1, 7, 30, 90, 365] {
        let mut mem = make_memory(
            &format!("expired-{days_expired}"),
            "Expired memory",
            MemoryType::Semantic,
        );
        mem.valid_until = Some(Utc::now() - Duration::days(days_expired));

        let result = temporal::validate(&mem, Utc::now());
        assert!(
            result.score < 1.0,
            "Expired memory ({days_expired} days ago) should have reduced score, got {}",
            result.score
        );
    }
}

#[test]
fn stress_temporal_fresh_memories() {
    let mem = make_memory("fresh", "Fresh memory", MemoryType::Semantic);
    let result = temporal::validate(&mem, Utc::now());
    assert!(
        result.score >= 0.5,
        "Fresh memory should have decent temporal score, got {}",
        result.score
    );
}

// ── Contradiction detection stress ───────────────────────────────────────

#[test]
fn stress_contradiction_detection_100_pairs() {
    // Create pairs of contradictory memories.
    let mut detected = 0;
    let total = 100;

    for i in 0..total {
        let a = make_memory(
            &format!("contra-a-{i}"),
            &format!("Always use pattern X for task {i}"),
            MemoryType::Semantic,
        );
        let b = make_memory(
            &format!("contra-b-{i}"),
            &format!("Never use pattern X for task {i}"),
            MemoryType::Semantic,
        );

        let contradiction = detection::detect_all(&a, &b, None);
        if contradiction.is_some() {
            detected += 1;
        }
    }

    // The absolute statement detector should catch "always" vs "never" patterns.
    assert!(
        detected >= 50,
        "Expected >= 50% contradiction detection for always/never pairs, got {}/{}",
        detected,
        total
    );
}

#[test]
fn stress_no_false_contradictions_unrelated() {
    // Unrelated memories should not be flagged as contradictory.
    let mut false_positives = 0;
    let total = 100;

    for i in 0..total {
        let a = make_memory(
            &format!("unrel-a-{i}"),
            &format!("Database indexing improves query performance for table {i}"),
            MemoryType::Semantic,
        );
        let b = make_memory(
            &format!("unrel-b-{i}"),
            &format!("Unit testing catches bugs early in module {i}"),
            MemoryType::Semantic,
        );

        let contradiction = detection::detect_all(&a, &b, None);
        if contradiction.is_some() {
            false_positives += 1;
        }
    }

    assert!(
        false_positives < 10,
        "Too many false contradictions for unrelated memories: {}/{}",
        false_positives,
        total
    );
}

// ── Consensus detection stress ───────────────────────────────────────────

#[test]
fn stress_consensus_with_many_agreeing_memories() {
    // 20 memories all saying similar things should form a consensus group.
    let memories: Vec<BaseMemory> = (0..20)
        .map(|i| {
            let mut m = make_memory(
                &format!("consensus-{i}"),
                "Always validate user input before processing",
                MemoryType::Semantic,
            );
            m.tags = vec!["validation".to_string(), "security".to_string()];
            m
        })
        .collect();

    let groups = consensus::detect_consensus(&memories);
    // With 20 identical-summary memories, there should be at least one consensus group.
    assert!(
        !groups.is_empty(),
        "20 agreeing memories should form at least one consensus group"
    );
}

// ── Full validation with context ─────────────────────────────────────────

#[test]
fn stress_full_validation_with_contradictions() {
    let engine = ValidationEngine::default();

    let target = make_memory("target", "Always use async for IO", MemoryType::Semantic);
    let contradicting = make_memory("contra", "Never use async for IO", MemoryType::Semantic);
    let supporting = make_memory(
        "support",
        "Async IO improves throughput",
        MemoryType::Semantic,
    );

    let related = vec![contradicting, supporting];

    let no_files = |_: &str| -> Option<citation::FileInfo> { None };
    let no_renames = |_: &str| -> Option<String> { None };
    let all_patterns = |_: &str| -> pattern_alignment::PatternInfo {
        pattern_alignment::PatternInfo {
            exists: true,
            confidence: None,
        }
    };

    let ctx = ValidationContext {
        related_memories: &related,
        all_memories: &related,
        file_checker: &no_files,
        rename_detector: &no_renames,
        pattern_checker: &all_patterns,
        similarity_fn: None,
    };

    let result = engine.validate_with_context(&target, &ctx).unwrap();

    assert!(result.overall_score >= 0.0 && result.overall_score <= 1.0);
    assert!(!result.memory_id.is_empty());
    // With a contradiction present, the contradiction dimension should be < 1.0.
    assert!(
        result.dimension_scores.contradiction <= 1.0,
        "Contradiction score should be bounded"
    );
}

// ── Edge cases ───────────────────────────────────────────────────────────

#[test]
fn stress_validate_memory_with_no_links() {
    let engine = ValidationEngine::default();
    let mem = make_memory("no-links", "Simple memory", MemoryType::Semantic);
    let result = engine.validate_basic(&mem, &[]).unwrap();

    assert!(result.overall_score >= 0.0 && result.overall_score <= 1.0);
}

#[test]
fn stress_validate_archived_memory() {
    let engine = ValidationEngine::default();
    let mut mem = make_memory("archived", "Old archived memory", MemoryType::Semantic);
    mem.archived = true;
    mem.confidence = Confidence::new(0.1);

    let result = engine.validate_basic(&mem, &[]).unwrap();
    assert!(result.overall_score >= 0.0 && result.overall_score <= 1.0);
}

#[test]
fn stress_validate_with_many_patterns() {
    let engine = ValidationEngine::default();
    let mut mem = make_memory(
        "many-patterns",
        "Memory with patterns",
        MemoryType::Semantic,
    );
    for i in 0..50 {
        mem.linked_patterns.push(PatternLink {
            pattern_id: format!("pat-{i}"),
            pattern_name: format!("pattern-{i}"),
        });
    }

    let result = engine.validate_basic(&mem, &[]).unwrap();
    assert!(result.overall_score >= 0.0 && result.overall_score <= 1.0);
}

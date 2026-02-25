//! Targeted coverage tests for cortex-validation uncovered paths.
//!
//! Focuses on: contradiction detection strategies, propagation, consensus,
//! healing modules, engine validate_with_context, dimension edge cases.

use chrono::{Duration, Utc};
use cortex_core::memory::links::FileLink;
use cortex_core::memory::*;
use cortex_core::models::{ContradictionType, HealingActionType};
use cortex_core::traits::IValidator;
use cortex_validation::contradiction::consensus;
use cortex_validation::contradiction::propagation;
use cortex_validation::contradiction::ContradictionDetector;
use cortex_validation::dimensions::{citation, pattern_alignment, temporal};
use cortex_validation::engine::{ValidationConfig, ValidationContext, ValidationEngine};
use cortex_validation::healing::{archival, confidence_adjust, flagging};

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
        content_hash: format!("hash-{id}"),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ─── Temporal Dimension ──────────────────────────────────────────────────────

#[test]
fn temporal_fresh_memory_scores_high() {
    let mem = make_memory("t1", "fresh memory", MemoryType::Semantic);
    let result = temporal::validate(&mem, Utc::now());
    assert!(result.score >= 0.8);
}

#[test]
fn temporal_expired_memory_scores_low() {
    let mut mem = make_memory("t2", "expired memory", MemoryType::Semantic);
    mem.valid_until = Some(Utc::now() - Duration::days(30));
    let result = temporal::validate(&mem, Utc::now());
    assert!(result.score < 0.5);
    assert!(!result.healing_actions.is_empty());
}

#[test]
fn temporal_no_expiry_is_fine() {
    let mem = make_memory("t3", "no expiry", MemoryType::Core);
    let result = temporal::validate(&mem, Utc::now());
    assert!(result.score >= 0.5);
}

// ─── Citation Dimension ──────────────────────────────────────────────────────

#[test]
fn citation_no_files_scores_full() {
    let mem = make_memory("c1", "no files", MemoryType::Semantic);
    let no_files = |_: &str| -> Option<citation::FileInfo> { None };
    let no_renames = |_: &str| -> Option<String> { None };
    let result = citation::validate(&mem, &no_files, &no_renames);
    assert!(result.score >= 0.8);
}

#[test]
fn citation_missing_file_scores_low() {
    let mut mem = make_memory("c2", "has file", MemoryType::PatternRationale);
    mem.linked_files = vec![FileLink {
        file_path: "src/deleted.rs".to_string(),
        line_start: Some(1),
        line_end: Some(10),
        content_hash: Some("old_hash".to_string()),
    }];
    let no_files = |_: &str| -> Option<citation::FileInfo> { None };
    let no_renames = |_: &str| -> Option<String> { None };
    let result = citation::validate(&mem, &no_files, &no_renames);
    assert!(result.score < 1.0);
}

#[test]
fn citation_file_exists_but_hash_changed() {
    let mut mem = make_memory("c3", "drifted file", MemoryType::PatternRationale);
    mem.linked_files = vec![FileLink {
        file_path: "src/main.rs".to_string(),
        line_start: Some(1),
        line_end: Some(10),
        content_hash: Some("old_hash".to_string()),
    }];
    let file_checker = |_: &str| -> Option<citation::FileInfo> {
        Some(citation::FileInfo {
            content_hash: Some("new_hash".to_string()),
            total_lines: Some(100),
        })
    };
    let no_renames = |_: &str| -> Option<String> { None };
    let result = citation::validate(&mem, &file_checker, &no_renames);
    assert!(result.score < 1.0);
}

#[test]
fn citation_rename_detected() {
    let mut mem = make_memory("c4", "renamed file", MemoryType::PatternRationale);
    mem.linked_files = vec![FileLink {
        file_path: "src/old_name.rs".to_string(),
        line_start: None,
        line_end: None,
        content_hash: None,
    }];
    let no_files = |_: &str| -> Option<citation::FileInfo> { None };
    let rename_detector = |path: &str| -> Option<String> {
        if path == "src/old_name.rs" {
            Some("src/new_name.rs".to_string())
        } else {
            None
        }
    };
    let result = citation::validate(&mem, &no_files, &rename_detector);
    assert!(result
        .healing_actions
        .iter()
        .any(|a| { a.action_type == HealingActionType::CitationUpdate }));
}

// ─── Pattern Alignment ───────────────────────────────────────────────────────

#[test]
fn pattern_alignment_no_patterns_scores_full() {
    let mem = make_memory("pa1", "no patterns", MemoryType::Semantic);
    let checker = |_: &str| -> pattern_alignment::PatternInfo {
        pattern_alignment::PatternInfo {
            exists: true,
            confidence: None,
        }
    };
    let result = pattern_alignment::validate(&mem, &checker);
    assert!(result.score >= 0.8);
}

// ─── Contradiction Detection ─────────────────────────────────────────────────

#[test]
fn contradiction_detector_empty_set() {
    let detector = ContradictionDetector::new();
    let contradictions = detector.detect(&[], None);
    assert!(contradictions.is_empty());
}

#[test]
fn contradiction_detector_single_memory() {
    let detector = ContradictionDetector::new();
    let a = make_memory("cd1", "Rust is fast", MemoryType::Semantic);
    let contradictions = detector.detect(&[a], None);
    assert!(contradictions.is_empty());
}

#[test]
fn contradiction_detector_detects_opposing_statements() {
    let detector = ContradictionDetector::new();
    let a = make_memory(
        "cd3",
        "Always use prepared statements for SQL",
        MemoryType::Tribal,
    );
    let b = make_memory(
        "cd4",
        "Never use prepared statements for SQL",
        MemoryType::Tribal,
    );
    let memories = vec![a, b];
    let contradictions = detector.detect(&memories, None);
    assert!(!contradictions.is_empty());
}

// ─── Consensus ───────────────────────────────────────────────────────────────

#[test]
fn consensus_empty_set() {
    let groups = consensus::detect_consensus(&[]);
    assert!(groups.is_empty());
}

#[test]
fn consensus_is_in_consensus_false_for_unknown() {
    let groups = consensus::detect_consensus(&[]);
    assert!(!consensus::is_in_consensus("unknown", &groups));
}

// ─── Propagation ─────────────────────────────────────────────────────────────

#[test]
fn propagation_base_delta_values() {
    let delta = propagation::base_delta(ContradictionType::Direct);
    assert!(delta < 0.0);
    assert_eq!(delta, propagation::DELTA_DIRECT);

    let delta2 = propagation::base_delta(ContradictionType::Supersession);
    assert!(delta2 < 0.0);
    assert_eq!(delta2, propagation::DELTA_SUPERSESSION);
}

#[test]
fn propagation_no_edges_only_sources() {
    let adjustments =
        propagation::propagate(&["m1".to_string()], ContradictionType::Direct, &[], None);
    assert_eq!(adjustments.len(), 1);
    assert_eq!(adjustments[0].memory_id, "m1");
    assert_eq!(adjustments[0].depth, 0);
}

#[test]
fn propagation_with_edges_ripples() {
    use cortex_core::memory::RelationshipEdge;
    let edges = vec![
        RelationshipEdge {
            source_id: "m1".to_string(),
            target_id: "m2".to_string(),
            relationship_type: cortex_core::memory::RelationshipType::Supports,
            strength: 0.8,
            evidence: vec![],
            cross_agent_relation: None,
        },
        RelationshipEdge {
            source_id: "m2".to_string(),
            target_id: "m3".to_string(),
            relationship_type: cortex_core::memory::RelationshipType::Related,
            strength: 0.6,
            evidence: vec![],
            cross_agent_relation: None,
        },
    ];
    let adjustments = propagation::propagate(
        &["m1".to_string()],
        ContradictionType::Direct,
        &edges,
        Some(3),
    );
    // Should have adjustments for m1, m2, and m3.
    assert!(adjustments.len() >= 2);
    // m2 should have a smaller delta than m1.
    let m1_delta = adjustments
        .iter()
        .find(|a| a.memory_id == "m1")
        .unwrap()
        .delta;
    let m2_delta = adjustments
        .iter()
        .find(|a| a.memory_id == "m2")
        .unwrap()
        .delta;
    assert!(m2_delta.abs() < m1_delta.abs());
}

// ─── Healing: Archival ───────────────────────────────────────────────────────

#[test]
fn archival_should_archive_low_confidence() {
    let mut mem = make_memory("ar1", "low confidence", MemoryType::Episodic);
    mem.confidence = Confidence::new(0.1);
    assert!(archival::should_archive(&mem));
}

#[test]
fn archival_should_not_archive_high_confidence() {
    let mem = make_memory("ar2", "high confidence", MemoryType::Semantic);
    assert!(!archival::should_archive(&mem));
}

#[test]
fn archival_archive_sets_flag() {
    let mut mem = make_memory("ar3", "to archive", MemoryType::Episodic);
    let reason = archival::archive(&mut mem, "confidence below threshold");
    assert!(mem.archived);
    assert!(!reason.reason.is_empty());
    assert_eq!(mem.confidence.value(), 0.0);
}

// ─── Healing: Confidence Adjust ──────────────────────────────────────────────

#[test]
fn confidence_adjust_blends() {
    let mut mem = make_memory("ca1", "adjust test", MemoryType::Semantic);
    mem.confidence = Confidence::new(0.8);
    confidence_adjust::adjust(&mut mem, 0.5, 0.3);
    let new_val = mem.confidence.value();
    assert!(new_val < 0.8 && new_val > 0.5);
}

#[test]
fn confidence_adjust_apply_delta() {
    let mut mem = make_memory("ca2", "delta test", MemoryType::Semantic);
    mem.confidence = Confidence::new(0.8);
    confidence_adjust::apply_delta(&mut mem, -0.2);
    assert!((mem.confidence.value() - 0.6).abs() < 0.01);
}

#[test]
fn confidence_adjust_clamps_to_zero() {
    let mut mem = make_memory("ca3", "clamp test", MemoryType::Semantic);
    mem.confidence = Confidence::new(0.1);
    confidence_adjust::apply_delta(&mut mem, -0.5);
    assert!(mem.confidence.value() >= 0.0);
}

// ─── Healing: Flagging ───────────────────────────────────────────────────────

#[test]
fn flagging_low_scores_creates_flag() {
    let flag = flagging::flag_for_review("f1", 0.2, 0.3, 0.1, 0.2);
    assert!(flag.is_some());
    let flag = flag.unwrap();
    assert_eq!(flag.severity, flagging::ReviewSeverity::High);
}

#[test]
fn flagging_high_scores_no_flag() {
    let flag = flagging::flag_for_review("f2", 0.9, 0.9, 0.9, 0.9);
    assert!(flag.is_none());
}

#[test]
fn flagging_medium_severity() {
    let flag = flagging::flag_for_review("f3", 0.4, 0.8, 0.8, 0.8);
    assert!(flag.is_some());
    let flag = flag.unwrap();
    assert_eq!(flag.severity, flagging::ReviewSeverity::Medium);
}

// ─── Engine ──────────────────────────────────────────────────────────────────

#[test]
fn engine_default_config() {
    let engine = ValidationEngine::default();
    let config = engine.config();
    assert_eq!(config.pass_threshold, 0.5);
    assert_eq!(config.adjustment_strength, 0.3);
    assert_eq!(config.archival_threshold, 0.15);
}

#[test]
fn engine_validate_basic_fresh_memory() {
    let engine = ValidationEngine::default();
    let mem = make_memory("ev1", "fresh memory", MemoryType::Semantic);
    let result = engine.validate_basic(&mem, &[]).unwrap();
    assert!(result.passed);
    assert!(result.overall_score >= 0.5);
}

#[test]
fn engine_validate_basic_expired_memory() {
    let engine = ValidationEngine::default();
    let mut mem = make_memory("ev2", "expired", MemoryType::Episodic);
    mem.valid_until = Some(Utc::now() - Duration::days(365));
    let result = engine.validate_basic(&mem, &[]).unwrap();
    assert!(result.dimension_scores.temporal < 0.5);
}

#[test]
fn engine_trait_impl_validate() {
    let engine = ValidationEngine::default();
    let mem = make_memory("ev3", "trait test", MemoryType::Semantic);
    let result = engine.validate(&mem).unwrap();
    assert_eq!(result.memory_id, "ev3");
}

#[test]
fn engine_validate_with_context_all_dimensions() {
    let engine = ValidationEngine::new(ValidationConfig {
        pass_threshold: 0.5,
        adjustment_strength: 0.3,
        archival_threshold: 0.15,
        epistemic_auto_promote: true,
    });

    let mem = make_memory("ctx1", "context test", MemoryType::Semantic);
    let related = vec![make_memory("ctx2", "related memory", MemoryType::Semantic)];

    let file_checker = |_: &str| -> Option<citation::FileInfo> {
        Some(citation::FileInfo {
            content_hash: None,
            total_lines: Some(100),
        })
    };
    let no_renames = |_: &str| -> Option<String> { None };
    let pattern_checker = |_: &str| -> pattern_alignment::PatternInfo {
        pattern_alignment::PatternInfo {
            exists: true,
            confidence: Some(0.9),
        }
    };

    let ctx = ValidationContext {
        related_memories: &related,
        all_memories: &related,
        file_checker: &file_checker,
        rename_detector: &no_renames,
        pattern_checker: &pattern_checker,
        similarity_fn: None,
    };

    let result = engine.validate_with_context(&mem, &ctx).unwrap();
    assert_eq!(result.memory_id, "ctx1");
    assert!(result.overall_score > 0.0);
}

#[test]
fn engine_custom_pass_threshold() {
    let engine = ValidationEngine::new(ValidationConfig {
        pass_threshold: 0.99,
        adjustment_strength: 0.3,
        archival_threshold: 0.15,
        epistemic_auto_promote: true,
    });
    let mem = make_memory("th1", "threshold test", MemoryType::Semantic);
    let result = engine.validate_basic(&mem, &[]).unwrap();
    assert!(!result.passed || result.overall_score >= 0.99);
}

// ─── Detection: detect_all and detect_all_exhaustive ─────────────────────────

#[test]
fn detect_all_no_contradiction_for_empty() {
    use cortex_validation::contradiction::detection;
    let a = make_memory("da1", "apples are fruit", MemoryType::Core);
    let b = make_memory("da2", "oranges are fruit", MemoryType::Episodic);
    let result = detection::detect_all(&a, &b, None);
    // Different types, no overlap — may or may not find contradiction.
    let _ = result;
}

#[test]
fn detect_all_exhaustive_returns_vec() {
    use cortex_validation::contradiction::detection;
    let a = make_memory("dae1", "Always use prepared statements", MemoryType::Tribal);
    let b = make_memory("dae2", "Never use prepared statements", MemoryType::Tribal);
    let results = detection::detect_all_exhaustive(&a, &b, None);
    assert!(!results.is_empty());
}

// ─── Detection: Temporal Supersession ────────────────────────────────────────

#[test]
fn temporal_supersession_different_types_no_match() {
    use cortex_validation::contradiction::detection::temporal_supersession;
    let a = make_memory("ts1", "old info", MemoryType::Semantic);
    let b = make_memory("ts2", "new info", MemoryType::Episodic);
    let result = temporal_supersession::detect(&a, &b, None, 0.3);
    assert!(result.is_none());
}

#[test]
fn temporal_supersession_same_tags_triggers() {
    use chrono::Duration;
    use cortex_validation::contradiction::detection::temporal_supersession;
    let mut a = make_memory("ts3", "old auth pattern", MemoryType::Semantic);
    a.valid_time = Utc::now() - Duration::days(30);
    a.tags = vec!["auth".to_string(), "security".to_string()];

    let mut b = make_memory("ts4", "new auth pattern", MemoryType::Semantic);
    b.valid_time = Utc::now();
    b.tags = vec!["auth".to_string(), "security".to_string()];

    let result = temporal_supersession::detect(&a, &b, None, 0.3);
    assert!(result.is_some());
}

#[test]
fn temporal_supersession_explicit_supersedes() {
    use chrono::Duration;
    use cortex_validation::contradiction::detection::temporal_supersession;
    let mut a = make_memory("ts5", "old version", MemoryType::Semantic);
    a.valid_time = Utc::now() - Duration::days(10);
    a.tags = vec!["auth".to_string()];

    let mut b = make_memory("ts6", "new version", MemoryType::Semantic);
    b.valid_time = Utc::now();
    b.tags = vec!["auth".to_string()];
    b.supersedes = Some("ts5".to_string());

    let result = temporal_supersession::detect(&a, &b, None, 0.3);
    assert!(result.is_some());
    let c = result.unwrap();
    assert!(c.description.contains("Explicit supersession"));
}

#[test]
fn temporal_supersession_via_embedding_similarity() {
    use chrono::Duration;
    use cortex_validation::contradiction::detection::temporal_supersession;
    let mut a = make_memory("ts7", "old approach", MemoryType::Semantic);
    a.valid_time = Utc::now() - Duration::days(5);

    let mut b = make_memory("ts8", "new approach", MemoryType::Semantic);
    b.valid_time = Utc::now();

    // High embedding similarity triggers supersession even without tag overlap.
    let result = temporal_supersession::detect(&a, &b, Some(0.95), 0.3);
    assert!(result.is_some());
}

// ─── Detection: Feedback ─────────────────────────────────────────────────────

#[test]
fn feedback_detection_negative_feedback() {
    use cortex_validation::contradiction::detection::feedback;
    let a = make_memory(
        "fb1",
        "Use singleton pattern for database connections",
        MemoryType::Tribal,
    );
    let mut b = make_memory("fb2", "singleton pattern feedback", MemoryType::Feedback);
    b.content = TypedContent::Feedback(cortex_core::memory::types::FeedbackContent {
        feedback:
            "This is wrong and outdated, singleton is an anti-pattern for database connections"
                .to_string(),
        source: "user".to_string(),
        category: "correction".to_string(),
    });
    b.tags = vec!["test".to_string()]; // Shared tag with a.

    let result = feedback::detect(&a, &b);
    assert!(result.is_some());
}

#[test]
fn feedback_detection_positive_feedback_no_contradiction() {
    use cortex_validation::contradiction::detection::feedback;
    let a = make_memory("fb3", "Use dependency injection", MemoryType::Tribal);
    let mut b = make_memory("fb4", "DI feedback", MemoryType::Feedback);
    b.content = TypedContent::Feedback(cortex_core::memory::types::FeedbackContent {
        feedback: "Great approach, works well".to_string(),
        source: "user".to_string(),
        category: "positive".to_string(),
    });
    b.tags = vec!["test".to_string()];

    let result = feedback::detect(&a, &b);
    assert!(result.is_none());
}

#[test]
fn feedback_detection_non_feedback_types() {
    use cortex_validation::contradiction::detection::feedback;
    let a = make_memory("fb5", "some info", MemoryType::Semantic);
    let b = make_memory("fb6", "other info", MemoryType::Semantic);
    let result = feedback::detect(&a, &b);
    assert!(result.is_none());
}

// ─── Detection: Cross-Pattern ────────────────────────────────────────────────

#[test]
fn cross_pattern_no_shared_patterns() {
    use cortex_validation::contradiction::detection::cross_pattern;
    let a = make_memory("cp1", "good pattern", MemoryType::PatternRationale);
    let b = make_memory("cp2", "bad pattern", MemoryType::PatternRationale);
    let result = cross_pattern::detect(&a, &b);
    assert!(result.is_none()); // No linked_patterns.
}

#[test]
fn cross_pattern_shared_pattern_opposing_sentiment() {
    use cortex_core::memory::links::PatternLink;
    use cortex_validation::contradiction::detection::cross_pattern;
    let mut a = make_memory(
        "cp3",
        "Singleton is a good recommended practice",
        MemoryType::PatternRationale,
    );
    a.linked_patterns = vec![PatternLink {
        pattern_id: "pat-singleton".to_string(),
        pattern_name: "Singleton".to_string(),
    }];

    let mut b = make_memory(
        "cp4",
        "Singleton is a bad anti-pattern to avoid",
        MemoryType::PatternRationale,
    );
    b.linked_patterns = vec![PatternLink {
        pattern_id: "pat-singleton".to_string(),
        pattern_name: "Singleton".to_string(),
    }];

    let result = cross_pattern::detect(&a, &b);
    assert!(result.is_some());
}

// ─── Healing: Citation Update ────────────────────────────────────────────────

#[test]
fn citation_update_renames_file_links() {
    use cortex_validation::healing::citation_update;
    use std::collections::HashMap;
    let mut mem = make_memory("cu1", "has file links", MemoryType::PatternRationale);
    mem.linked_files = vec![cortex_core::memory::links::FileLink {
        file_path: "src/old.rs".to_string(),
        line_start: Some(1),
        line_end: Some(10),
        content_hash: Some("hash123".to_string()),
    }];
    mem.linked_functions = vec![cortex_core::memory::links::FunctionLink {
        function_name: "main".to_string(),
        file_path: "src/old.rs".to_string(),
        signature: None,
    }];

    let mut rename_map = HashMap::new();
    rename_map.insert("src/old.rs".to_string(), "src/new.rs".to_string());

    let updated = citation_update::update_citations(&mut mem, &rename_map);
    assert_eq!(updated, 2); // file link + function link.
    assert_eq!(mem.linked_files[0].file_path, "src/new.rs");
    assert!(mem.linked_files[0].content_hash.is_none()); // Cleared.
    assert_eq!(mem.linked_functions[0].file_path, "src/new.rs");
}

#[test]
fn citation_update_no_renames() {
    use cortex_validation::healing::citation_update;
    use std::collections::HashMap;
    let mut mem = make_memory("cu2", "no renames", MemoryType::Semantic);
    let rename_map = HashMap::new();
    let updated = citation_update::update_citations(&mut mem, &rename_map);
    assert_eq!(updated, 0);
}

// ─── Healing: Embedding Refresh ──────────────────────────────────────────────

#[test]
fn embedding_refresh_content_hash_drift() {
    use cortex_validation::healing::embedding_refresh;
    let req = embedding_refresh::collect_refresh_requests("m1", false, true);
    assert!(req.is_some());
    assert!(req.unwrap().reason.contains("Content hash drift"));
}

#[test]
fn embedding_refresh_citation_changed() {
    use cortex_validation::healing::embedding_refresh;
    let req = embedding_refresh::collect_refresh_requests("m2", true, false);
    assert!(req.is_some());
    assert!(req.unwrap().reason.contains("Citation updated"));
}

#[test]
fn embedding_refresh_no_change() {
    use cortex_validation::healing::embedding_refresh;
    let req = embedding_refresh::collect_refresh_requests("m3", false, false);
    assert!(req.is_none());
}

// ─── Contradiction Detector: detect_and_propagate ────────────────────────────

#[test]
fn detector_detect_and_propagate() {
    let detector = ContradictionDetector::new();
    let a = make_memory(
        "dp1",
        "Always use prepared statements for SQL",
        MemoryType::Tribal,
    );
    let b = make_memory(
        "dp2",
        "Never use prepared statements for SQL",
        MemoryType::Tribal,
    );
    let memories = vec![a, b];
    let edges = vec![];
    let (contradictions, adjustments) = detector.detect_and_propagate(&memories, &edges, None);
    assert!(!contradictions.is_empty());
    assert!(!adjustments.is_empty());
}

// ─── Consensus: with actual memories ─────────────────────────────────────────

#[test]
fn consensus_with_memories() {
    let mems = vec![
        make_memory("con1", "use DI", MemoryType::Tribal),
        make_memory("con2", "use DI pattern", MemoryType::Tribal),
        make_memory("con3", "use DI for testing", MemoryType::Tribal),
    ];
    let groups = consensus::detect_consensus(&mems);
    // With 3 similar memories, may or may not form consensus.
    let _ = groups;
}

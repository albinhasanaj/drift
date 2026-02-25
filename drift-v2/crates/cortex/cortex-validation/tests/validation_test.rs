//! Tests for cortex-validation — T6-VAL-01 through T6-VAL-10.

use chrono::{Duration, Utc};
use cortex_core::memory::base::TypedContent;
use cortex_core::memory::types::{EpisodicContent, SemanticContent};
use cortex_core::memory::{BaseMemory, Confidence, FileLink, Importance, MemoryType, PatternLink};
use cortex_core::models::ContradictionType;
use cortex_validation::contradiction::consensus;
use cortex_validation::contradiction::detection;
use cortex_validation::contradiction::propagation;
use cortex_validation::dimensions::{citation, pattern_alignment, temporal};
use cortex_validation::engine::{ValidationConfig, ValidationContext, ValidationEngine};
use cortex_validation::healing;

/// Helper to create a minimal BaseMemory for testing.
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

// ─── T6-VAL-01: Citation validation detects missing file ───

#[test]
fn citation_detects_missing_file() {
    let mut mem = make_memory("m1", "Use bcrypt for hashing", MemoryType::Semantic);
    mem.linked_files.push(FileLink {
        file_path: "src/auth/hash.rs".into(),
        line_start: Some(10),
        line_end: Some(20),
        content_hash: Some("abc123".into()),
    });

    // File doesn't exist.
    let checker = |_: &str| -> Option<citation::FileInfo> { None };
    let rename = |_: &str| -> Option<String> { None };

    let result = citation::validate(&mem, &checker, &rename);
    assert!(result.score < 1.0, "Score should be < 1.0 for missing file");
    assert!(
        !result.healing_actions.is_empty(),
        "Should have healing actions"
    );
}

// ─── T6-VAL-02: Citation validation detects content drift ───

#[test]
fn citation_detects_content_drift() {
    let mut mem = make_memory("m2", "Config pattern", MemoryType::Semantic);
    mem.linked_files.push(FileLink {
        file_path: "src/config.rs".into(),
        line_start: Some(1),
        line_end: Some(50),
        content_hash: Some("old_hash".into()),
    });

    // File exists but hash changed.
    let checker = |_: &str| -> Option<citation::FileInfo> {
        Some(citation::FileInfo {
            content_hash: Some("new_hash".into()),
            total_lines: Some(100),
        })
    };
    let rename = |_: &str| -> Option<String> { None };

    let result = citation::validate(&mem, &checker, &rename);
    // File exists so it's partially valid, but hash mismatch should trigger healing.
    assert!(
        result
            .healing_actions
            .iter()
            .any(|a| a.description.contains("hash drift")),
        "Should flag content hash drift"
    );
}

// ─── T6-VAL-03: Temporal validation detects expired memory ───

#[test]
fn temporal_detects_expired_memory() {
    let mut mem = make_memory("m3", "Temporary workaround", MemoryType::Episodic);
    mem.valid_until = Some(Utc::now() - Duration::days(30));

    let result = temporal::validate(&mem, Utc::now());
    assert!(result.expired, "Memory should be detected as expired");
    assert_eq!(result.score, 0.0, "Expired memory should have score 0.0");
    assert!(
        result.healing_actions.iter().any(|a| {
            matches!(
                a.action_type,
                cortex_core::models::HealingActionType::Archival
            )
        }),
        "Should recommend archival"
    );
}

// ─── T6-VAL-04: Contradiction detected between opposing memories ───

#[test]
fn contradiction_detected_between_opposing_memories() {
    let a = make_memory(
        "m4a",
        "Always use bcrypt for password hashing",
        MemoryType::Semantic,
    );
    let b = make_memory(
        "m4b",
        "Never use bcrypt for password hashing",
        MemoryType::Semantic,
    );

    let result = detection::detect_all(&a, &b, None);
    assert!(
        result.is_some(),
        "Should detect contradiction between 'always' and 'never'"
    );

    let contradiction = result.unwrap();
    assert_eq!(contradiction.contradiction_type, ContradictionType::Direct);
}

// ─── T6-VAL-05: Consensus resists single contradiction ───

#[test]
fn consensus_resists_single_contradiction() {
    // Create 3 memories that form a consensus.
    let mut m1 = make_memory("c1", "Use dependency injection", MemoryType::Semantic);
    m1.tags = vec!["architecture".into(), "di".into()];
    let mut m2 = make_memory("c2", "Prefer DI for testability", MemoryType::Semantic);
    m2.tags = vec!["architecture".into(), "di".into()];
    let mut m3 = make_memory("c3", "DI improves modularity", MemoryType::Semantic);
    m3.tags = vec!["architecture".into(), "di".into()];

    let all = vec![m1.clone(), m2.clone(), m3.clone()];
    let groups = consensus::detect_consensus(&all);

    assert!(!groups.is_empty(), "Should detect a consensus group");
    assert!(
        consensus::is_in_consensus("c1", &groups),
        "m1 should be in consensus"
    );
    assert!(
        consensus::resists_contradiction("c1", &groups),
        "Consensus memory should resist contradiction"
    );
}

// ─── T6-VAL-06: Confidence propagation ripples correctly ───

#[test]
fn confidence_propagation_ripples_correctly() {
    use cortex_core::memory::{RelationshipEdge, RelationshipType};

    let edges = vec![
        RelationshipEdge {
            source_id: "m1".into(),
            target_id: "m2".into(),
            relationship_type: RelationshipType::Supports,
            strength: 0.8,
            evidence: vec![],
            cross_agent_relation: None,
        },
        RelationshipEdge {
            source_id: "m2".into(),
            target_id: "m3".into(),
            relationship_type: RelationshipType::Related,
            strength: 0.6,
            evidence: vec![],
            cross_agent_relation: None,
        },
    ];

    let adjustments =
        propagation::propagate(&["m1".into()], ContradictionType::Direct, &edges, None);

    // m1 gets direct delta.
    let m1_adj = adjustments.iter().find(|a| a.memory_id == "m1").unwrap();
    assert!((m1_adj.delta - propagation::DELTA_DIRECT).abs() < f64::EPSILON);

    // m2 gets propagated delta (0.5× of direct).
    let m2_adj = adjustments.iter().find(|a| a.memory_id == "m2").unwrap();
    assert!(
        (m2_adj.delta - (propagation::DELTA_DIRECT * propagation::PROPAGATION_FACTOR)).abs()
            < f64::EPSILON
    );

    // m3 gets further propagated delta (0.5× of m2's).
    let m3_adj = adjustments.iter().find(|a| a.memory_id == "m3").unwrap();
    let expected_m3 = propagation::DELTA_DIRECT
        * propagation::PROPAGATION_FACTOR
        * propagation::PROPAGATION_FACTOR;
    assert!(
        (m3_adj.delta - expected_m3).abs() < f64::EPSILON,
        "m3 delta should be {}, got {}",
        expected_m3,
        m3_adj.delta
    );
}

// ─── T6-VAL-07: Healing triggers archival below threshold ───

#[test]
fn healing_triggers_archival_below_threshold() {
    let mut mem = make_memory("m7", "Stale info", MemoryType::Episodic);
    mem.confidence = Confidence::new(0.1); // Below archival threshold (0.15).

    assert!(healing::archival::should_archive(&mem));

    let reason = healing::archival::archive(&mut mem, "Confidence below threshold");
    assert!(mem.archived);
    assert_eq!(reason.final_confidence, 0.1);
}

// ─── T6-VAL-08: Git rename detection updates citation ───

#[test]
fn git_rename_detection_updates_citation() {
    let mut mem = make_memory("m8", "Auth module", MemoryType::Semantic);
    mem.linked_files.push(FileLink {
        file_path: "src/old_auth.rs".into(),
        line_start: Some(1),
        line_end: Some(100),
        content_hash: None,
    });

    let mut rename_map = std::collections::HashMap::new();
    rename_map.insert("src/old_auth.rs".to_string(), "src/auth/mod.rs".to_string());

    let updated = healing::citation_update::update_citations(&mut mem, &rename_map);
    assert_eq!(updated, 1);
    assert_eq!(mem.linked_files[0].file_path, "src/auth/mod.rs");
}

// ─── T6-VAL-09: Pattern alignment detects removed pattern ───

#[test]
fn pattern_alignment_detects_removed_pattern() {
    let mut mem = make_memory("m9", "Uses singleton pattern", MemoryType::Semantic);
    mem.linked_patterns.push(PatternLink {
        pattern_id: "pat-1".into(),
        pattern_name: "singleton".into(),
    });

    // Pattern no longer exists.
    let checker = |_: &str| -> pattern_alignment::PatternInfo {
        pattern_alignment::PatternInfo {
            exists: false,
            confidence: None,
        }
    };

    let result = pattern_alignment::validate(&mem, &checker);
    assert!(
        result.score < 1.0,
        "Score should be < 1.0 for missing pattern"
    );
    assert!(
        !result.details[0].exists,
        "Pattern should be marked as not existing"
    );
    assert!(
        !result.healing_actions.is_empty(),
        "Should have healing actions for removed pattern"
    );
}

// ─── T6-VAL-10: Propagation deltas are correct ───

#[test]
fn propagation_deltas_correct() {
    assert!((propagation::base_delta(ContradictionType::Direct) - (-0.3)).abs() < f64::EPSILON);
    assert!((propagation::base_delta(ContradictionType::Partial) - (-0.15)).abs() < f64::EPSILON);
    assert!(
        (propagation::base_delta(ContradictionType::Supersession) - (-0.5)).abs() < f64::EPSILON
    );
    assert!((propagation::DELTA_CONFIRMATION - 0.1).abs() < f64::EPSILON);
    assert!((propagation::DELTA_CONSENSUS - 0.2).abs() < f64::EPSILON);
}

// ─── Additional: Full engine validation ───

#[test]
fn engine_validates_fresh_memory_as_passing() {
    let engine = ValidationEngine::default();
    let mem = make_memory("fresh", "Fresh memory", MemoryType::Semantic);

    let result = engine.validate_basic(&mem, &[]).unwrap();
    assert!(result.passed, "Fresh memory should pass validation");
    assert!(result.overall_score > 0.5);
}

#[test]
fn engine_validates_expired_memory_as_failing() {
    let engine = ValidationEngine::new(ValidationConfig {
        pass_threshold: 0.5,
        ..Default::default()
    });

    let mut mem = make_memory("expired", "Old workaround", MemoryType::Episodic);
    mem.valid_until = Some(Utc::now() - Duration::days(365));

    let result = engine.validate_basic(&mem, &[]).unwrap();
    // Temporal score will be 0.0 due to expiry, dragging overall down.
    assert!(
        result.dimension_scores.temporal == 0.0,
        "Temporal score should be 0.0 for expired memory"
    );
}

#[test]
fn engine_with_full_context() {
    let engine = ValidationEngine::default();
    let mem = make_memory("ctx", "Context test", MemoryType::Semantic);

    let checker = |_: &str| -> Option<citation::FileInfo> { None };
    let rename = |_: &str| -> Option<String> { None };
    let patterns = |_: &str| -> pattern_alignment::PatternInfo {
        pattern_alignment::PatternInfo {
            exists: true,
            confidence: Some(0.9),
        }
    };

    let ctx = ValidationContext {
        related_memories: &[],
        all_memories: &[],
        file_checker: &checker,
        rename_detector: &rename,
        pattern_checker: &patterns,
        similarity_fn: None,
    };

    let result = engine.validate_with_context(&mem, &ctx).unwrap();
    assert!(result.passed);
}

#[test]
fn confidence_adjust_blends_correctly() {
    let mut mem = make_memory("adj", "Test", MemoryType::Semantic);
    mem.confidence = Confidence::new(0.8);

    healing::confidence_adjust::adjust(&mut mem, 0.4, 0.5);
    // Expected: 0.8 * 0.5 + 0.4 * 0.5 = 0.6
    assert!((mem.confidence.value() - 0.6).abs() < f64::EPSILON);
}

#[test]
fn confidence_delta_applies_correctly() {
    let mut mem = make_memory("delta", "Test", MemoryType::Semantic);
    mem.confidence = Confidence::new(0.8);

    healing::confidence_adjust::apply_delta(&mut mem, -0.3);
    assert!((mem.confidence.value() - 0.5).abs() < f64::EPSILON);
}

#[test]
fn flagging_creates_review_flag() {
    let flag = healing::flagging::flag_for_review("m1", 0.3, 0.9, 0.9, 0.9);
    assert!(flag.is_some());
    let flag = flag.unwrap();
    assert_eq!(flag.severity, healing::flagging::ReviewSeverity::Medium);
}

#[test]
fn flagging_no_flag_when_all_scores_high() {
    let flag = healing::flagging::flag_for_review("m1", 0.9, 0.9, 0.9, 0.9);
    assert!(flag.is_none());
}

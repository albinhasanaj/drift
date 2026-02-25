use chrono::{Duration, Utc};
use cortex_core::errors::CortexResult;
use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_reclassification::{
    Direction, ReclassificationDecision, ReclassificationEngine, ReclassificationRecord,
    ReclassificationSignals,
};
use std::sync::Mutex;

// ── Mock Storage ──────────────────────────────────────────────────────────

struct MockStorage {
    memories: Mutex<Vec<BaseMemory>>,
}

impl MockStorage {
    fn with_memories(memories: Vec<BaseMemory>) -> Self {
        Self {
            memories: Mutex::new(memories),
        }
    }
}

fn make_memory(id: &str, importance: Importance) -> BaseMemory {
    let now = Utc::now();
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Tribal,
        content: TypedContent::Tribal(cortex_core::memory::types::TribalContent {
            knowledge: "Test".to_string(),
            severity: "medium".to_string(),
            warnings: vec![],
            consequences: vec![],
        }),
        summary: format!("Memory {}", id),
        transaction_time: now,
        valid_time: now,
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance,
        last_accessed: now,
        access_count: 10,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec![],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: format!("hash_{}", id),
    }
}

impl IMemoryStorage for MockStorage {
    fn create(&self, memory: &BaseMemory) -> CortexResult<()> {
        self.memories.lock().unwrap().push(memory.clone());
        Ok(())
    }
    fn get(&self, id: &str) -> CortexResult<Option<BaseMemory>> {
        Ok(self
            .memories
            .lock()
            .unwrap()
            .iter()
            .find(|m| m.id == id)
            .cloned())
    }
    fn update(&self, _: &BaseMemory) -> CortexResult<()> {
        Ok(())
    }
    fn delete(&self, _: &str) -> CortexResult<()> {
        Ok(())
    }
    fn create_bulk(&self, _: &[BaseMemory]) -> CortexResult<usize> {
        Ok(0)
    }
    fn get_bulk(&self, _: &[String]) -> CortexResult<Vec<BaseMemory>> {
        Ok(vec![])
    }
    fn query_by_type(&self, mt: MemoryType) -> CortexResult<Vec<BaseMemory>> {
        Ok(self
            .memories
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.memory_type == mt)
            .cloned()
            .collect())
    }
    fn query_by_importance(&self, min: Importance) -> CortexResult<Vec<BaseMemory>> {
        Ok(self
            .memories
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.importance >= min)
            .cloned()
            .collect())
    }
    fn query_by_confidence_range(&self, _: f64, _: f64) -> CortexResult<Vec<BaseMemory>> {
        Ok(vec![])
    }
    fn query_by_date_range(
        &self,
        _: chrono::DateTime<Utc>,
        _: chrono::DateTime<Utc>,
    ) -> CortexResult<Vec<BaseMemory>> {
        Ok(vec![])
    }
    fn query_by_tags(&self, _: &[String]) -> CortexResult<Vec<BaseMemory>> {
        Ok(vec![])
    }
    fn search_fts5(&self, _: &str, _: usize) -> CortexResult<Vec<BaseMemory>> {
        Ok(vec![])
    }
    fn search_vector(&self, _: &[f32], _: usize) -> CortexResult<Vec<(BaseMemory, f64)>> {
        Ok(vec![])
    }
    fn get_relationships(
        &self,
        _: &str,
        _: Option<RelationshipType>,
    ) -> CortexResult<Vec<RelationshipEdge>> {
        Ok(vec![])
    }
    fn add_relationship(&self, _: &RelationshipEdge) -> CortexResult<()> {
        Ok(())
    }
    fn remove_relationship(&self, _: &str, _: &str) -> CortexResult<()> {
        Ok(())
    }
    fn add_pattern_link(&self, _: &str, _: &PatternLink) -> CortexResult<()> {
        Ok(())
    }
    fn add_constraint_link(&self, _: &str, _: &ConstraintLink) -> CortexResult<()> {
        Ok(())
    }
    fn add_file_link(&self, _: &str, _: &FileLink) -> CortexResult<()> {
        Ok(())
    }
    fn add_function_link(&self, _: &str, _: &FunctionLink) -> CortexResult<()> {
        Ok(())
    }
    fn count_by_type(&self) -> CortexResult<Vec<(MemoryType, usize)>> {
        Ok(vec![])
    }
    fn average_confidence(&self) -> CortexResult<f64> {
        Ok(0.0)
    }
    fn stale_count(&self, _: u64) -> CortexResult<usize> {
        Ok(0)
    }
    fn vacuum(&self) -> CortexResult<()> {
        Ok(())
    }
}

// ── T9-RECL-01: High-access normal memory upgraded to high ────────────────

#[test]
fn high_access_normal_memory_upgraded_to_high() {
    let memory = make_memory("mem1", Importance::Normal);
    let signals = ReclassificationSignals {
        access_count_30d: 50,
        avg_retrieval_rank_30d: Some(2.0),
        linked_entity_count: 5,
        contradiction_wins: 3,
        user_feedback_score: 0.9,
    };

    let eval = ReclassificationEngine::evaluate(&memory, &signals, false, None);

    assert!(
        eval.composite_score > 0.85,
        "Composite score should be > 0.85 for upgrade, got {}",
        eval.composite_score
    );
    match eval.decision {
        ReclassificationDecision::Reclassify { new_importance, .. } => {
            assert_eq!(new_importance, Importance::High);
        }
        other => panic!("Expected Reclassify, got {:?}", other),
    }
}

// ── T9-RECL-02: User-set critical never auto-downgraded ──────────────────

#[test]
fn user_set_critical_never_auto_downgraded() {
    let memory = make_memory("mem_crit", Importance::Critical);
    let signals = ReclassificationSignals {
        access_count_30d: 0,
        avg_retrieval_rank_30d: None,
        linked_entity_count: 0,
        contradiction_wins: 0,
        user_feedback_score: 0.0,
    };

    let eval = ReclassificationEngine::evaluate(
        &memory, &signals, true, // user-set critical
        None,
    );

    match eval.decision {
        ReclassificationDecision::Blocked { reason } => {
            assert!(
                reason.contains("user-set critical"),
                "Should mention user-set critical in reason"
            );
        }
        ReclassificationDecision::NoChange => {
            // Also acceptable if score doesn't trigger downgrade
        }
        other => panic!(
            "Expected Blocked or NoChange for user-set critical, got {:?}",
            other
        ),
    }
}

// ── T9-RECL-03: Max 1 reclassification per memory per month ──────────────

#[test]
fn max_one_reclassification_per_month() {
    let memory = make_memory("mem1", Importance::Normal);
    let signals = ReclassificationSignals {
        access_count_30d: 50,
        avg_retrieval_rank_30d: Some(1.0),
        linked_entity_count: 5,
        contradiction_wins: 5,
        user_feedback_score: 1.0,
    };

    // Recent reclassification (10 days ago)
    let recent_record = ReclassificationRecord {
        memory_id: "mem1".to_string(),
        from: Importance::Low,
        to: Importance::Normal,
        composite_score: 0.75,
        signals: signals.clone(),
        timestamp: Utc::now() - Duration::days(10),
    };

    let eval = ReclassificationEngine::evaluate(&memory, &signals, false, Some(&recent_record));

    match eval.decision {
        ReclassificationDecision::Blocked { reason } => {
            assert!(
                reason.contains("cooldown"),
                "Should mention cooldown in reason: {}",
                reason
            );
        }
        other => panic!("Expected Blocked due to cooldown, got {:?}", other),
    }
}

// ── T9-RECL-04: Composite score computed correctly ────────────────────────

#[test]
fn composite_score_computed_correctly() {
    let signals = ReclassificationSignals {
        access_count_30d: 20,              // normalized: 1.0
        avg_retrieval_rank_30d: Some(1.0), // normalized: 1.0
        linked_entity_count: 3,            // normalized: 1.0
        contradiction_wins: 5,             // normalized: 1.0
        user_feedback_score: 1.0,
    };

    let score = signals.composite_score();
    assert!(
        (score - 1.0).abs() < f64::EPSILON,
        "All max signals should give 1.0, got {}",
        score
    );

    // Partial signals
    let partial = ReclassificationSignals {
        access_count_30d: 10,              // normalized: 0.5
        avg_retrieval_rank_30d: Some(5.0), // normalized: ~0.556
        linked_entity_count: 1,            // normalized: 0.333
        contradiction_wins: 0,             // normalized: 0.0
        user_feedback_score: 0.5,
    };

    let partial_score = partial.composite_score();
    assert!(
        partial_score > 0.0 && partial_score < 1.0,
        "Partial signals should give intermediate score, got {}",
        partial_score
    );
}

// ── T9-RECL-05: All reclassifications logged to audit trail ───────────────

#[test]
fn reclassification_produces_audit_data() {
    let memory = make_memory("mem_audit", Importance::Low);
    let signals = ReclassificationSignals {
        access_count_30d: 30,
        avg_retrieval_rank_30d: Some(2.0),
        linked_entity_count: 4,
        contradiction_wins: 2,
        user_feedback_score: 0.8,
    };

    let eval = ReclassificationEngine::evaluate(&memory, &signals, false, None);

    // The evaluation contains all data needed for audit logging
    assert_eq!(eval.memory_id, "mem_audit");
    assert_eq!(eval.current_importance, Importance::Low);
    assert!(eval.composite_score > 0.0);

    // If reclassified, we have the rule details
    if let ReclassificationDecision::Reclassify { rule, .. } = &eval.decision {
        assert_eq!(rule.from, Importance::Low);
        assert_eq!(rule.to, Importance::Normal);
    }
}

// ── Rules: upgrade and downgrade thresholds ───────────────────────────────

#[test]
fn upgrade_rules_correct_thresholds() {
    use cortex_reclassification::rules;

    // Low → Normal requires score > 0.7
    let rule = rules::find_applicable_rule(Importance::Low, 0.75);
    assert!(rule.is_some());
    let r = rule.unwrap();
    assert_eq!(r.from, Importance::Low);
    assert_eq!(r.to, Importance::Normal);
    assert_eq!(r.direction, Direction::Upgrade);

    // Score below threshold → no rule
    let no_rule = rules::find_applicable_rule(Importance::Low, 0.5);
    // Could be a downgrade rule for Low
    if let Some(r) = no_rule {
        assert_eq!(r.direction, Direction::Downgrade);
    }
}

#[test]
fn downgrade_rules_correct_thresholds() {
    use cortex_reclassification::rules;

    // Critical → High requires score < 0.5
    let rule = rules::find_applicable_rule(Importance::Critical, 0.3);
    assert!(rule.is_some());
    let r = rule.unwrap();
    assert_eq!(r.from, Importance::Critical);
    assert_eq!(r.to, Importance::High);
    assert_eq!(r.direction, Direction::Downgrade);
}

// ── Safeguards ────────────────────────────────────────────────────────────

#[test]
fn safeguard_blocks_empty_memory_id() {
    let result = cortex_reclassification::safeguards::is_reclassification_allowed(
        "",
        Importance::Normal,
        Direction::Upgrade,
        false,
        None,
        2,
    );
    assert!(!result.is_allowed());
}

// ── Full pass with mock storage ───────────────────────────────────────────

#[test]
fn full_pass_evaluates_all_memories() {
    let memories = vec![
        make_memory("m1", Importance::Low),
        make_memory("m2", Importance::Normal),
        make_memory("m3", Importance::High),
    ];
    let storage = MockStorage::with_memories(memories);

    let evaluations = ReclassificationEngine::run_full_pass(
        &storage,
        |_mem| ReclassificationSignals {
            access_count_30d: 25,
            avg_retrieval_rank_30d: Some(2.0),
            linked_entity_count: 4,
            contradiction_wins: 3,
            user_feedback_score: 0.8,
        },
        |_id| None,
        |_id| false,
    )
    .unwrap();

    // Should have evaluated all 3 memories (they all have importance >= Low)
    assert!(
        evaluations.len() >= 3,
        "Should evaluate at least 3 memories, got {}",
        evaluations.len()
    );
}

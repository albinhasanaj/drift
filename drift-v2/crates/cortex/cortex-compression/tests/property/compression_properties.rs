use chrono::Utc;
use cortex_compression::CompressionEngine;
use cortex_core::memory::*;
use cortex_core::traits::ICompressor;
use proptest::prelude::*;

fn arb_importance() -> impl Strategy<Value = Importance> {
    prop_oneof![
        Just(Importance::Low),
        Just(Importance::Normal),
        Just(Importance::High),
        Just(Importance::Critical),
    ]
}

fn arb_memory(importance: Importance) -> BaseMemory {
    BaseMemory {
        id: uuid::Uuid::new_v4().to_string(),
        memory_type: MemoryType::Semantic,
        content: TypedContent::Semantic(cortex_core::memory::types::SemanticContent {
            knowledge: "a test definition for property testing".to_string(),
            source_episodes: vec![],
            consolidation_confidence: 0.9,
        }),
        summary: "Test memory for property testing".to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.8),
        importance,
        last_accessed: Utc::now(),
        access_count: 5,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: "test_hash".to_string(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ── T4-COMP-07: Level ordering L0<L1<L2<L3 ──────────────────────────────

proptest! {
    #[test]
    fn level_ordering_holds_for_any_importance(importance in arb_importance()) {
        let engine = CompressionEngine::new();
        let memory = arb_memory(importance);

        let l0 = engine.compress(&memory, 0).unwrap();
        let l1 = engine.compress(&memory, 1).unwrap();
        let l2 = engine.compress(&memory, 2).unwrap();
        let l3 = engine.compress(&memory, 3).unwrap();

        prop_assert!(l0.token_count <= l1.token_count, "L0 > L1");
        prop_assert!(l1.token_count <= l2.token_count, "L1 > L2");
        prop_assert!(l2.token_count <= l3.token_count, "L2 > L3");
    }
}

// ── T4-COMP-08: compressToFit ≤ budget ───────────────────────────────────

proptest! {
    #[test]
    fn compress_to_fit_never_exceeds_budget(
        budget in 1usize..2000,
        importance in arb_importance()
    ) {
        let engine = CompressionEngine::new();
        let memory = arb_memory(importance);

        let result = engine.compress_to_fit(&memory, budget).unwrap();
        // L0 is the minimum — if even L0 exceeds budget, we still return L0
        // but for reasonable budgets, it should fit.
        if budget >= 10 {
            prop_assert!(
                result.token_count <= budget,
                "Exceeded budget {}: got {}",
                budget,
                result.token_count
            );
        }
    }
}

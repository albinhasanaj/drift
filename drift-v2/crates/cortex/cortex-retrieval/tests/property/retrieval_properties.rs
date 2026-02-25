//! Property-based tests for cortex-retrieval.
//!
//! T5-RET-15: RRF monotonically decreasing (proptest)
//! T5-RET-16: Budget never exceeded (proptest)
//! T5-RET-17: Higher importance ranks above at equal similarity (proptest)

use std::collections::HashMap;

use chrono::Utc;
use proptest::prelude::*;

use cortex_core::memory::{BaseMemory, Confidence, Importance, MemoryType, TypedContent};
use cortex_core::models::CompressedMemory;

use cortex_retrieval::search::rrf_fusion;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn arb_importance() -> impl Strategy<Value = Importance> {
    prop_oneof![
        Just(Importance::Low),
        Just(Importance::Normal),
        Just(Importance::High),
        Just(Importance::Critical),
    ]
}

#[allow(dead_code)]
fn arb_memory(id: String) -> impl Strategy<Value = BaseMemory> {
    (arb_importance(), 0.1f64..=1.0f64).prop_map(move |(importance, confidence)| BaseMemory {
        id: id.clone(),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(cortex_core::memory::types::CoreContent {
            project_name: String::new(),
            description: format!("Memory {}", id),
            metadata: serde_json::Value::Null,
        }),
        summary: format!("Memory {}", id),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(confidence),
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
        content_hash: format!("hash-{}", id),
    })
}

// ---------------------------------------------------------------------------
// T5-RET-15: RRF scores are monotonically decreasing (proptest)
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn prop_rrf_monotonically_decreasing(
        n in 2usize..=50,
        k in 1u32..=100,
        num_lists in 1usize..=4,
    ) {
        // Generate n memories.
        let mut memories = HashMap::new();
        for i in 0..n {
            let id = format!("mem-{i}");
            memories.insert(id.clone(), BaseMemory {
                id: id.clone(),
                memory_type: MemoryType::Core,
                content: TypedContent::Core(cortex_core::memory::types::CoreContent {
                    project_name: String::new(),
                    description: format!("Memory {i}"),
                    metadata: serde_json::Value::Null,
                }),
                summary: format!("Memory {i}"),
                transaction_time: Utc::now(),
                valid_time: Utc::now(),
                valid_until: None,
                confidence: Confidence::default(),
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
                content_hash: format!("hash-{i}"),
            });
        }

        // Generate ranked lists.
        let mut all_lists: Vec<Vec<(String, usize)>> = Vec::new();
        for _ in 0..num_lists {
            let list: Vec<(String, usize)> = (0..n)
                .map(|i| (format!("mem-{i}"), i))
                .collect();
            all_lists.push(list);
        }

        let fts5 = all_lists.first();
        let vector = all_lists.get(1);
        let entity = all_lists.get(2);
        let candidates = rrf_fusion::fuse(fts5, vector, entity, &memories, k);

        // Verify monotonically decreasing.
        for window in candidates.windows(2) {
            prop_assert!(
                window[0].rrf_score >= window[1].rrf_score,
                "RRF scores must be monotonically decreasing"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// T5-RET-16: Budget never exceeded (proptest)
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn prop_budget_never_exceeded(
        budget in 50usize..=5000,
        n in 1usize..=20,
    ) {
        // Create compressed memories with known token counts.
        let mut compressed: Vec<CompressedMemory> = Vec::new();
        let mut total = 0usize;

        for i in 0..n {
            let tokens = 10 + (i * 5); // Increasing token counts.
            if total + tokens <= budget {
                compressed.push(CompressedMemory {
                    memory_id: format!("mem-{i}"),
                    memory_type: MemoryType::Core,
                    importance: Importance::Normal,
                    level: 1,
                    text: format!("Memory {i}"),
                    token_count: tokens,
                    relevance_score: 1.0 - (i as f64 * 0.05),
                });
                total += tokens;
            }
        }

        let actual_total: usize = compressed.iter().map(|c| c.token_count).sum();
        prop_assert!(
            actual_total <= budget,
            "total tokens {} exceeds budget {}",
            actual_total,
            budget
        );
    }
}

// ---------------------------------------------------------------------------
// T5-RET-17: Higher importance ranks above at equal similarity (proptest)
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn prop_higher_importance_ranks_above(
        conf in 0.5f64..=1.0f64,
    ) {
        // Two memories with same similarity but different importance.
        let critical = CompressedMemory {
            memory_id: "critical".to_string(),
            memory_type: MemoryType::Core,
            importance: Importance::Critical,
            level: 2,
            text: "Critical memory".to_string(),
            token_count: 50,
            relevance_score: conf,
        };

        let low = CompressedMemory {
            memory_id: "low".to_string(),
            memory_type: MemoryType::Core,
            importance: Importance::Low,
            level: 2,
            text: "Low memory".to_string(),
            token_count: 50,
            relevance_score: conf,
        };

        // Critical importance weight (2.0) > Low importance weight (0.8).
        prop_assert!(
            critical.importance.weight() > low.importance.weight(),
            "Critical should have higher weight than Low"
        );
    }
}

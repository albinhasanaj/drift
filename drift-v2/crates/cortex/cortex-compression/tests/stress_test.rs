//! Compression stress tests: level ordering at scale, budget fitting,
//! priority-weighted packing, and edge cases.

use chrono::Utc;
use cortex_compression::CompressionEngine;
use cortex_core::memory::*;
use cortex_core::traits::ICompressor;
use std::time::Instant;

fn make_memory_with_content(id: &str, importance: Importance, summary: &str) -> BaseMemory {
    let content = TypedContent::Tribal(cortex_core::memory::types::TribalContent {
        knowledge: format!("Detailed knowledge about {summary}. This includes multiple aspects and considerations that should be preserved at higher compression levels."),
        severity: "high".to_string(),
        warnings: vec!["Warning about edge cases".to_string()],
        consequences: vec!["Potential impact on system stability".to_string()],
    });
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Tribal,
        content: content.clone(),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance,
        last_accessed: Utc::now(),
        access_count: 10,
        linked_patterns: vec![PatternLink {
            pattern_id: "pat-001".to_string(),
            pattern_name: "test-pattern".to_string(),
        }],
        linked_constraints: vec![],
        linked_files: vec![FileLink {
            file_path: "src/main.rs".to_string(),
            line_start: Some(1),
            line_end: Some(50),
            content_hash: Some("abc123".to_string()),
        }],
        linked_functions: vec![FunctionLink {
            function_name: "process_data".to_string(),
            file_path: "src/main.rs".to_string(),
            signature: Some("fn process_data() -> Result<()>".to_string()),
        }],
        tags: vec!["test".to_string(), "stress".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

// ── Level ordering at scale ──────────────────────────────────────────────

#[test]
fn stress_level_ordering_500_memories() {
    let engine = CompressionEngine::new();

    for i in 0..500 {
        let mem = make_memory_with_content(
            &format!("lo-{i}"),
            if i % 4 == 0 {
                Importance::Critical
            } else {
                Importance::Normal
            },
            &format!("Topic {i} about software engineering principle number {i}"),
        );

        let l0 = engine.compress(&mem, 0).unwrap();
        let l1 = engine.compress(&mem, 1).unwrap();
        let l2 = engine.compress(&mem, 2).unwrap();
        let l3 = engine.compress(&mem, 3).unwrap();

        assert!(
            l0.token_count <= l1.token_count,
            "Memory {i}: L0 ({}) > L1 ({})",
            l0.token_count,
            l1.token_count
        );
        assert!(
            l1.token_count <= l2.token_count,
            "Memory {i}: L1 ({}) > L2 ({})",
            l1.token_count,
            l2.token_count
        );
        assert!(
            l2.token_count <= l3.token_count,
            "Memory {i}: L2 ({}) > L3 ({})",
            l2.token_count,
            l3.token_count
        );
    }
}

// ── Budget fitting stress ────────────────────────────────────────────────

#[test]
fn stress_compress_to_fit_respects_budget_or_returns_l0() {
    let engine = CompressionEngine::new();
    // Note: compress_to_fit returns L0 even if it exceeds budget (L0 is the minimum).
    // For budgets >= L0 size, it should always fit.
    let budgets = [25, 50, 100, 200, 500, 1000];

    for budget in budgets {
        for i in 0..50 {
            let mem = make_memory_with_content(
                &format!("fit-{budget}-{i}"),
                Importance::Normal,
                &format!("Memory about topic {i} with enough content to test budget {budget}"),
            );

            let compressed = engine.compress_to_fit(&mem, budget).unwrap();
            // For reasonable budgets, should fit. For very small budgets, L0 is returned.
            if budget >= 15 {
                assert!(
                    compressed.token_count <= budget,
                    "Budget {budget}: compressed to {} tokens at level {} (exceeded)",
                    compressed.token_count,
                    compressed.level
                );
            } else {
                // Very small budgets: L0 is returned regardless.
                assert_eq!(
                    compressed.level, 0,
                    "Should fall back to L0 for tiny budget"
                );
            }
        }
    }
}

// ── Batch packing stress ─────────────────────────────────────────────────

#[test]
fn stress_batch_packing_100_memories() {
    let engine = CompressionEngine::new();
    let memories: Vec<BaseMemory> = (0..100)
        .map(|i| {
            let imp = match i % 4 {
                0 => Importance::Critical,
                1 => Importance::High,
                2 => Importance::Normal,
                _ => Importance::Low,
            };
            make_memory_with_content(
                &format!("batch-{i}"),
                imp,
                &format!("Batch memory {i} about engineering topic {}", i % 20),
            )
        })
        .collect();

    let budget = 2000;
    let start = Instant::now();
    let packed = engine.compress_batch_to_fit(&memories, budget).unwrap();
    let elapsed = start.elapsed();

    let total_tokens: usize = packed.iter().map(|c| c.token_count).sum();
    assert!(
        total_tokens <= budget,
        "Batch total {} exceeds budget {}",
        total_tokens,
        budget
    );
    assert!(elapsed.as_secs() < 5, "Batch packing took {:?}", elapsed);

    // Critical memories should be prioritized.
    if !packed.is_empty() {
        let critical_count = packed
            .iter()
            .filter(|c| c.importance == Importance::Critical)
            .count();
        let low_count = packed
            .iter()
            .filter(|c| c.importance == Importance::Low)
            .count();
        // With priority weighting, critical should appear more than low.
        assert!(
            critical_count >= low_count || packed.len() >= 100,
            "Critical ({}) should be >= Low ({}) in priority packing",
            critical_count,
            low_count
        );
    }
}

#[test]
fn stress_batch_packing_tight_budget() {
    let engine = CompressionEngine::new();
    let memories: Vec<BaseMemory> = (0..50)
        .map(|i| {
            make_memory_with_content(
                &format!("tight-{i}"),
                Importance::Normal,
                &format!("Memory {i}"),
            )
        })
        .collect();

    // Very tight budget — should still not exceed.
    let packed = engine.compress_batch_to_fit(&memories, 50).unwrap();
    let total: usize = packed.iter().map(|c| c.token_count).sum();
    assert!(total <= 50, "Tight budget exceeded: {} > 50", total);
}

// ── Edge cases ───────────────────────────────────────────────────────────

#[test]
fn stress_zero_budget_returns_empty() {
    let engine = CompressionEngine::new();
    let memories: Vec<BaseMemory> = (0..10)
        .map(|i| make_memory_with_content(&format!("zero-{i}"), Importance::Normal, "test"))
        .collect();

    let packed = engine.compress_batch_to_fit(&memories, 0).unwrap();
    assert!(packed.is_empty(), "Zero budget should return empty");
}

#[test]
fn stress_empty_batch_returns_empty() {
    let engine = CompressionEngine::new();
    let packed = engine.compress_batch_to_fit(&[], 1000).unwrap();
    assert!(packed.is_empty());
}

#[test]
fn stress_all_levels_produce_nonempty_text() {
    let engine = CompressionEngine::new();
    let mem = make_memory_with_content("nonempty", Importance::Normal, "Test memory content");

    for level in 0..=3 {
        let compressed = engine.compress(&mem, level).unwrap();
        assert!(
            !compressed.text.is_empty(),
            "Level {} produced empty text",
            level
        );
        assert!(compressed.token_count > 0, "Level {} has 0 tokens", level);
    }
}

// ── Performance ──────────────────────────────────────────────────────────

#[test]
fn stress_compression_throughput_1000() {
    let engine = CompressionEngine::new();
    let memories: Vec<BaseMemory> = (0..1000)
        .map(|i| {
            make_memory_with_content(
                &format!("perf-{i}"),
                Importance::Normal,
                &format!("Performance test memory number {i} with sufficient content"),
            )
        })
        .collect();

    let start = Instant::now();
    for mem in &memories {
        for level in 0..=3 {
            let _ = engine.compress(mem, level).unwrap();
        }
    }
    let elapsed = start.elapsed();

    // 4000 compressions should complete in under 10 seconds.
    assert!(
        elapsed.as_secs() < 10,
        "4000 compressions took {:?} (>10s)",
        elapsed
    );
}

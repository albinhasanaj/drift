//! Retrieval benchmarks.
//!
//! T5-RET-18: Retrieval 100 memories < 5ms p95
//! T5-RET-19: Retrieval 10K memories < 50ms p95
//! T5-RET-20: Hybrid search 10K < 30ms p95

use std::collections::HashMap;

use chrono::Utc;
use criterion::{criterion_group, criterion_main, Criterion};

use cortex_core::memory::{BaseMemory, Confidence, Importance, MemoryType, TypedContent};
use cortex_retrieval::search::rrf_fusion;

fn make_bench_memory(i: usize) -> BaseMemory {
    BaseMemory {
        id: format!("mem-{i}"),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(cortex_core::memory::types::CoreContent {
            project_name: String::new(),
            description: format!("Benchmark memory number {i} with some content for testing"),
            metadata: serde_json::Value::Null,
        }),
        summary: format!("Benchmark memory {i}"),
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
        tags: vec!["bench".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: format!("hash-{i}"),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

fn bench_rrf_100(c: &mut Criterion) {
    let n = 100;
    let mut memories = HashMap::new();
    for i in 0..n {
        let m = make_bench_memory(i);
        memories.insert(m.id.clone(), m);
    }

    let list1: Vec<(String, usize)> = (0..n).map(|i| (format!("mem-{i}"), i)).collect();
    let list2: Vec<(String, usize)> = (0..n)
        .rev()
        .map(|i| (format!("mem-{i}"), n - 1 - i))
        .collect();

    c.bench_function("rrf_fusion_100", |b| {
        b.iter(|| {
            rrf_fusion::fuse(Some(&list1), Some(&list2), None, &memories, 60);
        });
    });
}

fn bench_rrf_10k(c: &mut Criterion) {
    let n = 10_000;
    let mut memories = HashMap::new();
    for i in 0..n {
        let m = make_bench_memory(i);
        memories.insert(m.id.clone(), m);
    }

    let list1: Vec<(String, usize)> = (0..n).map(|i| (format!("mem-{i}"), i)).collect();
    let list2: Vec<(String, usize)> = (0..n)
        .rev()
        .map(|i| (format!("mem-{i}"), n - 1 - i))
        .collect();

    c.bench_function("rrf_fusion_10k", |b| {
        b.iter(|| {
            rrf_fusion::fuse(Some(&list1), Some(&list2), None, &memories, 60);
        });
    });
}

criterion_group!(benches, bench_rrf_100, bench_rrf_10k);
criterion_main!(benches);

use chrono::Utc;
use criterion::{criterion_group, criterion_main, Criterion};

use cortex_core::memory::types::*;
use cortex_core::memory::*;
use cortex_core::traits::IMemoryStorage;
use cortex_storage::StorageEngine;

fn make_memory(id: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Core,
        content: TypedContent::Core(CoreContent {
            project_name: "bench test".to_string(),
            description: "benchmarking".to_string(),
            metadata: serde_json::json!({}),
        }),
        summary: "benchmark memory".to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::Normal,
        last_accessed: Utc::now(),
        access_count: 0,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["bench".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: "bench_hash".to_string(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

fn bench_insert(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("bench.db");
    let engine = StorageEngine::open(&db_path).unwrap();
    let mut counter = 0u64;

    c.bench_function("insert_memory", |b| {
        b.iter(|| {
            counter += 1;
            let memory = make_memory(&format!("bench-{counter}"));
            engine.create(&memory).unwrap();
        });
    });
}

fn bench_get(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("bench_get.db");
    let engine = StorageEngine::open(&db_path).unwrap();

    // Pre-populate.
    for i in 0..100 {
        engine.create(&make_memory(&format!("get-{i}"))).unwrap();
    }

    c.bench_function("get_memory", |b| {
        let mut idx = 0;
        b.iter(|| {
            let id = format!("get-{}", idx % 100);
            engine.get(&id).unwrap();
            idx += 1;
        });
    });
}

fn bench_fts5_search(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("bench_fts.db");
    let engine = StorageEngine::open(&db_path).unwrap();

    // Pre-populate with varied content.
    for i in 0..100 {
        let mut mem = make_memory(&format!("fts-{i}"));
        mem.content = TypedContent::Core(CoreContent {
            project_name: format!("principle number {i} about benchmarking"),
            description: format!("rationale {i}"),
            metadata: serde_json::json!({}),
        });
        engine.create(&mem).unwrap();
    }

    c.bench_function("fts5_search", |b| {
        b.iter(|| {
            engine.search_fts5("benchmarking", 10).unwrap();
        });
    });
}

fn bench_bulk_insert(c: &mut Criterion) {
    c.bench_function("bulk_insert_100", |b| {
        b.iter(|| {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("bench_bulk.db");
            let engine = StorageEngine::open(&db_path).unwrap();
            let memories: Vec<BaseMemory> = (0..100)
                .map(|i| make_memory(&format!("bulk-{i}")))
                .collect();
            engine.create_bulk(&memories).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_insert,
    bench_get,
    bench_fts5_search,
    bench_bulk_insert
);
criterion_main!(benches);

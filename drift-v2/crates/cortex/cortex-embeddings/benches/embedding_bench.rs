use cortex_core::config::EmbeddingConfig;
use cortex_embeddings::EmbeddingEngine;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_tfidf_single(c: &mut Criterion) {
    let mut engine = EmbeddingEngine::new(EmbeddingConfig {
        provider: "tfidf".to_string(),
        dimensions: 1024,
        ..Default::default()
    });

    c.bench_function("tfidf_embed_single", |b| {
        b.iter(|| {
            engine
                .embed_query("rust programming language systems design patterns")
                .unwrap()
        })
    });
}

fn bench_tfidf_batch(c: &mut Criterion) {
    let engine = EmbeddingEngine::new(EmbeddingConfig {
        provider: "tfidf".to_string(),
        dimensions: 1024,
        ..Default::default()
    });

    let texts: Vec<String> = (0..10)
        .map(|i| format!("test embedding text number {i} with some content"))
        .collect();

    c.bench_function("tfidf_embed_batch_10", |b| {
        b.iter(|| {
            use cortex_core::traits::IEmbeddingProvider;
            engine.embed_batch(&texts).unwrap()
        })
    });
}

fn bench_cache_hit(c: &mut Criterion) {
    let mut engine = EmbeddingEngine::new(EmbeddingConfig {
        provider: "tfidf".to_string(),
        dimensions: 1024,
        ..Default::default()
    });

    // Prime the cache.
    engine.embed_query("cached query text").unwrap();

    c.bench_function("cache_hit_embed", |b| {
        b.iter(|| engine.embed_query("cached query text").unwrap())
    });
}

criterion_group!(
    benches,
    bench_tfidf_single,
    bench_tfidf_batch,
    bench_cache_hit
);
criterion_main!(benches);

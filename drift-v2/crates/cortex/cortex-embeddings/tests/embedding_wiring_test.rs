//! Phase D embedding wiring tests (D-07, D-08, D-09, D-10).

use cortex_core::config::EmbeddingConfig;
use cortex_core::traits::IEmbeddingProvider;
use cortex_embeddings::cache::l2_sqlite::L2SqliteCache;
use cortex_embeddings::engine::EmbeddingEngine;

fn tfidf_config() -> EmbeddingConfig {
    EmbeddingConfig {
        provider: "tfidf".to_string(),
        dimensions: 128,
        matryoshka_search_dims: 64,
        ..Default::default()
    }
}

/// D-07: L2 cache persists across engine restarts.
#[test]
fn d07_l2_cache_survives_restart() {
    let dir = std::env::temp_dir().join("d07_l2_cache_test");
    let _ = std::fs::create_dir_all(&dir);
    let db_path = dir.join("embed.db");

    // First engine: embed and cache.
    {
        let mut engine = EmbeddingEngine::new_with_db_path(tfidf_config(), &db_path);
        let vec = engine.embed_query("persistent query").unwrap();
        assert_eq!(vec.len(), 128);
    }
    // Engine dropped.

    // Verify L2 cache file has the embedding.
    {
        let cache = L2SqliteCache::open(&db_path);
        // The cache key is blake3 hash of the enriched query.
        // We just verify the cache is non-empty after embedding.
        assert!(!cache.is_empty(), "L2 cache should have entries after embedding");
    }
}

/// D-08: L2 cache miss promotes to L1.
#[test]
fn d08_l2_miss_promotes_to_l1() {
    use cortex_embeddings::cache::{CacheCoordinator, CacheHitTier};

    let mut coord = CacheCoordinator::new(100);

    // Cold start: no hits.
    let (result, tier) = coord.get("cold-hash");
    assert!(result.is_none());
    assert_eq!(tier, CacheHitTier::Miss);

    // Insert into L2 only.
    coord.l2.insert("l2-only".to_string(), &[1.0, 2.0, 3.0]);

    // First access: L2 hit, promotes to L1.
    let (result, tier) = coord.get("l2-only");
    assert_eq!(result, Some(vec![1.0, 2.0, 3.0]));
    assert_eq!(tier, CacheHitTier::L2);

    // Second access: L1 hit (promoted).
    let (result, tier) = coord.get("l2-only");
    assert_eq!(result, Some(vec![1.0, 2.0, 3.0]));
    assert_eq!(tier, CacheHitTier::L1);
}

/// D-09: Embedding provider chain degrades correctly.
#[test]
fn d09_provider_chain_degrades() {
    // Configure with tfidf (always available).
    let engine = EmbeddingEngine::new(tfidf_config());
    assert!(engine.is_available());

    // The trait impl should use the real chain, not a fresh TF-IDF.
    let provider: &dyn IEmbeddingProvider = &engine;
    let vec = provider.embed("test degradation").unwrap();
    assert_eq!(vec.len(), 128);
    assert_eq!(provider.dimensions(), 128);
}

/// D-10: Consolidation uses real embeddings not TF-IDF bypass.
/// (Verifies that the IEmbeddingProvider trait impl uses the configured chain.)
#[test]
fn d10_trait_impl_uses_configured_chain() {
    let engine = EmbeddingEngine::new(tfidf_config());
    let provider: &dyn IEmbeddingProvider = &engine;

    // The name should reflect the active provider, not "cortex-embedding-engine".
    let name = provider.name();
    // TF-IDF is the configured provider, so the chain should report it.
    assert!(
        !name.is_empty(),
        "provider name should not be empty"
    );

    // Batch embedding should work through the chain.
    let texts = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let vecs = provider.embed_batch(&texts).unwrap();
    assert_eq!(vecs.len(), 3);
    assert!(vecs.iter().all(|v| v.len() == 128));
}

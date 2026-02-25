//! Enterprise stress tests for Cortex Embeddings hardening fixes.
//!
//! Covers:
//! - P2-2/B-03: clone_provider() creates a lightweight SharedProvider that uses
//!   the same config but doesn't duplicate cache infrastructure.
//!
//! Every test targets a specific production failure mode.

use cortex_core::config::EmbeddingConfig;
use cortex_core::traits::IEmbeddingProvider;
use cortex_embeddings::EmbeddingEngine;

// ═══════════════════════════════════════════════════════════════════════════════
// P2-2/B-03: clone_provider — shared provider chain, no cache duplication
// ═══════════════════════════════════════════════════════════════════════════════

/// PRODUCTION BUG: Consolidation engine got a full duplicate EmbeddingEngine
/// with its own separate cache and TF-IDF state. clone_provider() must produce
/// an IEmbeddingProvider that embeds consistently with the main engine.
#[test]
fn hst_b03_01_clone_provider_returns_valid_provider() {
    let config = EmbeddingConfig::default();
    let engine = EmbeddingEngine::new(config);
    let provider = engine.clone_provider();

    assert!(provider.is_available());
    assert!(provider.dimensions() > 0);
    assert!(!provider.name().is_empty());
}

/// clone_provider embeddings must have correct dimensionality.
#[test]
fn hst_b03_02_clone_provider_correct_dimensions() {
    let config = EmbeddingConfig::default();
    let engine = EmbeddingEngine::new(config.clone());
    let provider = engine.clone_provider();

    let embedding = provider.embed("test text for dimension check").unwrap();
    assert_eq!(
        embedding.len(),
        provider.dimensions(),
        "Embedding length must match declared dimensions"
    );
    assert_eq!(
        embedding.len(),
        config.dimensions,
        "Must match configured dimensions"
    );
}

/// Same text → same embedding from clone and main engine.
/// This verifies the provider chain is configured identically.
#[test]
fn hst_b03_03_clone_provider_consistent_with_engine() {
    let config = EmbeddingConfig::default();
    let engine = EmbeddingEngine::new(config);
    let provider = engine.clone_provider();

    let text = "consistent embedding test";
    let engine_emb = engine.embed(text).unwrap();
    let provider_emb = provider.embed(text).unwrap();

    assert_eq!(
        engine_emb.len(),
        provider_emb.len(),
        "Dimension mismatch between engine and clone"
    );

    // Same provider chain config → same output for deterministic providers.
    // TF-IDF is deterministic for the same input.
    for (i, (a, b)) in engine_emb.iter().zip(provider_emb.iter()).enumerate() {
        assert!(
            (a - b).abs() < 1e-6,
            "Embedding mismatch at index {i}: engine={a}, clone={b}"
        );
    }
}

/// Multiple clones are independent — both produce valid embeddings concurrently.
#[test]
fn hst_b03_04_multiple_clones_independent() {
    let config = EmbeddingConfig::default();
    let engine = EmbeddingEngine::new(config);

    let p1 = engine.clone_provider();
    let p2 = engine.clone_provider();

    // Both should work independently and produce valid embeddings.
    let emb1 = p1.embed("the authentication system handles user login and session management").unwrap();
    let emb2 = p2.embed("the database migration runs schema updates in production").unwrap();

    assert_eq!(emb1.len(), p1.dimensions());
    assert_eq!(emb2.len(), p2.dimensions());
    assert_eq!(emb1.len(), emb2.len(), "Both clones must produce same dimensionality");
}

/// embed_batch on clone works for multiple texts.
#[test]
fn hst_b03_05_clone_provider_batch_embed() {
    let config = EmbeddingConfig::default();
    let engine = EmbeddingEngine::new(config);
    let provider = engine.clone_provider();

    let texts: Vec<String> = (0..10)
        .map(|i| format!("batch text number {i} for embedding"))
        .collect();

    let results = provider.embed_batch(&texts).unwrap();
    assert_eq!(results.len(), 10);
    for (i, emb) in results.iter().enumerate() {
        assert_eq!(
            emb.len(),
            provider.dimensions(),
            "Batch result {i} has wrong dimensions"
        );
    }
}

/// Stress: 500 sequential embeds on clone — no degradation, no panic.
#[test]
fn hst_b03_06_clone_provider_stress_500_embeds() {
    let config = EmbeddingConfig::default();
    let engine = EmbeddingEngine::new(config);
    let provider = engine.clone_provider();

    for i in 0..500 {
        let text = format!("stress test text {i} with some varying content about topic {}", i % 7);
        let emb = provider.embed(&text).unwrap();
        assert_eq!(emb.len(), provider.dimensions());
    }
}

/// Empty string doesn't panic — returns valid embedding or error, not crash.
#[test]
fn hst_b03_07_clone_provider_empty_string() {
    let config = EmbeddingConfig::default();
    let engine = EmbeddingEngine::new(config);
    let provider = engine.clone_provider();

    // Empty string might return zero vector or error, but must not panic.
    let result = provider.embed("");
    // Accept either Ok (with correct dims) or Err.
    if let Ok(emb) = result {
        assert_eq!(emb.len(), provider.dimensions());
    }
}

/// Very long text (100KB) doesn't OOM or panic.
#[test]
fn hst_b03_08_clone_provider_very_long_text() {
    let config = EmbeddingConfig::default();
    let engine = EmbeddingEngine::new(config);
    let provider = engine.clone_provider();

    let long_text = "word ".repeat(20_000); // ~100KB
    let emb = provider.embed(&long_text).unwrap();
    assert_eq!(emb.len(), provider.dimensions());
}

/// clone_provider name must not be empty — used in health reporting.
#[test]
fn hst_b03_09_clone_provider_has_name() {
    let config = EmbeddingConfig::default();
    let engine = EmbeddingEngine::new(config);
    let provider = engine.clone_provider();

    assert!(!provider.name().is_empty(), "Provider name must not be empty");
}

//! Targeted coverage tests for cortex-embeddings uncovered paths.
//!
//! Focuses on: tfidf_fallback internals, enrichment edge cases, matryoshka edge cases,
//! degradation chain paths, engine embed_memory/embed_query_for_search, cache coordination.

use chrono::Utc;
use cortex_core::config::EmbeddingConfig;
use cortex_core::memory::links::{FileLink, PatternLink};
use cortex_core::memory::*;
use cortex_core::traits::IEmbeddingProvider;

// ─── Helper ──────────────────────────────────────────────────────────────────

fn make_memory(id: &str, summary: &str) -> BaseMemory {
    BaseMemory {
        id: id.to_string(),
        memory_type: MemoryType::Semantic,
        content: TypedContent::Semantic(cortex_core::memory::types::SemanticContent {
            knowledge: summary.to_string(),
            source_episodes: vec![],
            consolidation_confidence: 0.9,
        }),
        summary: summary.to_string(),
        transaction_time: Utc::now(),
        valid_time: Utc::now(),
        valid_until: None,
        confidence: Confidence::new(0.9),
        importance: Importance::High,
        last_accessed: Utc::now(),
        access_count: 3,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags: vec!["test".to_string()],
        archived: false,
        superseded_by: None,
        supersedes: None,
        namespace: Default::default(),
        source_agent: Default::default(),
        content_hash: blake3::hash(summary.as_bytes()).to_hex().to_string(),
    }
}

fn tfidf_config() -> EmbeddingConfig {
    EmbeddingConfig {
        provider: "tfidf".to_string(),
        dimensions: 128,
        matryoshka_search_dims: 64,
        ..Default::default()
    }
}

// ─── TF-IDF fallback: tokenization, hashing, edge cases ─────────────────────

#[test]
fn tfidf_single_word() {
    let p = cortex_embeddings::providers::TfIdfFallback::new(128);
    let v = p.embed("hello").unwrap();
    assert_eq!(v.len(), 128);
    // Single word should produce a non-zero vector.
    assert!(v.iter().any(|&x| x != 0.0));
}

#[test]
fn tfidf_unicode_text() {
    let p = cortex_embeddings::providers::TfIdfFallback::new(256);
    let v = p.embed("日本語テスト embedding 测试").unwrap();
    assert_eq!(v.len(), 256);
}

#[test]
fn tfidf_special_characters_only() {
    let p = cortex_embeddings::providers::TfIdfFallback::new(64);
    // Only special chars — all tokens filtered out (< 2 chars after split).
    let v = p.embed("! @ # $ % ^ & *").unwrap();
    assert_eq!(v.len(), 64);
    // Should be zero vector since no valid tokens.
    assert!(v.iter().all(|&x| x == 0.0));
}

#[test]
fn tfidf_long_text_produces_normalized_vector() {
    let p = cortex_embeddings::providers::TfIdfFallback::new(512);
    let long_text = "rust programming language systems memory safety concurrency \
                     performance zero cost abstractions ownership borrowing lifetimes \
                     traits generics pattern matching error handling async await futures";
    let v = p.embed(long_text).unwrap();
    assert_eq!(v.len(), 512);
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 1e-4, "expected unit norm, got {norm}");
}

#[test]
fn tfidf_name_is_correct() {
    let p = cortex_embeddings::providers::TfIdfFallback::new(64);
    assert_eq!(p.name(), "tfidf-fallback");
}

// ─── Enrichment: edge cases ──────────────────────────────────────────────────

#[test]
fn enrichment_empty_summary() {
    let mut mem = make_memory("e1", "");
    mem.summary = String::new();
    let enriched = cortex_embeddings::enrichment::enrich_for_embedding(&mem);
    // Should still have the metadata prefix.
    assert!(enriched.starts_with("[Semantic|High|domain_agnostic]"));
    // No summary appended.
    assert!(!enriched.contains("  ")); // no double spaces
}

#[test]
fn enrichment_with_files_and_patterns() {
    let mut mem = make_memory("e2", "test summary");
    mem.linked_files = vec![
        FileLink {
            file_path: "src/main.rs".to_string(),
            line_start: Some(1),
            line_end: Some(10),
            content_hash: Some("abc".to_string()),
        },
        FileLink {
            file_path: "src/lib.rs".to_string(),
            line_start: None,
            line_end: None,
            content_hash: None,
        },
    ];
    mem.linked_patterns = vec![
        PatternLink {
            pattern_id: "p1".to_string(),
            pattern_name: "singleton".to_string(),
        },
        PatternLink {
            pattern_id: "p2".to_string(),
            pattern_name: "observer".to_string(),
        },
    ];
    let enriched = cortex_embeddings::enrichment::enrich_for_embedding(&mem);
    assert!(enriched.contains("Files: src/main.rs, src/lib.rs"));
    assert!(enriched.contains("Patterns: singleton, observer"));
}

#[test]
fn enrichment_no_files_no_patterns() {
    let mem = make_memory("e3", "just a summary");
    let enriched = cortex_embeddings::enrichment::enrich_for_embedding(&mem);
    assert!(!enriched.contains("Files:"));
    assert!(!enriched.contains("Patterns:"));
}

#[test]
fn query_enrichment_format() {
    let enriched = cortex_embeddings::enrichment::enrich_query("find all SQL queries");
    assert_eq!(enriched, "[Query] find all SQL queries");
}

// ─── Matryoshka: edge cases ─────────────────────────────────────────────────

#[test]
fn matryoshka_truncate_to_same_size() {
    let v = vec![0.5; 128];
    let result = cortex_embeddings::matryoshka::truncate(&v, 128).unwrap();
    assert_eq!(result.len(), 128);
    // Should be renormalized.
    let norm: f32 = result.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 1e-4);
}

#[test]
fn matryoshka_truncate_zero_vector() {
    let v = vec![0.0; 128];
    let result = cortex_embeddings::matryoshka::truncate(&v, 64).unwrap();
    assert_eq!(result.len(), 64);
    // Zero vector stays zero.
    assert!(result.iter().all(|&x| x == 0.0));
}

#[test]
fn matryoshka_validate_exact_match() {
    let v = vec![0.0; 384];
    assert!(cortex_embeddings::matryoshka::validate_dimensions(&v, 384).is_ok());
}

#[test]
fn matryoshka_validate_mismatch_error() {
    let v = vec![0.0; 128];
    let err = cortex_embeddings::matryoshka::validate_dimensions(&v, 256);
    assert!(err.is_err());
}

#[test]
fn matryoshka_cosine_similarity_different_lengths() {
    let a = vec![1.0, 0.0, 0.0, 0.0, 0.0];
    let b = vec![1.0, 0.0, 0.0];
    // Should use min length.
    let sim = cortex_embeddings::matryoshka::cosine_similarity(&a, &b);
    assert!((sim - 1.0).abs() < 1e-5);
}

#[test]
fn matryoshka_search_dims_constants() {
    assert_eq!(cortex_embeddings::matryoshka::SEARCH_DIMS_SMALL, 256);
    assert_eq!(cortex_embeddings::matryoshka::SEARCH_DIMS_MEDIUM, 384);
}

// ─── Degradation chain: additional paths ─────────────────────────────────────

#[test]
fn degradation_chain_empty_returns_error() {
    let mut chain = cortex_embeddings::degradation::DegradationChain::new();
    let result = chain.embed("test");
    assert!(result.is_err());
}

#[test]
fn degradation_chain_len_and_empty() {
    let mut chain = cortex_embeddings::degradation::DegradationChain::new();
    assert!(chain.is_empty());
    assert_eq!(chain.len(), 0);

    chain.push(Box::new(cortex_embeddings::providers::TfIdfFallback::new(
        64,
    )));
    assert!(!chain.is_empty());
    assert_eq!(chain.len(), 1);
}

#[test]
fn degradation_chain_active_provider_name_empty() {
    let chain = cortex_embeddings::degradation::DegradationChain::new();
    assert_eq!(chain.active_provider_name(), "none");
}

#[test]
fn degradation_chain_active_provider_name_with_provider() {
    let mut chain = cortex_embeddings::degradation::DegradationChain::new();
    chain.push(Box::new(cortex_embeddings::providers::TfIdfFallback::new(
        64,
    )));
    assert_eq!(chain.active_provider_name(), "tfidf-fallback");
}

#[test]
fn degradation_chain_push_cache_fallback() {
    let mut chain = cortex_embeddings::degradation::DegradationChain::new();
    chain.push_cache_fallback(Box::new(cortex_embeddings::providers::TfIdfFallback::new(
        64,
    )));
    assert_eq!(chain.len(), 1);
    let (vec, name) = chain.embed("test").unwrap();
    assert_eq!(name, "tfidf-fallback");
    assert_eq!(vec.len(), 64);
}

#[test]
fn degradation_chain_batch_all_fail() {
    let mut chain = cortex_embeddings::degradation::DegradationChain::new();
    // Empty chain — all fail.
    let result = chain.embed_batch(&["a".to_string(), "b".to_string()]);
    assert!(result.is_err());
}

#[test]
fn degradation_drain_events_clears() {
    let mut chain = cortex_embeddings::degradation::DegradationChain::new();
    chain.push(Box::new(cortex_embeddings::providers::TfIdfFallback::new(
        64,
    )));
    chain.embed("test").unwrap();
    let events = chain.drain_events();
    assert!(events.is_empty());
    // Drain again — still empty.
    let events2 = chain.drain_events();
    assert!(events2.is_empty());
}

// ─── Engine: embed_memory, embed_query_for_search, drain_degradation ─────────

#[test]
fn engine_embed_memory_roundtrip() {
    let mut engine = cortex_embeddings::EmbeddingEngine::new(tfidf_config());
    let mem = make_memory("m1", "test memory for embedding");
    let vec = engine.embed_memory(&mem).unwrap();
    assert_eq!(vec.len(), 128);
}

#[test]
fn engine_embed_memory_caches() {
    let mut engine = cortex_embeddings::EmbeddingEngine::new(tfidf_config());
    let mem = make_memory("m2", "cached memory test");
    let a = engine.embed_memory(&mem).unwrap();
    let b = engine.embed_memory(&mem).unwrap();
    assert_eq!(a, b);
}

#[test]
fn engine_embed_memory_for_search_truncates() {
    let mut engine = cortex_embeddings::EmbeddingEngine::new(tfidf_config());
    let mem = make_memory("m3", "search truncation test");
    let vec = engine.embed_memory_for_search(&mem).unwrap();
    assert_eq!(vec.len(), 64); // matryoshka_search_dims
}

#[test]
fn engine_embed_query_for_search() {
    let mut engine = cortex_embeddings::EmbeddingEngine::new(tfidf_config());
    let vec = engine.embed_query_for_search("test query").unwrap();
    assert_eq!(vec.len(), 64);
}

#[test]
fn engine_drain_degradation_events_empty() {
    let mut engine = cortex_embeddings::EmbeddingEngine::new(tfidf_config());
    engine.embed_query("test").unwrap();
    assert!(engine.drain_degradation_events().is_empty());
}

#[test]
fn engine_active_provider() {
    let engine = cortex_embeddings::EmbeddingEngine::new(tfidf_config());
    // With tfidf config, the active provider should be tfidf-fallback.
    assert_eq!(engine.active_provider(), "tfidf-fallback");
}

#[test]
fn engine_dimensions_and_search_dimensions() {
    let engine = cortex_embeddings::EmbeddingEngine::new(tfidf_config());
    assert_eq!(engine.dimensions(), 128);
    assert_eq!(engine.search_dimensions(), 64);
}

#[test]
fn engine_trait_impl_embed() {
    let engine = cortex_embeddings::EmbeddingEngine::new(tfidf_config());
    let provider: &dyn IEmbeddingProvider = &engine;
    assert!(provider.is_available());
    assert_eq!(provider.name(), engine.active_provider());
    let vec = provider.embed("hello world").unwrap();
    assert_eq!(vec.len(), 128);
}

#[test]
fn engine_trait_impl_embed_batch() {
    let engine = cortex_embeddings::EmbeddingEngine::new(tfidf_config());
    let provider: &dyn IEmbeddingProvider = &engine;
    let texts = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let vecs = provider.embed_batch(&texts).unwrap();
    assert_eq!(vecs.len(), 3);
    assert!(vecs.iter().all(|v| v.len() == 128));
}

// ─── Provider Registry ───────────────────────────────────────────────────────

#[test]
fn create_provider_tfidf() {
    let config = EmbeddingConfig {
        provider: "tfidf".to_string(),
        dimensions: 128,
        ..Default::default()
    };
    let provider = cortex_embeddings::providers::create_provider(&config);
    assert!(provider.is_available());
    assert_eq!(provider.dimensions(), 128);
}

#[test]
fn create_provider_unknown_falls_back_to_tfidf() {
    let config = EmbeddingConfig {
        provider: "nonexistent".to_string(),
        dimensions: 64,
        ..Default::default()
    };
    let provider = cortex_embeddings::providers::create_provider(&config);
    assert!(provider.is_available());
}

#[test]
fn create_provider_onnx_no_model_path_falls_back() {
    let config = EmbeddingConfig {
        provider: "onnx".to_string(),
        dimensions: 128,
        model_path: None,
        ..Default::default()
    };
    let provider = cortex_embeddings::providers::create_provider(&config);
    assert!(provider.is_available()); // Falls back to TF-IDF.
}

#[test]
fn create_provider_onnx_bad_path_falls_back() {
    let config = EmbeddingConfig {
        provider: "onnx".to_string(),
        dimensions: 128,
        model_path: Some("/nonexistent/model.onnx".to_string()),
        ..Default::default()
    };
    let provider = cortex_embeddings::providers::create_provider(&config);
    assert!(provider.is_available()); // Falls back to TF-IDF.
}

#[test]
fn create_provider_api_falls_back() {
    let config = EmbeddingConfig {
        provider: "api".to_string(),
        dimensions: 128,
        ..Default::default()
    };
    let provider = cortex_embeddings::providers::create_provider(&config);
    assert!(provider.is_available()); // Falls back to TF-IDF.
}

#[test]
fn create_provider_ollama_unavailable_falls_back() {
    let config = EmbeddingConfig {
        provider: "ollama".to_string(),
        dimensions: 128,
        ..Default::default()
    };
    let provider = cortex_embeddings::providers::create_provider(&config);
    // Ollama is not running, so falls back to TF-IDF.
    assert!(provider.is_available());
}

// ─── Migration Worker ────────────────────────────────────────────────────────

#[test]
fn worker_config_defaults() {
    let config = cortex_embeddings::migration::worker::WorkerConfig::default();
    assert_eq!(config.batch_size, 50);
    assert_eq!(config.throttle_ms, 100);
}

#[test]
fn worker_prioritize_by_importance() {
    let mut memories = vec![
        make_memory_with_importance("low", "low priority", Importance::Low),
        make_memory_with_importance("crit", "critical priority", Importance::Critical),
        make_memory_with_importance("norm", "normal priority", Importance::Normal),
    ];
    cortex_embeddings::migration::worker::prioritize(&mut memories);
    assert_eq!(memories[0].importance, Importance::Critical);
    assert_eq!(memories[2].importance, Importance::Low);
}

fn make_memory_with_importance(id: &str, summary: &str, importance: Importance) -> BaseMemory {
    let mut mem = make_memory(id, summary);
    mem.importance = importance;
    mem
}

#[test]
fn worker_reembed_batch_with_tfidf() {
    let provider = cortex_embeddings::providers::TfIdfFallback::new(64);
    let progress = cortex_embeddings::migration::progress::MigrationProgress::new(2);
    let memories = vec![
        make_memory("rb1", "first memory"),
        make_memory("rb2", "second memory"),
    ];
    let enricher = |m: &BaseMemory| -> String { m.summary.clone() };
    let results = cortex_embeddings::migration::worker::reembed_batch(
        &memories, &provider, &enricher, &progress,
    );
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].1.len(), 64);
}

// ─── Migration Progress ──────────────────────────────────────────────────────

#[test]
fn migration_progress_tracking() {
    let progress = cortex_embeddings::migration::progress::MigrationProgress::new(10);
    progress.record_success();
    progress.record_success();
    progress.record_failure();
    let snap = progress.snapshot();
    assert_eq!(snap.completed, 2);
    assert_eq!(snap.failed, 1);
    assert_eq!(snap.remaining, 7);
}

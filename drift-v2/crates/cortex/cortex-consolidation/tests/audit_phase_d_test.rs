//! Phase D tests — D-T01 through D-T03.
//!
//! Tests for LlmPolisher constructor injection and LlmExtractor injection.

use cortex_consolidation::engine::ConsolidationEngine;
use cortex_consolidation::llm_polish::LlmPolisher;
use cortex_core::traits::IEmbeddingProvider;

/// Simple test embedding provider.
struct TestProvider;

impl IEmbeddingProvider for TestProvider {
    fn embed(&self, _text: &str) -> cortex_core::errors::CortexResult<Vec<f32>> {
        Ok(vec![0.1; 64])
    }

    fn embed_batch(
        &self,
        texts: &[String],
    ) -> cortex_core::errors::CortexResult<Vec<Vec<f32>>> {
        Ok(texts.iter().map(|_| vec![0.1; 64]).collect())
    }

    fn dimensions(&self) -> usize {
        64
    }

    fn name(&self) -> &str {
        "test-provider"
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// A test polisher that wraps text.
struct TestPolisher;

impl LlmPolisher for TestPolisher {
    fn polish(&self, summary: &str) -> Option<String> {
        Some(format!("[polished] {summary}"))
    }
}

// ── D-T01: Default ConsolidationEngine uses NoOpPolisher ────────────────────

/// D-T01: ConsolidationEngine defaults to NoOpPolisher.
#[test]
fn dt01_default_noop_polisher() {
    let engine = ConsolidationEngine::new(Box::new(TestProvider));
    let result = engine.polisher().polish("test summary");
    assert!(
        result.is_none(),
        "NoOpPolisher should return None"
    );
}

// ── D-T02: ConsolidationEngine with injected polisher ───────────────────────

/// D-T02: with_polisher injects a real polisher.
#[test]
fn dt02_injected_polisher_works() {
    let engine = ConsolidationEngine::new(Box::new(TestProvider))
        .with_polisher(Box::new(TestPolisher));

    let result = engine.polisher().polish("my summary");
    assert_eq!(
        result,
        Some("[polished] my summary".to_string()),
        "injected polisher should transform the summary"
    );
}

/// D-T02b: set_polisher replaces the polisher after construction.
#[test]
fn dt02b_set_polisher_replaces() {
    let mut engine = ConsolidationEngine::new(Box::new(TestProvider));

    // Initially NoOp.
    assert!(engine.polisher().polish("x").is_none());

    // Replace with real polisher.
    engine.set_polisher(Box::new(TestPolisher));
    assert_eq!(
        engine.polisher().polish("x"),
        Some("[polished] x".to_string())
    );
}

// ── D-T03: LlmPolisher trait contract ───────────────────────────────────────

/// D-T03: Multiple polisher swaps work correctly.
#[test]
fn dt03_polisher_swap_lifecycle() {
    let mut engine = ConsolidationEngine::new(Box::new(TestProvider));

    // Start with NoOp.
    assert!(engine.polisher().polish("x").is_none());

    // Swap to TestPolisher.
    engine.set_polisher(Box::new(TestPolisher));
    assert_eq!(engine.polisher().polish("x"), Some("[polished] x".to_string()));

    // Swap back to a different NoOp-like polisher.
    struct AlwaysNone;
    impl LlmPolisher for AlwaysNone {
        fn polish(&self, _summary: &str) -> Option<String> { None }
    }
    engine.set_polisher(Box::new(AlwaysNone));
    assert!(engine.polisher().polish("x").is_none());
}

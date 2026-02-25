#![allow(clippy::single_match)]
//! T14-INT-01: Full lifecycle integration test.
//!
//! Create 50 episodic → consolidate → retrieve → decay → validate
//! All stages complete without error.

use chrono::{Duration, Utc};
use cortex_compression::CompressionEngine;
use cortex_consolidation::engine::ConsolidationEngine;
use cortex_core::config::RetrievalConfig;
use cortex_core::errors::CortexResult;
use cortex_core::memory::types::EpisodicContent;
use cortex_core::memory::*;
use cortex_core::models::RetrievalContext;
use cortex_core::traits::{IConsolidator, IEmbeddingProvider, IMemoryStorage, IRetriever};
use cortex_decay::{DecayContext, DecayEngine};
use cortex_retrieval::engine::RetrievalEngine;
use cortex_storage::StorageEngine;
use cortex_validation::engine::{ValidationConfig, ValidationEngine};

// ---------------------------------------------------------------------------
// Test embedder
// ---------------------------------------------------------------------------

struct LifecycleEmbedder;

impl IEmbeddingProvider for LifecycleEmbedder {
    fn embed(&self, text: &str) -> CortexResult<Vec<f32>> {
        let hash = blake3::hash(text.as_bytes());
        let bytes = hash.as_bytes();
        Ok((0..64)
            .map(|i| (bytes[i % 32] as f32 / 255.0) * 2.0 - 1.0)
            .collect())
    }
    fn embed_batch(&self, texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
        texts.iter().map(|t| self.embed(t)).collect()
    }
    fn dimensions(&self) -> usize {
        64
    }
    fn name(&self) -> &str {
        "lifecycle-test"
    }
    fn is_available(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_episodic(cluster: &str, index: usize, tags: Vec<String>) -> BaseMemory {
    let interaction = format!(
        "Working on {} topic, iteration {}. Discussed implementation details and best practices.",
        cluster, index
    );
    let content = TypedContent::Episodic(EpisodicContent {
        interaction: interaction.clone(),
        context: format!("{} session {}", cluster, index),
        outcome: Some(format!("Completed {} task {}", cluster, index)),
    });
    let now = Utc::now();
    BaseMemory {
        id: format!("{}-ep-{:03}", cluster, index),
        memory_type: MemoryType::Episodic,
        content: content.clone(),
        summary: format!("{} knowledge point {}", cluster, index),
        transaction_time: now - Duration::days(10),
        valid_time: now - Duration::days(10),
        valid_until: None,
        confidence: Confidence::new(0.75 + (index as f64 * 0.01)),
        importance: Importance::Normal,
        last_accessed: now,
        access_count: (index as u64) + 1,
        linked_patterns: vec![],
        linked_constraints: vec![],
        linked_files: vec![],
        linked_functions: vec![],
        tags,
        archived: false,
        superseded_by: None,
        supersedes: None,
        content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        namespace: Default::default(),
        source_agent: Default::default(),
    }
}

fn create_50_episodic_memories() -> Vec<BaseMemory> {
    let clusters = [
        (
            "database_config",
            vec!["database".to_string(), "config".to_string()],
        ),
        (
            "error_handling",
            vec!["errors".to_string(), "rust".to_string()],
        ),
        (
            "authentication",
            vec!["auth".to_string(), "security".to_string()],
        ),
        (
            "caching_strategy",
            vec!["cache".to_string(), "performance".to_string()],
        ),
        (
            "deployment_pipeline",
            vec!["ci".to_string(), "deployment".to_string()],
        ),
    ];

    let mut memories = Vec::with_capacity(50);
    for (cluster_name, tags) in &clusters {
        for i in 0..10 {
            memories.push(make_episodic(cluster_name, i, tags.clone()));
        }
    }
    memories
}

// ===========================================================================
// T14-INT-01: Full lifecycle test
// ===========================================================================

#[test]
fn t14_int_01_full_lifecycle() {
    let start = std::time::Instant::now();

    // ── Step 1: Create 50 episodic memories across 5 topic clusters ──
    let memories = create_50_episodic_memories();
    assert_eq!(memories.len(), 50, "Should create exactly 50 memories");
    assert!(
        memories
            .iter()
            .all(|m| m.memory_type == MemoryType::Episodic),
        "All should be episodic"
    );
    assert!(
        memories.iter().all(|m| m.confidence.value() >= 0.7),
        "All confidence should be >= 0.7"
    );

    // Store in storage engine.
    let storage = StorageEngine::open_in_memory().unwrap();
    for m in &memories {
        storage.create(m).unwrap();
    }

    // Verify all stored.
    for m in &memories {
        let retrieved = storage.get(&m.id).unwrap();
        assert!(
            retrieved.is_some(),
            "Memory '{}' should be retrievable",
            m.id
        );
    }

    // ── Step 2: Run consolidation ──
    let consolidation_engine = ConsolidationEngine::new(Box::new(LifecycleEmbedder));
    let result = consolidation_engine.consolidate(&memories).unwrap();

    // Should create some semantic memories (3-10 expected from 5 clusters).
    assert!(
        result.created.len() >= 3,
        "Expected at least 3 semantic memories from 5 clusters, got {}",
        result.created.len()
    );
    assert!(
        result.created.len() <= 10,
        "Expected at most 10 semantic memories, got {}",
        result.created.len()
    );

    // Should archive some episodic memories.
    assert!(
        result.archived.len() >= 20,
        "Expected at least 20 episodic memories archived, got {}",
        result.archived.len()
    );

    // Metrics should be valid.
    assert!(
        result.metrics.precision >= 0.3,
        "Precision too low: {}",
        result.metrics.precision
    );

    // Store the new semantic memories (we only have IDs from consolidation).
    // In a real system, the pipeline would store them. For this test,
    // we verify the IDs were generated.

    // ── Step 3: Retrieve — query each topic ──
    let compressor = CompressionEngine::new();
    let config = RetrievalConfig::default();
    let retrieval_engine = RetrievalEngine::new(&storage, &compressor, config);

    // FTS5 uses AND semantics — all query terms must appear in the document.
    // Use single terms that match the memory content (cluster names + tags).
    let queries = ["database", "errors", "auth", "cache", "deployment"];

    for query in &queries {
        let context = RetrievalContext {
            focus: query.to_string(),
            intent: None,
            active_files: vec![],
            budget: 2000,
            sent_ids: vec![],
        };

        let results = retrieval_engine.retrieve(&context, 2000).unwrap();
        assert!(
            !results.is_empty(),
            "Query '{}' should return at least 1 result, got {}",
            query,
            results.len()
        );

        // Budget should never be exceeded.
        let total_tokens: usize = results.iter().map(|r| r.token_count).sum();
        assert!(
            total_tokens <= 2000,
            "Query '{}': total tokens {} exceeds budget 2000",
            query,
            total_tokens
        );
    }

    // ── Step 4: Decay — simulate 30 days passage ──
    let decay_engine = DecayEngine::new();
    let decay_ctx = DecayContext {
        now: Utc::now() + Duration::days(30),
        stale_citation_ratio: 0.0,
        has_active_patterns: false,
    };

    let mut all_decayed_bounded = true;
    let mut all_decreased = true;

    for m in &memories {
        if m.archived {
            continue;
        }
        let decayed = decay_engine.calculate_with_context(m, &decay_ctx).unwrap();

        // Bounded 0.0-1.0.
        if !(0.0..=1.0).contains(&decayed) {
            all_decayed_bounded = false;
        }

        // Should decrease (or stay same for very high importance).
        if decayed > m.confidence.value() + f64::EPSILON {
            all_decreased = false;
        }
    }

    assert!(
        all_decayed_bounded,
        "All decayed confidences should be in [0.0, 1.0]"
    );
    assert!(
        all_decreased,
        "Confidences should decrease after 30 days without access"
    );

    // ── Step 5: Validate — run 4-dimension validation ──
    let validation_engine = ValidationEngine::new(ValidationConfig::default());

    let all_memories: Vec<BaseMemory> = memories.clone();

    let all_validated = true;
    let mut all_scores_bounded = true;

    for m in &all_memories {
        let val_result = validation_engine.validate_basic(m, &all_memories).unwrap();

        if val_result.overall_score < 0.0 || val_result.overall_score > 1.0 {
            all_scores_bounded = false;
        }

        let scores = &val_result.dimension_scores;
        if scores.citation < 0.0
            || scores.citation > 1.0
            || scores.temporal < 0.0
            || scores.temporal > 1.0
            || scores.contradiction < 0.0
            || scores.contradiction > 1.0
            || scores.pattern_alignment < 0.0
            || scores.pattern_alignment > 1.0
        {
            all_scores_bounded = false;
        }

        // Mark as validated (no-op: all_validated stays true if loop completes).
    }

    assert!(
        all_validated,
        "All memories should be validated without error"
    );
    assert!(
        all_scores_bounded,
        "All dimension scores should be in [0.0, 1.0]"
    );

    // ── Success criteria ──
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 30,
        "Full lifecycle should complete in < 30s, took {:?}",
        elapsed
    );
}

// ===========================================================================
// T14-INT-02: Concurrent access test
// ===========================================================================

#[test]
fn t14_int_02_concurrent_access() {
    let storage = StorageEngine::open_in_memory().unwrap();

    // Seed 100 memories.
    let memories: Vec<BaseMemory> = (0..100)
        .map(|i| {
            let content = TypedContent::Core(cortex_core::memory::types::CoreContent {
                project_name: String::new(),
                description: format!("Memory {}", i),
                metadata: serde_json::Value::Null,
            });
            BaseMemory {
                id: format!("concurrent-{:03}", i),
                memory_type: MemoryType::Semantic,
                content: content.clone(),
                summary: format!("Concurrent test memory {}", i),
                transaction_time: Utc::now(),
                valid_time: Utc::now(),
                valid_until: None,
                confidence: Confidence::new(0.8),
                importance: Importance::Normal,
                last_accessed: Utc::now(),
                access_count: 1,
                linked_patterns: vec![],
                linked_constraints: vec![],
                linked_files: vec![],
                linked_functions: vec![],
                tags: vec!["concurrent".to_string()],
                archived: false,
                superseded_by: None,
                supersedes: None,
                content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
                namespace: Default::default(),
                source_agent: Default::default(),
            }
        })
        .collect();

    for m in &memories {
        storage.create(m).unwrap();
    }

    // Use std::thread for concurrent access (no tokio needed).
    let storage = std::sync::Arc::new(storage);
    let errors = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reads_completed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut handles = Vec::new();

    // 10 reader threads, each reads 50 random memories.
    for reader_id in 0..10 {
        let storage = storage.clone();
        let errors = errors.clone();
        let reads_completed = reads_completed.clone();

        handles.push(std::thread::spawn(move || {
            for i in 0..50 {
                let id = format!("concurrent-{:03}", (reader_id * 10 + i) % 100);
                match storage.get(&id) {
                    Ok(Some(_)) => {
                        reads_completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Ok(None) => {
                        // Memory might have been deleted by writer — acceptable.
                    }
                    Err(_) => {
                        errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // 1 writer thread, updates 10 memories.
    {
        let storage = storage.clone();
        let errors = errors.clone();

        handles.push(std::thread::spawn(move || {
            for i in 0..10 {
                let id = format!("concurrent-{:03}", i);
                if let Ok(Some(mut m)) = storage.get(&id) {
                    m.summary = format!("Updated concurrent memory {}", i);
                    m.access_count += 1;
                    if storage.update(&m).is_err() {
                        errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // Wait for all threads.
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let error_count = errors.load(std::sync::atomic::Ordering::Relaxed);
    let read_count = reads_completed.load(std::sync::atomic::Ordering::Relaxed);

    assert_eq!(
        error_count, 0,
        "No errors should occur during concurrent access"
    );
    assert!(read_count > 0, "Some reads should complete successfully");

    // Verify data integrity after concurrent access.
    for i in 0..100 {
        let id = format!("concurrent-{:03}", i);
        let m = storage.get(&id).unwrap();
        assert!(m.is_some(), "Memory '{}' should still exist", id);
    }
}

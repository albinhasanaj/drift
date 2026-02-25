//! ConsolidationEngine: implements IConsolidator, Arc<AtomicBool> is_running guard.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cortex_core::config::MultiAgentConfig;
use cortex_core::errors::{ConsolidationError, CortexError, CortexResult};
use cortex_core::memory::BaseMemory;
use cortex_core::models::ConsolidationResult;
use cortex_core::traits::{IConsolidator, IEmbeddingProvider, IMemoryStorage};
use tracing::info;

use crate::llm_polish::{LlmPolisher, NoOpPolisher};
use crate::monitoring::{self, ConsolidationDashboard, TunableThresholds};
use crate::pipeline;

/// The main consolidation engine.
///
/// Coordinates the 6-phase pipeline, enforces single-execution guard,
/// tracks quality metrics, and manages auto-tuning.
pub struct ConsolidationEngine {
    /// Guard: only one consolidation can run at a time.
    is_running: Arc<AtomicBool>,
    /// Embedding provider for similarity computations.
    embedding_provider: Box<dyn IEmbeddingProvider>,
    /// Persistent storage for creating/archiving memories.
    storage: Option<Arc<dyn IMemoryStorage>>,
    /// Quality monitoring dashboard.
    dashboard: ConsolidationDashboard,
    /// Tunable thresholds (adjusted by auto-tuning).
    thresholds: TunableThresholds,
    /// Recent quality assessments for auto-tuning.
    recent_assessments: Vec<monitoring::QualityAssessment>,
    /// Multi-agent configuration (None = single-agent mode).
    multiagent_config: Option<MultiAgentConfig>,
    /// D-02: LLM polisher for summary refinement (NoOp by default).
    polisher: Box<dyn LlmPolisher>,
}

impl ConsolidationEngine {
    /// Create a new consolidation engine.
    pub fn new(embedding_provider: Box<dyn IEmbeddingProvider>) -> Self {
        Self {
            is_running: Arc::new(AtomicBool::new(false)),
            embedding_provider,
            storage: None,
            dashboard: ConsolidationDashboard::new(),
            thresholds: TunableThresholds::default(),
            recent_assessments: Vec::new(),
            multiagent_config: None,
            polisher: Box::new(NoOpPolisher),
        }
    }

    /// Set storage for persisting consolidation results.
    pub fn with_storage(mut self, storage: Arc<dyn IMemoryStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// D-02: Inject a real LLM polisher for summary refinement.
    /// If not called, the engine uses NoOpPolisher (returns None, no LLM calls).
    pub fn with_polisher(mut self, polisher: Box<dyn LlmPolisher>) -> Self {
        self.polisher = polisher;
        self
    }

    /// D-02: Set the polisher after construction.
    pub fn set_polisher(&mut self, polisher: Box<dyn LlmPolisher>) {
        self.polisher = polisher;
    }

    /// D-02: Get a reference to the current polisher.
    pub fn polisher(&self) -> &dyn LlmPolisher {
        self.polisher.as_ref()
    }

    /// Set storage after construction.
    pub fn set_storage(&mut self, storage: Arc<dyn IMemoryStorage>) {
        self.storage = Some(storage);
    }

    /// Enable multi-agent consolidation with the given config.
    ///
    /// When enabled, consolidation extends across namespaces, delegating
    /// cross-namespace logic to cortex-multiagent's consolidation module.
    pub fn with_multiagent_config(mut self, config: MultiAgentConfig) -> Self {
        if config.enabled {
            info!("multi-agent consolidation enabled");
            self.multiagent_config = Some(config);
        }
        self
    }

    /// Whether multi-agent consolidation is active.
    pub fn is_multiagent_enabled(&self) -> bool {
        self.multiagent_config
            .as_ref()
            .map(|c| c.enabled)
            .unwrap_or(false)
    }

    /// Check if a consolidation is currently running.
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }

    /// Get the monitoring dashboard.
    pub fn dashboard(&self) -> &ConsolidationDashboard {
        &self.dashboard
    }

    /// Get the current tunable thresholds.
    pub fn thresholds(&self) -> &TunableThresholds {
        &self.thresholds
    }

    /// Run consolidation with existing semantic memories for dedup.
    pub fn consolidate_with_context(
        &mut self,
        candidates: &[BaseMemory],
        existing_semantics: &[(String, Vec<f32>)],
    ) -> CortexResult<ConsolidationResult> {
        // Acquire the single-execution guard.
        if self
            .is_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(CortexError::ConsolidationError(
                ConsolidationError::MergeFailed {
                    reason: "consolidation already in progress".to_string(),
                },
            ));
        }

        let output = pipeline::run_pipeline(
            candidates,
            self.embedding_provider.as_ref(),
            existing_semantics,
        );

        // Release the guard.
        self.is_running.store(false, Ordering::SeqCst);

        let output = output?;

        // Persist results to storage if available.
        if let Some(storage) = &self.storage {
            Self::persist_results(storage, &output)?;
        }

        let result = output.result;

        // Assess quality and record.
        let assessment = monitoring::assess_quality(&result.metrics);
        self.dashboard
            .record_run(result.metrics.clone(), assessment.clone());
        self.recent_assessments.push(assessment);

        // Auto-tuning check.
        let adjustments =
            monitoring::auto_tuning::maybe_tune(&mut self.thresholds, &self.recent_assessments);
        for adj in &adjustments {
            info!(
                param = %adj.parameter,
                old = adj.old_value,
                new = adj.new_value,
                reason = %adj.reason,
                "auto-tuning adjustment"
            );
        }

        Ok(result)
    }

    /// Persist created memories and archive source episodes.
    fn persist_results(
        storage: &Arc<dyn IMemoryStorage>,
        output: &pipeline::PipelineOutput,
    ) -> CortexResult<()> {
        // Create new semantic memories.
        for mem in &output.created_memories {
            storage.create(mem)?;
            info!(id = %mem.id, "persisted consolidated semantic memory");
        }

        // Archive source episodes and set superseded_by.
        for (source_id, superseding_id) in &output.archive_map {
            if let Some(mut source) = storage.get(source_id)? {
                source.archived = true;
                source.superseded_by = Some(superseding_id.clone());
                storage.update(&source)?;
                info!(
                    source_id = %source_id,
                    superseded_by = %superseding_id,
                    "archived source episode"
                );
            }
        }

        Ok(())
    }
}

impl IConsolidator for ConsolidationEngine {
    fn consolidate(&self, candidates: &[BaseMemory]) -> CortexResult<ConsolidationResult> {
        // Acquire the single-execution guard.
        if self
            .is_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(CortexError::ConsolidationError(
                ConsolidationError::MergeFailed {
                    reason: "consolidation already in progress".to_string(),
                },
            ));
        }

        let output = pipeline::run_pipeline(
            candidates,
            self.embedding_provider.as_ref(),
            &[], // No existing semantics in the basic trait interface.
        );

        // Release the guard.
        self.is_running.store(false, Ordering::SeqCst);

        let output = output?;

        // Persist results to storage if available.
        if let Some(storage) = &self.storage {
            Self::persist_results(storage, &output)?;
        }

        Ok(output.result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use cortex_core::memory::types::EpisodicContent;
    use cortex_core::memory::*;
    use cortex_core::traits::IEmbeddingProvider;

    /// Simple test embedding provider.
    struct TestEmbedder;

    impl IEmbeddingProvider for TestEmbedder {
        fn embed(&self, _text: &str) -> CortexResult<Vec<f32>> {
            Ok(vec![0.5; 64])
        }
        fn embed_batch(&self, texts: &[String]) -> CortexResult<Vec<Vec<f32>>> {
            Ok(texts.iter().map(|_| vec![0.5; 64]).collect())
        }
        fn dimensions(&self) -> usize {
            64
        }
        fn name(&self) -> &str {
            "test"
        }
        fn is_available(&self) -> bool {
            true
        }
    }

    fn make_old_episodic(summary: &str) -> BaseMemory {
        let content = TypedContent::Episodic(EpisodicContent {
            interaction: summary.to_string(),
            context: "ctx".to_string(),
            outcome: None,
        });
        let now = Utc::now();
        BaseMemory {
            id: uuid::Uuid::new_v4().to_string(),
            memory_type: MemoryType::Episodic,
            content: content.clone(),
            summary: summary.to_string(),
            transaction_time: now - Duration::days(10),
            valid_time: now - Duration::days(10),
            valid_until: None,
            confidence: Confidence::new(0.8),
            importance: Importance::Normal,
            last_accessed: now,
            access_count: 3,
            linked_patterns: vec![],
            linked_constraints: vec![],
            linked_files: vec![],
            linked_functions: vec![],
            tags: vec!["rust".to_string()],
            archived: false,
            superseded_by: None,
            supersedes: None,
            namespace: Default::default(),
            source_agent: Default::default(),
            content_hash: BaseMemory::compute_content_hash(&content).unwrap(),
        }
    }

    #[test]
    fn engine_consolidates_empty_candidates() {
        let engine = ConsolidationEngine::new(Box::new(TestEmbedder));
        let result = engine.consolidate(&[]).unwrap();
        assert!(result.created.is_empty());
        assert!(result.archived.is_empty());
    }

    #[test]
    fn engine_rejects_concurrent_runs() {
        let engine = ConsolidationEngine::new(Box::new(TestEmbedder));
        // Simulate a running consolidation.
        engine.is_running.store(true, Ordering::SeqCst);
        let result = engine.consolidate(&[]);
        assert!(result.is_err());
        engine.is_running.store(false, Ordering::SeqCst);
    }

    #[test]
    fn engine_processes_eligible_memories() {
        let engine = ConsolidationEngine::new(Box::new(TestEmbedder));
        let memories: Vec<BaseMemory> = (0..5)
            .map(|i| make_old_episodic(&format!("Rust memory safety topic {}", i)))
            .collect();
        let result = engine.consolidate(&memories).unwrap();
        // With identical embeddings, HDBSCAN should cluster them.
        // The exact result depends on HDBSCAN behavior with identical vectors.
        assert!(result.metrics.precision > 0.0);
    }
}

//! CausalEngine: owns graph, coordinates inference + traversal + narrative, syncs graph ↔ SQLite.

use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::traits::ICausalStorage;

use crate::graph::stable_graph::{CausalEdgeWeight, EdgeEvidence};
use crate::graph::sync;
use crate::graph::GraphManager;
use crate::inference::{InferenceEngine, InferenceResult};
use crate::narrative::{CausalNarrative, NarrativeGenerator};
use crate::relations::CausalRelation;
use crate::traversal::{TraversalConfig, TraversalEngine, TraversalResult};

/// The main causal intelligence engine.
pub struct CausalEngine {
    /// Thread-safe graph manager.
    graph: GraphManager,
    /// Inference engine for evaluating memory pairs.
    inference: InferenceEngine,
    /// Traversal engine for graph queries.
    traversal: TraversalEngine,
}

impl CausalEngine {
    /// Create a new CausalEngine with default settings.
    pub fn new() -> Self {
        Self {
            graph: GraphManager::new(),
            inference: InferenceEngine::new(),
            traversal: TraversalEngine::default(),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(inference_threshold: f64, traversal_config: TraversalConfig) -> Self {
        Self {
            graph: GraphManager::new(),
            inference: InferenceEngine::with_threshold(inference_threshold),
            traversal: TraversalEngine::new(traversal_config),
        }
    }

    /// Get a reference to the graph manager.
    pub fn graph(&self) -> &GraphManager {
        &self.graph
    }

    /// C-04: Hydrate the in-memory causal graph from storage.
    /// Should be called once during runtime initialization after storage is available.
    pub fn hydrate(&self, storage: &dyn ICausalStorage) -> CortexResult<()> {
        let shared = self.graph.shared();
        let mut guard = shared.write().map_err(|e| {
            cortex_core::errors::CortexError::ConcurrencyError(e.to_string())
        })?;
        sync::rebuild_from_storage(storage, &mut guard)
    }

    // --- Graph Operations ---

    /// Add a causal edge with DAG enforcement and optional storage persistence.
    pub fn add_edge(
        &self,
        source: &BaseMemory,
        target: &BaseMemory,
        relation: CausalRelation,
        strength: f64,
        evidence: Vec<EdgeEvidence>,
        storage: Option<&dyn ICausalStorage>,
    ) -> CortexResult<()> {
        let weight = CausalEdgeWeight {
            relation,
            strength,
            evidence,
            inferred: false,
        };

        // DAG enforcement happens inside GraphManager::add_edge.
        self.graph.add_edge(
            &source.id,
            &target.id,
            source.memory_type.category(),
            target.memory_type.category(),
            weight.clone(),
        )?;

        // Persist to storage if provided.
        if let Some(storage) = storage {
            sync::persist_edge(storage, &source.id, &target.id, &weight)?;
        }

        Ok(())
    }

    /// Remove a causal edge.
    pub fn remove_edge(
        &self,
        source_id: &str,
        target_id: &str,
        storage: Option<&dyn ICausalStorage>,
    ) -> CortexResult<bool> {
        let removed = self.graph.remove_edge(source_id, target_id)?;
        if removed {
            if let Some(storage) = storage {
                sync::remove_persisted_edge(storage, source_id, target_id)?;
            }
        }
        Ok(removed)
    }

    // --- Inference ---

    /// Infer causal relationship between two memories.
    pub fn infer(&self, source: &BaseMemory, target: &BaseMemory) -> InferenceResult {
        self.inference.infer(source, target)
    }

    /// Infer and automatically add edges that exceed the threshold.
    pub fn infer_and_connect(
        &self,
        source: &BaseMemory,
        candidates: &[BaseMemory],
        storage: Option<&dyn ICausalStorage>,
    ) -> CortexResult<Vec<InferenceResult>> {
        let results = self.inference.infer_batch(source, candidates);

        for result in &results {
            if result.above_threshold {
                // Find the target memory.
                if let Some(target) = candidates.iter().find(|c| c.id == result.target_id) {
                    let weight = CausalEdgeWeight {
                        relation: result.suggested_relation,
                        strength: result.strength,
                        evidence: Vec::new(),
                        inferred: true,
                    };

                    // Try to add the edge; ignore cycle errors for inferred edges.
                    let add_result = self.graph.add_edge(
                        &source.id,
                        &target.id,
                        source.memory_type.category(),
                        target.memory_type.category(),
                        weight.clone(),
                    );

                    if let Ok(()) = add_result {
                        if let Some(storage) = storage {
                            let _ = sync::persist_edge(storage, &source.id, &target.id, &weight);
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    // --- Traversal ---

    /// Trace origins: "what caused this?"
    pub fn trace_origins(&self, memory_id: &str) -> CortexResult<TraversalResult> {
        let graph = self.graph.shared();
        let guard = graph
            .read()
            .map_err(|e| cortex_core::errors::CortexError::ConcurrencyError(e.to_string()))?;
        Ok(self.traversal.trace_origins(&guard, memory_id))
    }

    /// Trace effects: "what did this cause?"
    pub fn trace_effects(&self, memory_id: &str) -> CortexResult<TraversalResult> {
        let graph = self.graph.shared();
        let guard = graph
            .read()
            .map_err(|e| cortex_core::errors::CortexError::ConcurrencyError(e.to_string()))?;
        Ok(self.traversal.trace_effects(&guard, memory_id))
    }

    /// Bidirectional traversal.
    pub fn bidirectional(&self, memory_id: &str) -> CortexResult<TraversalResult> {
        let graph = self.graph.shared();
        let guard = graph
            .read()
            .map_err(|e| cortex_core::errors::CortexError::ConcurrencyError(e.to_string()))?;
        Ok(self.traversal.bidirectional(&guard, memory_id))
    }

    /// Direct neighbors.
    pub fn neighbors(&self, memory_id: &str) -> CortexResult<TraversalResult> {
        let graph = self.graph.shared();
        let guard = graph
            .read()
            .map_err(|e| cortex_core::errors::CortexError::ConcurrencyError(e.to_string()))?;
        Ok(self.traversal.neighbors(&guard, memory_id))
    }

    /// Counterfactual analysis.
    pub fn counterfactual(&self, memory_id: &str) -> CortexResult<TraversalResult> {
        let graph = self.graph.shared();
        let guard = graph
            .read()
            .map_err(|e| cortex_core::errors::CortexError::ConcurrencyError(e.to_string()))?;
        Ok(self.traversal.counterfactual(&guard, memory_id))
    }

    /// Intervention analysis.
    pub fn intervention(&self, memory_id: &str) -> CortexResult<TraversalResult> {
        let graph = self.graph.shared();
        let guard = graph
            .read()
            .map_err(|e| cortex_core::errors::CortexError::ConcurrencyError(e.to_string()))?;
        Ok(self.traversal.intervention(&guard, memory_id))
    }

    // --- Narrative ---

    /// Generate a causal narrative for a memory.
    pub fn narrative(&self, memory_id: &str) -> CortexResult<CausalNarrative> {
        let graph = self.graph.shared();
        let guard = graph
            .read()
            .map_err(|e| cortex_core::errors::CortexError::ConcurrencyError(e.to_string()))?;
        Ok(NarrativeGenerator::generate(&guard, memory_id))
    }

    // --- Maintenance ---

    /// Prune weak and unvalidated edges.
    pub fn prune(&self, min_strength: f64) -> CortexResult<crate::graph::pruning::PruneResult> {
        self.graph.prune(min_strength)
    }

    /// Get graph statistics.
    pub fn stats(&self) -> CortexResult<(usize, usize)> {
        Ok((self.graph.node_count()?, self.graph.edge_count()?))
    }
}

impl Default for CausalEngine {
    fn default() -> Self {
        Self::new()
    }
}

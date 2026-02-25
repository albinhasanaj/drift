//! Grounding loop orchestration: compare Cortex memories against Drift scan results.
//! Max 500 memories per loop.

use std::time::Instant;

use tracing::{info, warn};

use super::classification::{classify_groundability, Groundability};
use super::evidence::{EvidenceType, GroundingEvidence};
use super::scorer::GroundingScorer;
use super::GroundingVerdict;
use super::{
    AdjustmentMode, ConfidenceAdjustment, GroundingConfig, GroundingResult, GroundingSnapshot,
    TriggerType,
};
use crate::config::EvidenceConfig;
use crate::errors::{BridgeResult, ErrorChain};
use crate::traits::IBridgeStorage;

/// The grounding loop runner.
pub struct GroundingLoopRunner {
    scorer: GroundingScorer,
    config: GroundingConfig,
}

impl GroundingLoopRunner {
    pub fn new(config: GroundingConfig) -> Self {
        Self {
            scorer: GroundingScorer::new(config.clone()),
            config,
        }
    }

    /// Create a runner with custom evidence weight overrides.
    pub fn with_evidence_config(config: GroundingConfig, evidence_config: EvidenceConfig) -> Self {
        Self {
            scorer: GroundingScorer::with_evidence_config(config.clone(), evidence_config),
            config,
        }
    }

    /// Run the grounding loop for a set of memories.
    /// Respects max_memories_per_loop (500 default). Excess deferred, not dropped.
    pub fn run(
        &self,
        memories: &[MemoryForGrounding],
        _drift_db: Option<&rusqlite::Connection>,
        bridge_store: Option<&dyn IBridgeStorage>,
        trigger: TriggerType,
    ) -> BridgeResult<GroundingSnapshot> {
        let start = Instant::now();
        let max = self.config.max_memories_per_loop;

        // Cap at max_memories_per_loop
        let to_process = if memories.len() > max {
            info!(
                total = memories.len(),
                max = max,
                deferred = memories.len() - max,
                "Capping grounding loop — excess deferred to next loop"
            );
            &memories[..max]
        } else {
            memories
        };

        let mut snapshot = GroundingSnapshot {
            total_checked: 0,
            validated: 0,
            partial: 0,
            weak: 0,
            invalidated: 0,
            not_groundable: 0,
            insufficient_data: 0,
            avg_grounding_score: 0.0,
            contradictions_generated: 0,
            duration_ms: 0,
            error_count: 0,
            trigger_type: Some(format!("{:?}", trigger)),
        };

        let mut total_score = 0.0;
        let mut scored_count = 0u32;
        let mut error_chain = ErrorChain::new();

        for memory in to_process {
            snapshot.total_checked += 1;

            let groundability = classify_groundability(&memory.memory_type);
            if groundability == Groundability::NotGroundable {
                snapshot.not_groundable += 1;
                continue;
            }

            // Collect evidence from Drift data
            let evidence = self.collect_evidence(memory, _drift_db);

            if evidence.is_empty() {
                snapshot.insufficient_data += 1;
                continue;
            }

            // Compute grounding score
            let grounding_score = self.scorer.compute_score(&evidence);
            let verdict = self.scorer.score_to_verdict(grounding_score);

            // Get previous score for trend detection
            let previous_score = bridge_store
                .and_then(|store| store.get_previous_grounding_score(&memory.memory_id).ok())
                .flatten();
            let score_delta = previous_score.map(|prev| grounding_score - prev);

            // Compute confidence adjustment
            let confidence_adjustment = self.scorer.compute_confidence_adjustment(
                &verdict,
                score_delta,
                memory.current_confidence,
            );

            // Check for contradiction
            let generates_contradiction =
                self.scorer.should_generate_contradiction(grounding_score, score_delta, &verdict);

            match verdict {
                GroundingVerdict::Validated => snapshot.validated += 1,
                GroundingVerdict::Partial => snapshot.partial += 1,
                GroundingVerdict::Weak => snapshot.weak += 1,
                GroundingVerdict::Invalidated => snapshot.invalidated += 1,
                _ => {}
            }

            total_score += grounding_score;
            scored_count += 1;

            // Persist grounding result
            let result = GroundingResult {
                memory_id: memory.memory_id.clone(),
                verdict,
                grounding_score,
                previous_score,
                score_delta,
                confidence_adjustment: confidence_adjustment.clone(),
                evidence,
                generates_contradiction,
                duration_ms: 0,
            };

            if let Some(store) = bridge_store {
                if let Err(e) = store.insert_grounding_result(&result) {
                    error_chain.push(
                        snapshot.total_checked as usize,
                        crate::errors::BridgeError::GroundingFailed {
                            memory_id: result.memory_id.clone(),
                            reason: format!("Failed to persist grounding result: {}", e),
                        },
                    );
                }

                // Apply confidence adjustment back to bridge_memories
                if let Some(delta) = confidence_adjustment.delta {
                    if delta.abs() > f64::EPSILON {
                        if let Err(e) = store.update_memory_confidence(&memory.memory_id, delta) {
                            error_chain.push(
                                snapshot.total_checked as usize,
                                crate::errors::BridgeError::GroundingFailed {
                                    memory_id: memory.memory_id.clone(),
                                    reason: format!("Failed to apply confidence adjustment: {}", e),
                                },
                            );
                        }
                    }
                }

                // Generate and persist contradiction memory
                if generates_contradiction {
                    snapshot.contradictions_generated += 1;
                    match super::contradiction::generate_contradiction(&result, Some(store)) {
                        Ok(Some(cid)) => {
                            info!(contradiction_id = %cid, memory_id = %memory.memory_id, "Contradiction memory created");
                        }
                        Ok(None) => {}
                        Err(e) => {
                            error_chain.push(
                                snapshot.total_checked as usize,
                                crate::errors::BridgeError::GroundingFailed {
                                    memory_id: memory.memory_id.clone(),
                                    reason: format!("Failed to generate contradiction: {}", e),
                                },
                            );
                        }
                    }
                }
            }
        }

        if scored_count > 0 {
            snapshot.avg_grounding_score = total_score / scored_count as f64;
        }
        snapshot.duration_ms = start.elapsed().as_millis() as u32;
        snapshot.error_count = error_chain.len() as u32;

        // Log accumulated errors as a batch summary
        if error_chain.has_errors() {
            warn!(
                error_count = error_chain.len(),
                "Grounding loop completed with {} non-fatal errors",
                error_chain.len()
            );
            for chained in error_chain.iter() {
                warn!(
                    step = chained.step,
                    error = %chained.error,
                    "Grounding error at step {}",
                    chained.step
                );
            }
        }

        // Persist snapshot
        if let Some(store) = bridge_store {
            if let Err(e) = store.insert_snapshot(&snapshot) {
                warn!(
                    error = %e,
                    "Failed to persist grounding snapshot — dashboard data silently lost"
                );
            }
        }

        info!(
            total = snapshot.total_checked,
            validated = snapshot.validated,
            partial = snapshot.partial,
            weak = snapshot.weak,
            invalidated = snapshot.invalidated,
            contradictions = snapshot.contradictions_generated,
            avg_score = format!("{:.3}", snapshot.avg_grounding_score),
            duration_ms = snapshot.duration_ms,
            trigger = ?trigger,
            "Grounding loop complete"
        );

        Ok(snapshot)
    }

    /// Collect evidence for a single memory from Drift data sources.
    ///
    /// Strategy: pre-populated fields on MemoryForGrounding are the fast path.
    /// When a field is None AND drift_db + evidence_context are available,
    /// fall back to querying drift.db directly via the evidence collector.
    fn collect_evidence(
        &self,
        memory: &MemoryForGrounding,
        drift_db: Option<&rusqlite::Connection>,
    ) -> Vec<GroundingEvidence> {
        let mut evidence = Vec::new();
        let mut covered_types = std::collections::HashSet::new();

        // Fast path: use pre-populated fields from MemoryForGrounding
        if let Some(pattern_confidence) = memory.pattern_confidence {
            if pattern_confidence.is_finite() {
                evidence.push(GroundingEvidence::new(
                    EvidenceType::PatternConfidence,
                    format!("Pattern confidence: {:.2}", pattern_confidence),
                    pattern_confidence,
                    Some(memory.current_confidence),
                    pattern_confidence.clamp(0.0, 1.0),
                ));
                covered_types.insert(EvidenceType::PatternConfidence);
            }
        }

        if let Some(occurrence_rate) = memory.occurrence_rate {
            if occurrence_rate.is_finite() {
                evidence.push(GroundingEvidence::new(
                    EvidenceType::PatternOccurrence,
                    format!("Pattern occurrence rate: {:.1}%", occurrence_rate * 100.0),
                    occurrence_rate,
                    None,
                    occurrence_rate.clamp(0.0, 1.0),
                ));
                covered_types.insert(EvidenceType::PatternOccurrence);
            }
        }

        if let Some(fp_rate) = memory.false_positive_rate {
            if fp_rate.is_finite() {
                let support = (1.0 - fp_rate).clamp(0.0, 1.0);
                evidence.push(GroundingEvidence::new(
                    EvidenceType::FalsePositiveRate,
                    format!("False positive rate: {:.1}%", fp_rate * 100.0),
                    fp_rate,
                    None,
                    support,
                ));
                covered_types.insert(EvidenceType::FalsePositiveRate);
            }
        }

        if let Some(constraint_pass) = memory.constraint_verified {
            evidence.push(GroundingEvidence::new(
                EvidenceType::ConstraintVerification,
                format!("Constraint verification: {}", if constraint_pass { "pass" } else { "fail" }),
                if constraint_pass { 1.0 } else { 0.0 },
                None,
                if constraint_pass { 1.0 } else { 0.0 },
            ));
            covered_types.insert(EvidenceType::ConstraintVerification);
        }

        if let Some(coupling) = memory.coupling_metric {
            if coupling.is_finite() {
                evidence.push(GroundingEvidence::new(
                    EvidenceType::CouplingMetric,
                    format!("Coupling metric: {:.2}", coupling),
                    coupling,
                    None,
                    coupling.clamp(0.0, 1.0),
                ));
                covered_types.insert(EvidenceType::CouplingMetric);
            }
        }

        if let Some(dna_health) = memory.dna_health {
            if dna_health.is_finite() {
                evidence.push(GroundingEvidence::new(
                    EvidenceType::DnaHealth,
                    format!("DNA health score: {:.2}", dna_health),
                    dna_health,
                    None,
                    dna_health.clamp(0.0, 1.0),
                ));
                covered_types.insert(EvidenceType::DnaHealth);
            }
        }

        if let Some(test_coverage) = memory.test_coverage {
            if test_coverage.is_finite() {
                evidence.push(GroundingEvidence::new(
                    EvidenceType::TestCoverage,
                    format!("Test coverage: {:.1}%", test_coverage * 100.0),
                    test_coverage,
                    None,
                    test_coverage.clamp(0.0, 1.0),
                ));
                covered_types.insert(EvidenceType::TestCoverage);
            }
        }

        if let Some(error_gaps) = memory.error_handling_gaps {
            let support = 1.0 - (error_gaps as f64 / 100.0).clamp(0.0, 1.0);
            evidence.push(GroundingEvidence::new(
                EvidenceType::ErrorHandlingGaps,
                format!("Error handling gaps: {}", error_gaps),
                error_gaps as f64,
                None,
                support,
            ));
            covered_types.insert(EvidenceType::ErrorHandlingGaps);
        }

        if let Some(decision_score) = memory.decision_evidence {
            if decision_score.is_finite() {
                evidence.push(GroundingEvidence::new(
                    EvidenceType::DecisionEvidence,
                    format!("Decision evidence score: {:.2}", decision_score),
                    decision_score,
                    None,
                    decision_score.clamp(0.0, 1.0),
                ));
                covered_types.insert(EvidenceType::DecisionEvidence);
            }
        }

        if let Some(boundary_score) = memory.boundary_data {
            if boundary_score.is_finite() {
                evidence.push(GroundingEvidence::new(
                    EvidenceType::BoundaryData,
                    format!("Boundary data score: {:.2}", boundary_score),
                    boundary_score,
                    None,
                    boundary_score.clamp(0.0, 1.0),
                ));
                covered_types.insert(EvidenceType::BoundaryData);
            }
        }

        // Slow path: fill gaps from drift.db when evidence_context is available
        if let (Some(drift_conn), Some(ctx)) = (drift_db, &memory.evidence_context) {
            for evidence_type in EvidenceType::ALL {
                if covered_types.contains(&evidence_type) {
                    continue; // Already have this from pre-populated fields
                }
                match super::evidence::collector::collect_one(evidence_type, ctx, drift_conn) {
                    Ok(Some(e)) => evidence.push(e),
                    Ok(None) => {} // No data in drift.db for this type
                    Err(e) => {
                        tracing::debug!(
                            evidence_type = ?evidence_type,
                            error = %e,
                            "drift.db evidence fallback failed — skipping"
                        );
                    }
                }
            }
        }

        evidence
    }

    /// Ground a single memory (for on-demand / memory creation triggers).
    pub fn ground_single(
        &self,
        memory: &MemoryForGrounding,
        _drift_db: Option<&rusqlite::Connection>,
        bridge_store: Option<&dyn IBridgeStorage>,
    ) -> BridgeResult<GroundingResult> {
        let start = Instant::now();

        let groundability = classify_groundability(&memory.memory_type);
        if groundability == Groundability::NotGroundable {
            return Ok(GroundingResult {
                memory_id: memory.memory_id.clone(),
                verdict: GroundingVerdict::NotGroundable,
                grounding_score: 0.0,
                previous_score: None,
                score_delta: None,
                confidence_adjustment: ConfidenceAdjustment {
                    mode: AdjustmentMode::NoChange,
                    delta: None,
                    reason: "Memory type is not groundable".to_string(),
                },
                evidence: vec![],
                generates_contradiction: false,
                duration_ms: start.elapsed().as_millis() as u32,
            });
        }

        let evidence = self.collect_evidence(memory, _drift_db);

        if evidence.is_empty() {
            return Ok(GroundingResult {
                memory_id: memory.memory_id.clone(),
                verdict: GroundingVerdict::InsufficientData,
                grounding_score: 0.0,
                previous_score: None,
                score_delta: None,
                confidence_adjustment: ConfidenceAdjustment {
                    mode: AdjustmentMode::NoChange,
                    delta: None,
                    reason: "Insufficient Drift data for grounding".to_string(),
                },
                evidence: vec![],
                generates_contradiction: false,
                duration_ms: start.elapsed().as_millis() as u32,
            });
        }

        let grounding_score = self.scorer.compute_score(&evidence);
        let verdict = self.scorer.score_to_verdict(grounding_score);

        let previous_score = bridge_store
            .and_then(|store| store.get_previous_grounding_score(&memory.memory_id).ok())
            .flatten();
        let score_delta = previous_score.map(|prev| grounding_score - prev);

        let confidence_adjustment = self.scorer.compute_confidence_adjustment(
            &verdict,
            score_delta,
            memory.current_confidence,
        );

        let generates_contradiction =
            self.scorer.should_generate_contradiction(grounding_score, score_delta, &verdict);

        let result = GroundingResult {
            memory_id: memory.memory_id.clone(),
            verdict,
            grounding_score,
            previous_score,
            score_delta,
            confidence_adjustment,
            evidence,
            generates_contradiction,
            duration_ms: start.elapsed().as_millis() as u32,
        };

        if let Some(store) = bridge_store {
            if let Err(e) = store.insert_grounding_result(&result) {
                warn!(
                    memory_id = %result.memory_id,
                    error = %e,
                    "Failed to persist single grounding result"
                );
            }

            // Apply confidence adjustment back to bridge_memories
            if let Some(delta) = result.confidence_adjustment.delta {
                if delta.abs() > f64::EPSILON {
                    if let Err(e) = store.update_memory_confidence(&memory.memory_id, delta) {
                        warn!(
                            memory_id = %memory.memory_id,
                            delta = delta,
                            error = %e,
                            "Failed to apply confidence adjustment — memory retains old confidence"
                        );
                    }
                }
            }

            // Generate and persist contradiction memory
            if result.generates_contradiction {
                match super::contradiction::generate_contradiction(&result, Some(store)) {
                    Ok(Some(cid)) => {
                        info!(contradiction_id = %cid, memory_id = %memory.memory_id, "Contradiction memory created");
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(memory_id = %memory.memory_id, error = %e, "Failed to generate contradiction memory");
                    }
                }
            }
        }

        Ok(result)
    }
}

/// Simplified memory representation for grounding.
/// Contains the data needed to ground a memory without requiring the full BaseMemory.
#[derive(Debug, Clone)]
pub struct MemoryForGrounding {
    pub memory_id: String,
    pub memory_type: cortex_core::MemoryType,
    pub current_confidence: f64,
    // Evidence data points (populated from drift.db queries)
    pub pattern_confidence: Option<f64>,
    pub occurrence_rate: Option<f64>,
    pub false_positive_rate: Option<f64>,
    pub constraint_verified: Option<bool>,
    pub coupling_metric: Option<f64>,
    pub dna_health: Option<f64>,
    pub test_coverage: Option<f64>,
    pub error_handling_gaps: Option<u32>,
    pub decision_evidence: Option<f64>,
    pub boundary_data: Option<f64>,
    /// Optional context for querying drift.db directly when pre-populated fields are None.
    /// Built from memory tags via `context_from_tags()`.
    pub evidence_context: Option<super::evidence::collector::EvidenceContext>,
}

impl Default for GroundingLoopRunner {
    fn default() -> Self {
        Self::new(GroundingConfig::default())
    }
}

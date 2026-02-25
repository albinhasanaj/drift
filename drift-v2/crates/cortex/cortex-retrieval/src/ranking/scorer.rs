//! Multi-factor relevance scorer (10 factors).
//!
//! Factors: semantic similarity, keyword match, file proximity, pattern alignment,
//! recency, confidence, importance, intent-type match, evidence freshness, epistemic status.

use chrono::Utc;

use cortex_core::config::MultiAgentConfig;
use cortex_core::intent::Intent;
use cortex_core::memory::BaseMemory;
use cortex_core::models::EpistemicStatus;

use crate::intent::IntentEngine;
use crate::search::rrf_fusion::RrfCandidate;

/// Weights for the 10 scoring factors.
#[derive(Debug, Clone)]
pub struct ScorerWeights {
    pub semantic_similarity: f64,
    pub keyword_match: f64,
    pub file_proximity: f64,
    pub pattern_alignment: f64,
    pub recency: f64,
    pub confidence: f64,
    pub importance: f64,
    pub intent_type_match: f64,
    pub evidence_freshness: f64,
    pub epistemic_status: f64,
}

impl Default for ScorerWeights {
    fn default() -> Self {
        Self {
            semantic_similarity: 0.22,
            keyword_match: 0.13,
            file_proximity: 0.10,
            pattern_alignment: 0.08,
            recency: 0.10,
            confidence: 0.10,
            importance: 0.08,
            intent_type_match: 0.08,
            evidence_freshness: 0.06,
            epistemic_status: 0.05,
        }
    }
}

/// Scored candidate after multi-factor ranking.
#[derive(Debug, Clone)]
pub struct ScoredCandidate {
    pub memory: BaseMemory,
    /// Final composite score [0.0, ~2.0+].
    pub score: f64,
    /// RRF score from fusion stage.
    pub rrf_score: f64,
}

/// Score a list of RRF candidates using 10 factors.
pub fn score(
    candidates: &[RrfCandidate],
    intent: Intent,
    active_files: &[String],
    intent_engine: &IntentEngine,
    weights: &ScorerWeights,
) -> Vec<ScoredCandidate> {
    score_with_temporal(candidates, intent, active_files, intent_engine, weights, None)
}

/// Temporal context for scoring — provides evidence freshness and epistemic status.
pub struct TemporalScoringContext {
    /// Evidence freshness per memory ID [0.0, 1.0]. Missing entries default to 0.5.
    pub evidence_freshness: std::collections::HashMap<String, f64>,
    /// Epistemic status per memory ID. Missing entries default to Conjecture.
    pub epistemic_statuses: std::collections::HashMap<String, EpistemicStatus>,
}

/// Multi-agent trust context for scoring — provides trust-weighted ranking.
pub struct TrustScoringContext {
    /// Multi-agent config.
    pub config: MultiAgentConfig,
    /// Trust score lookup: agent_id → trust score [0.0, 1.0].
    pub trust_scores: std::collections::HashMap<String, f64>,
}

impl TrustScoringContext {
    /// Get the trust factor for a memory's source agent.
    /// Returns 1.0 (no modulation) if multi-agent is disabled or no trust data.
    pub fn trust_factor(&self, memory: &BaseMemory) -> f64 {
        if !self.config.enabled {
            return 1.0;
        }
        self.trust_scores
            .get(&memory.source_agent.0)
            .copied()
            .unwrap_or(0.5) // Neutral if no trust data.
    }
}

/// Map an epistemic status to a score value.
pub fn epistemic_status_score(status: &EpistemicStatus) -> f64 {
    match status {
        EpistemicStatus::Verified { .. } => 1.0,
        EpistemicStatus::Provisional { .. } => 0.7,
        EpistemicStatus::Conjecture { .. } => 0.4,
        EpistemicStatus::Stale { .. } => 0.2,
    }
}

/// Score a list of RRF candidates using 10 factors, with optional temporal context.
pub fn score_with_temporal(
    candidates: &[RrfCandidate],
    intent: Intent,
    active_files: &[String],
    intent_engine: &IntentEngine,
    weights: &ScorerWeights,
    temporal_ctx: Option<&TemporalScoringContext>,
) -> Vec<ScoredCandidate> {
    let now = Utc::now();
    let max_rrf = candidates
        .first()
        .map(|c| c.rrf_score)
        .unwrap_or(1.0)
        .max(f64::EPSILON);

    let mut scored: Vec<ScoredCandidate> = candidates
        .iter()
        .map(|c| {
            let m = &c.memory;

            // Factor 1: Semantic similarity (normalized RRF as proxy).
            let f_semantic = c.rrf_score / max_rrf;

            // Factor 2: Keyword match — real BM25 rank from FTS5 search.
            // Uses RRF-style normalization: 1/(1 + rank) to produce a smooth signal
            // that doesn't create extreme spread with few candidates.
            let f_keyword = match c.fts5_rank {
                Some(rank) => 1.0 / (1.0 + rank as f64),
                None => 0.0,
            };

            // Factor 3: File proximity — do any linked files match active files?
            let f_file = file_proximity_score(m, active_files);

            // Factor 4: Pattern alignment — has linked patterns?
            let f_pattern = if m.linked_patterns.is_empty() {
                0.0
            } else {
                (m.linked_patterns.len() as f64).min(3.0) / 3.0
            };

            // Factor 5: Recency — exponential decay over days.
            let days_since = (now - m.last_accessed).num_days().max(0) as f64;
            let f_recency = (-days_since / 90.0).exp(); // 90-day half-life.

            // Factor 6: Confidence.
            let f_confidence = m.confidence.value();

            // Factor 7: Importance weight.
            let f_importance = m.importance.weight() / 2.0; // Normalize: Critical=1.0.

            // Factor 8: Intent-type match boost.
            let f_intent = intent_engine.boost(intent, m.memory_type) / 2.0; // Normalize.

            // Factor 9: Evidence freshness [0.0, 1.0].
            let f_evidence_freshness = temporal_ctx
                .and_then(|ctx| ctx.evidence_freshness.get(&m.id))
                .copied()
                .unwrap_or(0.5);

            // Factor 10: Epistemic status score.
            let f_epistemic = temporal_ctx
                .and_then(|ctx| ctx.epistemic_statuses.get(&m.id))
                .map(epistemic_status_score)
                .unwrap_or(0.4); // Default to Conjecture score.

            let score = weights.semantic_similarity * f_semantic
                + weights.keyword_match * f_keyword
                + weights.file_proximity * f_file
                + weights.pattern_alignment * f_pattern
                + weights.recency * f_recency
                + weights.confidence * f_confidence
                + weights.importance * f_importance
                + weights.intent_type_match * f_intent
                + weights.evidence_freshness * f_evidence_freshness
                + weights.epistemic_status * f_epistemic;

            ScoredCandidate {
                memory: m.clone(),
                score,
                rrf_score: c.rrf_score,
            }
        })
        .collect();

    // Sort by score descending.
    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    scored
}

/// Apply trust-weighted scoring to already-scored candidates.
///
/// When multi-agent is enabled, each candidate's score is modulated by the
/// trust score of its source agent. Higher-trust agents' memories rank higher.
/// When disabled, scores are unchanged (trust_factor = 1.0).
pub fn apply_trust_weighting(
    candidates: &mut [ScoredCandidate],
    trust_ctx: &TrustScoringContext,
) {
    for candidate in candidates.iter_mut() {
        let trust_factor = trust_ctx.trust_factor(&candidate.memory);
        candidate.score *= trust_factor;
    }

    // Re-sort by score descending after trust modulation.
    candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

/// Compute file proximity score [0.0, 1.0].
fn file_proximity_score(memory: &BaseMemory, active_files: &[String]) -> f64 {
    if active_files.is_empty() || memory.linked_files.is_empty() {
        return 0.0;
    }

    let matches = memory
        .linked_files
        .iter()
        .filter(|f| {
            active_files
                .iter()
                .any(|af| af.contains(&f.file_path) || f.file_path.contains(af.as_str()))
        })
        .count();

    (matches as f64 / memory.linked_files.len() as f64).min(1.0)
}

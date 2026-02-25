//! ValidationEngine — implements IValidator, runs all 4 dimensions,
//! aggregates results, triggers healing actions, and promotes epistemic status.

use chrono::Utc;
use cortex_core::config::MultiAgentConfig;
use cortex_core::errors::CortexResult;
use cortex_core::memory::BaseMemory;
use cortex_core::models::{DimensionScores, EpistemicStatus, HealingAction, ValidationResult};
use cortex_core::traits::IValidator;

use crate::contradiction::SimilarityFn;
use crate::dimensions::{citation, contradiction, pattern_alignment, temporal};

/// Configuration for the validation engine.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Minimum overall score to pass validation.
    pub pass_threshold: f64,
    /// Confidence adjustment strength (0.0–1.0).
    pub adjustment_strength: f64,
    /// Archival threshold — memories below this confidence get archived.
    pub archival_threshold: f64,
    /// Whether to automatically promote epistemic status on validation pass.
    pub epistemic_auto_promote: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            pass_threshold: 0.5,
            adjustment_strength: 0.3,
            archival_threshold: 0.15,
            epistemic_auto_promote: true,
        }
    }
}

/// External context needed for full validation.
///
/// Groups the callbacks and related data that the engine needs,
/// avoiding excessive function parameters.
pub struct ValidationContext<'a> {
    /// Related memories to check for contradictions.
    pub related_memories: &'a [BaseMemory],
    /// Full memory set for consensus detection.
    pub all_memories: &'a [BaseMemory],
    /// Checks if a file exists and returns its info.
    pub file_checker: &'a dyn Fn(&str) -> Option<citation::FileInfo>,
    /// Checks if a file was renamed (git mv detection).
    pub rename_detector: &'a dyn Fn(&str) -> Option<String>,
    /// Returns the current state of a pattern.
    pub pattern_checker: &'a dyn Fn(&str) -> pattern_alignment::PatternInfo,
    /// Optional embedding similarity lookup.
    pub similarity_fn: Option<&'a SimilarityFn<'a>>,
}

/// The 4-dimension validation engine.
///
/// Validates memories across citation, temporal, contradiction, and pattern
/// alignment dimensions. Aggregates scores and produces healing actions.
pub struct ValidationEngine {
    config: ValidationConfig,
    /// Multi-agent configuration (None = single-agent mode).
    multiagent_config: Option<MultiAgentConfig>,
}

impl ValidationEngine {
    pub fn new(config: ValidationConfig) -> Self {
        Self {
            config,
            multiagent_config: None,
        }
    }

    /// Enable multi-agent validation with the given config.
    ///
    /// When enabled, contradiction detection extends across namespaces,
    /// delegating cross-agent logic to cortex-multiagent's validation module.
    pub fn with_multiagent_config(mut self, config: MultiAgentConfig) -> Self {
        if config.enabled {
            self.multiagent_config = Some(config);
        }
        self
    }

    /// Whether multi-agent validation is active.
    pub fn is_multiagent_enabled(&self) -> bool {
        self.multiagent_config
            .as_ref()
            .map(|c| c.enabled)
            .unwrap_or(false)
    }

    /// Validate a memory with full context.
    pub fn validate_with_context(
        &self,
        memory: &BaseMemory,
        ctx: &ValidationContext<'_>,
    ) -> CortexResult<ValidationResult> {
        let mut all_healing_actions: Vec<HealingAction> = Vec::new();

        // Dimension 1: Citation validation.
        let citation_result = citation::validate(memory, ctx.file_checker, ctx.rename_detector);
        all_healing_actions.extend(citation_result.healing_actions);

        // Dimension 2: Temporal validation.
        let temporal_result = temporal::validate(memory, Utc::now());
        all_healing_actions.extend(temporal_result.healing_actions);

        // Dimension 3: Contradiction validation.
        let contradiction_result = contradiction::validate(
            memory,
            ctx.related_memories,
            ctx.all_memories,
            ctx.similarity_fn,
        );
        all_healing_actions.extend(contradiction_result.healing_actions);

        // Dimension 4: Pattern alignment.
        let pattern_result = pattern_alignment::validate(memory, ctx.pattern_checker);
        all_healing_actions.extend(pattern_result.healing_actions);

        let scores = DimensionScores {
            citation: citation_result.score,
            temporal: temporal_result.score,
            contradiction: contradiction_result.score,
            pattern_alignment: pattern_result.score,
        };

        let overall_score = scores.average();
        let passed = overall_score >= self.config.pass_threshold;

        Ok(ValidationResult {
            memory_id: memory.id.clone(),
            dimension_scores: scores,
            overall_score,
            healing_actions: all_healing_actions,
            passed,
        })
    }

    /// Simplified validation that uses no-op callbacks.
    /// Useful for basic temporal + contradiction checks without file system access.
    pub fn validate_basic(
        &self,
        memory: &BaseMemory,
        related_memories: &[BaseMemory],
    ) -> CortexResult<ValidationResult> {
        let no_files = |_: &str| -> Option<citation::FileInfo> { None };
        let no_renames = |_: &str| -> Option<String> { None };
        let no_patterns = |_: &str| -> pattern_alignment::PatternInfo {
            pattern_alignment::PatternInfo {
                exists: true,
                confidence: None,
            }
        };

        let ctx = ValidationContext {
            related_memories,
            all_memories: related_memories,
            file_checker: &no_files,
            rename_detector: &no_renames,
            pattern_checker: &no_patterns,
            similarity_fn: None,
        };

        self.validate_with_context(memory, &ctx)
    }

    /// Get the engine configuration.
    pub fn config(&self) -> &ValidationConfig {
        &self.config
    }

    /// Promote epistemic status based on validation result.
    ///
    /// - If validation passes and memory is Conjecture → promote to Provisional.
    /// - If validation passes and memory is Provisional + user_confirmed → promote to Verified.
    /// - Validation failure does NOT demote — epistemic status only degrades via evidence decay.
    pub fn promote_epistemic_status(
        &self,
        current_status: &EpistemicStatus,
        validation_passed: bool,
        user_confirmed: bool,
    ) -> Option<EpistemicStatus> {
        if !self.config.epistemic_auto_promote || !validation_passed {
            return None;
        }

        match current_status {
            EpistemicStatus::Conjecture { .. } => Some(EpistemicStatus::Provisional {
                evidence_count: 1,
                last_validated: Utc::now(),
            }),
            EpistemicStatus::Provisional { evidence_count, .. } if user_confirmed => {
                Some(EpistemicStatus::Verified {
                    verified_by: vec!["validation_engine".to_string()],
                    verified_at: Utc::now(),
                    evidence_refs: vec![format!("validation_pass_count:{}", evidence_count + 1)],
                })
            }
            _ => None,
        }
    }
}

impl Default for ValidationEngine {
    fn default() -> Self {
        Self::new(ValidationConfig::default())
    }
}

impl IValidator for ValidationEngine {
    fn validate(&self, memory: &BaseMemory) -> CortexResult<ValidationResult> {
        self.validate_basic(memory, &[])
    }
}

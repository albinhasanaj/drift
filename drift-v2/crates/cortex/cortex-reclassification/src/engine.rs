//! ReclassificationEngine — monthly background task evaluating all memories.

use cortex_core::errors::CortexResult;
use cortex_core::memory::{BaseMemory, Importance};
use cortex_core::traits::IMemoryStorage;

use crate::rules::{self, ReclassificationRule};
use crate::safeguards::{self, ReclassificationRecord, SafeguardResult};
use crate::signals::ReclassificationSignals;

/// Result of evaluating a single memory for reclassification.
#[derive(Debug, Clone)]
pub struct ReclassificationEvaluation {
    pub memory_id: String,
    pub current_importance: Importance,
    pub composite_score: f64,
    pub decision: ReclassificationDecision,
}

/// The decision for a memory.
#[derive(Debug, Clone)]
pub enum ReclassificationDecision {
    /// No change needed.
    NoChange,
    /// Reclassify to a new importance level.
    Reclassify {
        new_importance: Importance,
        rule: ReclassificationRule,
    },
    /// Blocked by safeguards.
    Blocked { reason: String },
}

/// Engine that evaluates memories for importance reclassification.
pub struct ReclassificationEngine;

impl ReclassificationEngine {
    /// Evaluate a single memory for reclassification.
    pub fn evaluate(
        memory: &BaseMemory,
        signals: &ReclassificationSignals,
        is_user_set_critical: bool,
        last_reclassification: Option<&ReclassificationRecord>,
    ) -> ReclassificationEvaluation {
        let composite_score = signals.composite_score();

        // Find applicable rule
        let rule = match rules::find_applicable_rule(memory.importance, composite_score) {
            Some(r) => r,
            None => {
                return ReclassificationEvaluation {
                    memory_id: memory.id.clone(),
                    current_importance: memory.importance,
                    composite_score,
                    decision: ReclassificationDecision::NoChange,
                };
            }
        };

        // Check safeguards
        let safeguard = safeguards::is_reclassification_allowed(
            &memory.id,
            memory.importance,
            rule.direction,
            is_user_set_critical,
            last_reclassification,
            rule.cooldown_months,
        );

        match safeguard {
            SafeguardResult::Allowed => ReclassificationEvaluation {
                memory_id: memory.id.clone(),
                current_importance: memory.importance,
                composite_score,
                decision: ReclassificationDecision::Reclassify {
                    new_importance: rule.to,
                    rule,
                },
            },
            SafeguardResult::Blocked { reason } => ReclassificationEvaluation {
                memory_id: memory.id.clone(),
                current_importance: memory.importance,
                composite_score,
                decision: ReclassificationDecision::Blocked { reason },
            },
        }
    }

    /// Run a full reclassification pass over all memories.
    ///
    /// `signal_provider` is a function that gathers signals for a given memory.
    /// `history_provider` returns the last reclassification record for a memory.
    /// `user_critical_check` returns true if the memory was explicitly set to critical by a user.
    pub fn run_full_pass<F, H, U>(
        storage: &dyn IMemoryStorage,
        signal_provider: F,
        history_provider: H,
        user_critical_check: U,
    ) -> CortexResult<Vec<ReclassificationEvaluation>>
    where
        F: Fn(&BaseMemory) -> ReclassificationSignals,
        H: Fn(&str) -> Option<ReclassificationRecord>,
        U: Fn(&str) -> bool,
    {
        let mut evaluations = Vec::new();

        // Evaluate all importance levels
        for importance in [
            Importance::Low,
            Importance::Normal,
            Importance::High,
            Importance::Critical,
        ] {
            let memories = storage.query_by_importance(importance)?;
            for memory in &memories {
                let signals = signal_provider(memory);
                let last_reclass = history_provider(&memory.id);
                let is_user_critical = user_critical_check(&memory.id);

                let eval =
                    Self::evaluate(memory, &signals, is_user_critical, last_reclass.as_ref());
                evaluations.push(eval);
            }
        }

        Ok(evaluations)
    }
}

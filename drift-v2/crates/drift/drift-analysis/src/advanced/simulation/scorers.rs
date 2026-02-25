//! 4 scorers for simulation: complexity, risk, effort, confidence.
//!
//! Each scorer produces a normalized [0.0, 1.0] score.

use super::types::{SimulationApproach, SimulationTask};

/// Trait for scoring a simulation approach.
pub trait Scorer: Send + Sync {
    /// Score a task+approach combination. Returns [0.0, 1.0].
    fn score(&self, task: &SimulationTask, approach: &SimulationApproach) -> f64;

    /// Human-readable name of this scorer.
    fn name(&self) -> &'static str;

    /// Weight of this scorer in composite scoring.
    fn weight(&self) -> f64;
}

/// Complexity scorer — cyclomatic + cognitive complexity.
///
/// Higher complexity → higher score (worse).
pub struct ComplexityScorer;

impl Scorer for ComplexityScorer {
    fn score(&self, task: &SimulationTask, _approach: &SimulationApproach) -> f64 {
        let ctx = &task.context;
        // Normalize: complexity 0-50 maps to 0.0-1.0
        let cyclomatic = (ctx.avg_complexity / 50.0).clamp(0.0, 1.0);
        let cognitive = (ctx.avg_cognitive_complexity / 50.0).clamp(0.0, 1.0);
        // Weighted average: cognitive complexity is harder to reason about
        let raw = cyclomatic * 0.4 + cognitive * 0.6;
        raw.clamp(0.0, 1.0)
    }

    fn name(&self) -> &'static str { "complexity" }
    fn weight(&self) -> f64 { 0.25 }
}

/// Risk scorer — blast radius + data sensitivity.
///
/// Higher blast radius or sensitivity → higher score (worse).
pub struct RiskScorer;

impl Scorer for RiskScorer {
    fn score(&self, task: &SimulationTask, _approach: &SimulationApproach) -> f64 {
        let ctx = &task.context;
        // Normalize blast radius: 0-100 callers maps to 0.0-1.0
        let blast = (ctx.blast_radius as f64 / 100.0).clamp(0.0, 1.0);
        let sensitivity = ctx.sensitivity.clamp(0.0, 1.0);
        let instability = ctx.coupling_instability.clamp(0.0, 1.0);
        // Weighted: blast radius most important, then sensitivity, then instability
        let raw = blast * 0.45 + sensitivity * 0.35 + instability * 0.20;
        raw.clamp(0.0, 1.0)
    }

    fn name(&self) -> &'static str { "risk" }
    fn weight(&self) -> f64 { 0.30 }
}

/// Effort scorer — LOC estimate + dependency count.
///
/// More code and dependencies → higher score (more effort).
pub struct EffortScorer;

impl Scorer for EffortScorer {
    fn score(&self, task: &SimulationTask, _approach: &SimulationApproach) -> f64 {
        let ctx = &task.context;
        // Normalize LOC: 0-10000 lines maps to 0.0-1.0
        let loc = (ctx.total_loc as f64 / 10_000.0).clamp(0.0, 1.0);
        // Normalize deps: 0-50 deps maps to 0.0-1.0
        let deps = (ctx.dependency_count as f64 / 50.0).clamp(0.0, 1.0);
        let raw = loc * 0.6 + deps * 0.4;
        raw.clamp(0.0, 1.0)
    }

    fn name(&self) -> &'static str { "effort" }
    fn weight(&self) -> f64 { 0.25 }
}

/// Confidence scorer — test coverage + constraint satisfaction.
///
/// Higher coverage and fewer violations → lower score (better confidence).
/// Note: this scorer is inverted — lower score means MORE confidence.
pub struct ConfidenceScorer;

impl Scorer for ConfidenceScorer {
    fn score(&self, task: &SimulationTask, _approach: &SimulationApproach) -> f64 {
        let ctx = &task.context;
        // Invert: high coverage = low uncertainty
        let coverage_gap = 1.0 - ctx.test_coverage.clamp(0.0, 1.0);
        // Normalize violations: 0-20 maps to 0.0-1.0
        let violations = (ctx.constraint_violations as f64 / 20.0).clamp(0.0, 1.0);
        let raw = coverage_gap * 0.6 + violations * 0.4;
        raw.clamp(0.0, 1.0)
    }

    fn name(&self) -> &'static str { "confidence" }
    fn weight(&self) -> f64 { 0.20 }
}

/// Get all 4 scorers.
pub fn all_scorers() -> Vec<Box<dyn Scorer>> {
    vec![
        Box::new(ComplexityScorer),
        Box::new(RiskScorer),
        Box::new(EffortScorer),
        Box::new(ConfidenceScorer),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advanced::simulation::types::*;

    fn make_task(ctx: SimulationContext) -> SimulationTask {
        SimulationTask {
            category: TaskCategory::AddFeature,
            description: "test task".to_string(),
            affected_files: vec![],
            context: ctx,
        }
    }

    fn make_approach() -> SimulationApproach {
        SimulationApproach {
            name: "test".to_string(),
            description: "test approach".to_string(),
            estimated_effort_hours: 10.0,
            risk_level: RiskLevel::Low,
            affected_file_count: 5,
            complexity_score: 0.0,
            risk_score: 0.0,
            effort_score: 0.0,
            confidence_score: 0.0,
            composite_score: 0.0,
            tradeoffs: vec![],
        }
    }

    #[test]
    fn test_all_scorers_produce_valid_range() {
        let scorers = all_scorers();
        let task = make_task(SimulationContext {
            avg_complexity: 25.0,
            avg_cognitive_complexity: 30.0,
            blast_radius: 50,
            sensitivity: 0.5,
            test_coverage: 0.6,
            constraint_violations: 5,
            total_loc: 5000,
            dependency_count: 20,
            coupling_instability: 0.4,
        });
        let approach = make_approach();

        for scorer in &scorers {
            let score = scorer.score(&task, &approach);
            assert!(
                (0.0..=1.0).contains(&score),
                "Scorer {} produced out-of-range score: {}",
                scorer.name(),
                score
            );
        }
    }

    #[test]
    fn test_scorers_with_zero_context() {
        let scorers = all_scorers();
        let task = make_task(SimulationContext::default());
        let approach = make_approach();

        for scorer in &scorers {
            let score = scorer.score(&task, &approach);
            assert!(
                (0.0..=1.0).contains(&score),
                "Scorer {} failed with zero context: {}",
                scorer.name(),
                score
            );
        }
    }

    #[test]
    fn test_scorers_with_extreme_context() {
        let scorers = all_scorers();
        let task = make_task(SimulationContext {
            avg_complexity: 100.0,
            avg_cognitive_complexity: 100.0,
            blast_radius: 500,
            sensitivity: 1.0,
            test_coverage: 1.0,
            constraint_violations: 100,
            total_loc: 50000,
            dependency_count: 200,
            coupling_instability: 1.0,
        });
        let approach = make_approach();

        for scorer in &scorers {
            let score = scorer.score(&task, &approach);
            assert!(
                (0.0..=1.0).contains(&score),
                "Scorer {} failed with extreme context: {}",
                scorer.name(),
                score
            );
        }
    }

    #[test]
    fn test_high_complexity_high_coverage_balanced() {
        let task = make_task(SimulationContext {
            avg_complexity: 45.0,
            avg_cognitive_complexity: 45.0,
            blast_radius: 80,
            sensitivity: 0.8,
            test_coverage: 0.95,
            constraint_violations: 1,
            total_loc: 8000,
            dependency_count: 30,
            coupling_instability: 0.7,
        });
        let approach = make_approach();

        let complexity = ComplexityScorer.score(&task, &approach);
        let confidence = ConfidenceScorer.score(&task, &approach);

        // High complexity but high coverage → complexity high, confidence low
        assert!(complexity > 0.5, "Expected high complexity score");
        assert!(confidence < 0.3, "Expected low confidence score (good coverage)");
        // Neither should be NaN
        assert!(!complexity.is_nan());
        assert!(!confidence.is_nan());
    }
}

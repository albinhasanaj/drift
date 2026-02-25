//! 15 strategy recommendations for simulation approaches.

use super::types::*;
use super::scorers::{all_scorers, Scorer};
use super::monte_carlo::MonteCarloSimulator;

/// Strategy recommender — generates approaches and recommends the best one.
pub struct StrategyRecommender {
    scorers: Vec<Box<dyn Scorer>>,
    simulator: MonteCarloSimulator,
}

impl StrategyRecommender {
    pub fn new() -> Self {
        Self {
            scorers: all_scorers(),
            simulator: MonteCarloSimulator::new(1000),
        }
    }

    pub fn with_seed(mut self, seed: u64) -> Self {
        self.simulator = MonteCarloSimulator::new(1000).with_seed(seed);
        self
    }

    /// Generate approaches for a task and recommend the best one.
    pub fn recommend(&self, task: &SimulationTask) -> SimulationResult {
        let mut approaches = self.generate_approaches(task);

        // Score each approach
        for approach in &mut approaches {
            let mut composite = 0.0;
            let mut total_weight = 0.0;

            for scorer in &self.scorers {
                let score = scorer.score(task, approach);
                total_weight += scorer.weight();

                match scorer.name() {
                    "complexity" => approach.complexity_score = score,
                    "risk" => approach.risk_score = score,
                    "effort" => approach.effort_score = score,
                    "confidence" => approach.confidence_score = score,
                    _ => {}
                }

                // Lower composite = better (less risk, less effort, etc.)
                composite += score * scorer.weight();
            }

            if total_weight > 0.0 {
                approach.composite_score = composite / total_weight;
            }
            approach.risk_level = RiskLevel::from_score(approach.risk_score);
        }

        // Sort by composite score (lower = better)
        approaches.sort_by(|a, b| {
            a.composite_score
                .partial_cmp(&b.composite_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let recommended_index = 0; // Best approach is first after sort

        // Run Monte Carlo for effort estimation
        let effort_estimate = self.simulator.simulate(task.category, &task.context);

        SimulationResult {
            task_category: task.category,
            task_description: task.description.clone(),
            approaches,
            effort_estimate,
            recommended_approach_index: recommended_index,
            simulation_iterations: 1000,
        }
    }

    /// Generate candidate approaches based on task category.
    fn generate_approaches(&self, task: &SimulationTask) -> Vec<SimulationApproach> {
        let strategies = strategies_for_category(task.category);
        strategies
            .into_iter()
            .map(|(name, desc, effort_mult, tradeoffs)| {
                let base = task.category.base_effort_hours();
                SimulationApproach {
                    name: name.to_string(),
                    description: desc.to_string(),
                    estimated_effort_hours: base * effort_mult,
                    risk_level: RiskLevel::Low,
                    affected_file_count: task.affected_files.len(),
                    complexity_score: 0.0,
                    risk_score: 0.0,
                    effort_score: 0.0,
                    confidence_score: 0.0,
                    composite_score: 0.0,
                    tradeoffs: tradeoffs.iter().map(|s| s.to_string()).collect(),
                }
            })
            .collect()
    }
}

impl Default for StrategyRecommender {
    fn default() -> Self {
        Self::new()
    }
}

/// 15 strategy templates mapped to task categories.
/// Returns (name, description, effort_multiplier, tradeoffs).
fn strategies_for_category(
    category: TaskCategory,
) -> Vec<(&'static str, &'static str, f64, Vec<&'static str>)> {
    match category {
        TaskCategory::AddFeature => vec![
            ("incremental", "Add feature incrementally with feature flags", 1.0,
             vec!["Lower risk", "Slower delivery", "Flag cleanup needed"]),
            ("big_bang", "Implement complete feature in one pass", 0.8,
             vec!["Faster delivery", "Higher risk", "Harder to review"]),
            ("prototype_first", "Build prototype, validate, then productionize", 1.3,
             vec!["Better design", "More effort", "Validated approach"]),
        ],
        TaskCategory::FixBug => vec![
            ("minimal_fix", "Smallest change that fixes the bug", 0.6,
             vec!["Low risk", "May not address root cause", "Quick turnaround"]),
            ("root_cause", "Fix the root cause with comprehensive testing", 1.2,
             vec!["Prevents recurrence", "More effort", "Better long-term"]),
            ("defensive", "Fix bug and add defensive checks around it", 1.0,
             vec!["Prevents similar bugs", "More code", "Better resilience"]),
        ],
        TaskCategory::Refactor => vec![
            ("strangler_fig", "Gradually replace old code with new implementation", 1.5,
             vec!["Low risk", "Longer timeline", "Parallel systems temporarily"]),
            ("extract_and_replace", "Extract interface, then swap implementation", 1.0,
             vec!["Clean separation", "Moderate risk", "Good testability"]),
            ("rewrite", "Complete rewrite of the module", 0.8,
             vec!["Clean slate", "High risk", "May lose edge cases"]),
        ],
        TaskCategory::SecurityFix => vec![
            ("patch", "Apply targeted security patch", 0.5,
             vec!["Quick mitigation", "May miss variants", "Low disruption"]),
            ("harden", "Comprehensive hardening of the affected area", 1.2,
             vec!["Thorough protection", "More effort", "Better posture"]),
            ("defense_in_depth", "Add multiple layers of security controls", 1.5,
             vec!["Maximum protection", "Significant effort", "May impact performance"]),
        ],
        TaskCategory::PerformanceOptimization => vec![
            ("profile_and_fix", "Profile hotspots and optimize critical paths", 1.0,
             vec!["Data-driven", "Targeted impact", "Requires profiling setup"]),
            ("algorithmic", "Replace algorithm with more efficient alternative", 0.8,
             vec!["Potentially large gains", "Higher risk", "Needs correctness proof"]),
            ("caching", "Add caching layer to reduce computation", 0.7,
             vec!["Quick wins", "Cache invalidation complexity", "Memory tradeoff"]),
        ],
        _ => vec![
            ("standard", "Standard approach for this task type", 1.0,
             vec!["Predictable", "Well-understood", "No surprises"]),
            ("accelerated", "Fast-track approach with reduced validation", 0.7,
             vec!["Faster delivery", "Higher risk", "Less validation"]),
            ("thorough", "Comprehensive approach with extra validation", 1.3,
             vec!["Lower risk", "More effort", "Better quality"]),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task(category: TaskCategory) -> SimulationTask {
        SimulationTask {
            category,
            description: format!("Test task for {:?}", category),
            affected_files: vec!["src/main.rs".to_string()],
            context: SimulationContext {
                avg_complexity: 15.0,
                avg_cognitive_complexity: 20.0,
                blast_radius: 25,
                sensitivity: 0.3,
                test_coverage: 0.7,
                constraint_violations: 2,
                total_loc: 3000,
                dependency_count: 10,
                coupling_instability: 0.3,
            },
        }
    }

    #[test]
    fn test_generates_approaches_for_all_categories() {
        let recommender = StrategyRecommender::new().with_seed(42);

        for category in TaskCategory::ALL {
            let task = make_task(*category);
            let result = recommender.recommend(&task);
            assert!(
                !result.approaches.is_empty(),
                "No approaches for {:?}",
                category
            );
            assert!(result.effort_estimate.is_valid());
        }
    }

    #[test]
    fn test_at_least_5_categories_generate_approaches() {
        let recommender = StrategyRecommender::new().with_seed(42);
        let mut categories_with_approaches = 0;

        for category in TaskCategory::ALL {
            let task = make_task(*category);
            let result = recommender.recommend(&task);
            if !result.approaches.is_empty() {
                categories_with_approaches += 1;
            }
        }

        assert!(
            categories_with_approaches >= 5,
            "Only {} categories generated approaches, need at least 5",
            categories_with_approaches
        );
    }

    #[test]
    fn test_recommended_approach_is_valid_index() {
        let recommender = StrategyRecommender::new().with_seed(42);
        let task = make_task(TaskCategory::AddFeature);
        let result = recommender.recommend(&task);

        assert!(result.recommended_approach_index < result.approaches.len());
    }

    #[test]
    fn test_approaches_have_valid_scores() {
        let recommender = StrategyRecommender::new().with_seed(42);
        let task = make_task(TaskCategory::FixBug);
        let result = recommender.recommend(&task);

        for approach in &result.approaches {
            assert!((0.0..=1.0).contains(&approach.complexity_score));
            assert!((0.0..=1.0).contains(&approach.risk_score));
            assert!((0.0..=1.0).contains(&approach.effort_score));
            assert!((0.0..=1.0).contains(&approach.confidence_score));
        }
    }
}

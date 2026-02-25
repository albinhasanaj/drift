//! Phase 7 Simulation Engine tests — T7-SIM-01 through T7-SIM-07.

use drift_analysis::advanced::simulation::*;

fn make_context(complexity: f64, blast_radius: u32, coverage: f64) -> SimulationContext {
    SimulationContext {
        avg_complexity: complexity,
        avg_cognitive_complexity: complexity * 1.2,
        blast_radius,
        sensitivity: 0.3,
        test_coverage: coverage,
        constraint_violations: 2,
        total_loc: 3000,
        dependency_count: 10,
        coupling_instability: 0.3,
    }
}

fn make_task(category: TaskCategory) -> SimulationTask {
    SimulationTask {
        category,
        description: format!("Test task for {:?}", category),
        affected_files: vec!["src/main.rs".to_string(), "src/lib.rs".to_string()],
        context: make_context(15.0, 25, 0.7),
    }
}

// T7-SIM-01: Simulation generates approaches for at least 5 of 13 task categories.
#[test]
fn t7_sim_01_generates_approaches_for_at_least_5_categories() {
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
    // Actually all 13 should work
    assert_eq!(categories_with_approaches, 13);
}

// T7-SIM-02: Monte Carlo produces P10/P50/P90 — verify P10 < P50 < P90.
#[test]
fn t7_sim_02_monte_carlo_ordering_invariant() {
    let sim = MonteCarloSimulator::new(5000).with_seed(42);
    let ctx = make_context(15.0, 30, 0.7);

    for category in TaskCategory::ALL {
        let ci = sim.simulate(*category, &ctx);
        assert!(
            ci.is_valid(),
            "Category {:?}: P10={:.2} P50={:.2} P90={:.2} — ordering violated",
            category, ci.p10, ci.p50, ci.p90
        );
        assert!(ci.p10 > 0.0, "P10 must be positive for {:?}", category);
        assert!(ci.p90 > ci.p10, "P90 must exceed P10 for {:?}", category);
    }
}

// T7-SIM-04: Monte Carlo with deterministic seed produces identical results.
#[test]
fn t7_sim_04_deterministic_seed_reproducibility() {
    let ctx = make_context(20.0, 40, 0.6);

    let sim1 = MonteCarloSimulator::new(2000).with_seed(12345);
    let ci1 = sim1.simulate(TaskCategory::AddFeature, &ctx);

    let sim2 = MonteCarloSimulator::new(2000).with_seed(12345);
    let ci2 = sim2.simulate(TaskCategory::AddFeature, &ctx);

    assert_eq!(ci1.p10, ci2.p10, "P10 not reproducible");
    assert_eq!(ci1.p50, ci2.p50, "P50 not reproducible");
    assert_eq!(ci1.p90, ci2.p90, "P90 not reproducible");
}

// T7-SIM-05: All 4 scorers produce scores in [0.0, 1.0].
#[test]
fn t7_sim_05_all_scorers_valid_range() {
    let scorers = scorers::all_scorers();
    let task = make_task(TaskCategory::Refactor);
    let approach = SimulationApproach {
        name: "test".into(),
        description: "test approach".into(),
        estimated_effort_hours: 10.0,
        risk_level: RiskLevel::Low,
        affected_file_count: 5,
        complexity_score: 0.0,
        risk_score: 0.0,
        effort_score: 0.0,
        confidence_score: 0.0,
        composite_score: 0.0,
        tradeoffs: vec![],
    };

    for scorer in &scorers {
        let score = scorer.score(&task, &approach);
        assert!(
            (0.0..=1.0).contains(&score),
            "Scorer '{}' produced {}, expected [0.0, 1.0]",
            scorer.name(),
            score
        );
        assert!(!score.is_nan(), "Scorer '{}' produced NaN", scorer.name());
    }
}

// T7-SIM-06: Simulation with zero historical data — wide intervals, not error.
#[test]
fn t7_sim_06_zero_context_wide_intervals() {
    let recommender = StrategyRecommender::new().with_seed(99);
    let task = SimulationTask {
        category: TaskCategory::FixBug,
        description: "Fix with no context".into(),
        affected_files: vec![],
        context: SimulationContext::default(),
    };

    let result = recommender.recommend(&task);
    assert!(!result.approaches.is_empty(), "Should still produce approaches");
    assert!(result.effort_estimate.is_valid(), "CI should be valid even with zero context");
    assert!(result.effort_estimate.p10 > 0.0, "P10 should be positive");
}

// T7-SIM-07: Contradictory signals (high complexity + high coverage) — balanced, not NaN.
#[test]
fn t7_sim_07_contradictory_signals_balanced() {
    let recommender = StrategyRecommender::new().with_seed(42);
    let task = SimulationTask {
        category: TaskCategory::SecurityFix,
        description: "High complexity but high coverage".into(),
        affected_files: vec!["src/auth.rs".into()],
        context: SimulationContext {
            avg_complexity: 45.0,
            avg_cognitive_complexity: 50.0,
            blast_radius: 80,
            sensitivity: 0.9,
            test_coverage: 0.95,
            constraint_violations: 1,
            total_loc: 8000,
            dependency_count: 30,
            coupling_instability: 0.7,
        },
    };

    let result = recommender.recommend(&task);
    for approach in &result.approaches {
        assert!(!approach.composite_score.is_nan(), "Composite score is NaN");
        assert!(!approach.complexity_score.is_nan(), "Complexity score is NaN");
        assert!(!approach.risk_score.is_nan(), "Risk score is NaN");
        assert!(!approach.effort_score.is_nan(), "Effort score is NaN");
        assert!(!approach.confidence_score.is_nan(), "Confidence score is NaN");
        assert!(
            (0.0..=1.0).contains(&approach.composite_score),
            "Composite score {} out of range",
            approach.composite_score
        );
    }
    assert!(result.effort_estimate.is_valid());
}

// Additional: Verify 13 task categories exist.
#[test]
fn test_13_task_categories_exist() {
    assert_eq!(TaskCategory::ALL.len(), 13);
}

// Additional: Verify recommended approach index is valid.
#[test]
fn test_recommended_approach_index_valid() {
    let recommender = StrategyRecommender::new().with_seed(42);
    for category in TaskCategory::ALL {
        let task = make_task(*category);
        let result = recommender.recommend(&task);
        assert!(
            result.recommended_approach_index < result.approaches.len(),
            "Invalid recommended index for {:?}",
            category
        );
    }
}

// Additional: Verify ConfidenceInterval::is_valid works correctly.
#[test]
fn test_confidence_interval_validation() {
    assert!(ConfidenceInterval { p10: 1.0, p50: 5.0, p90: 10.0 }.is_valid());
    assert!(!ConfidenceInterval { p10: 10.0, p50: 5.0, p90: 1.0 }.is_valid());
    assert!(!ConfidenceInterval { p10: -1.0, p50: 5.0, p90: 10.0 }.is_valid());
}

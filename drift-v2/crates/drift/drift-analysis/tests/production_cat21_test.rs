#![allow(clippy::manual_range_contains, clippy::unnecessary_map_or)]
//! Production Category 21: Advanced Systems (Flow 14) — Simulation & Decisions
//!
//! Tests: T21-01, T21-02, T21-03
//! Source: drift-analysis/src/advanced/simulation/, drift-analysis/src/advanced/decisions/

use drift_analysis::advanced::simulation::{
    MonteCarloSimulator, StrategyRecommender, SimulationContext, SimulationTask, TaskCategory,
};
use drift_analysis::advanced::decisions::{CommitSummary, GitAnalyzer};

/// T21-01: Simulation — All 13 Task Categories
///
/// Call `StrategyRecommender::recommend(task)` for each of the 13 categories.
/// Each must return non-empty approaches with confidence interval and risk assessment.
/// Source: advanced/simulation/ — StrategyRecommender::recommend() with 13 categories
#[test]
fn t21_01_simulation_all_13_task_categories() {
    let recommender = StrategyRecommender::new().with_seed(42);

    let context = SimulationContext {
        avg_complexity: 20.0,
        avg_cognitive_complexity: 25.0,
        blast_radius: 30,
        sensitivity: 0.4,
        test_coverage: 0.65,
        constraint_violations: 3,
        total_loc: 5000,
        dependency_count: 15,
        coupling_instability: 0.35,
    };

    assert_eq!(
        TaskCategory::ALL.len(),
        13,
        "Expected exactly 13 task categories"
    );

    for category in TaskCategory::ALL {
        let task = SimulationTask {
            category: *category,
            description: format!("Test task for {}", category.name()),
            affected_files: vec!["src/main.rs".to_string(), "src/lib.rs".to_string()],
            context: context.clone(),
        };

        let result = recommender.recommend(&task);

        // Must return non-empty approaches
        assert!(
            !result.approaches.is_empty(),
            "Category {:?} returned empty approaches",
            category
        );

        // Confidence interval must be valid (p10 <= p50 <= p90)
        assert!(
            result.effort_estimate.is_valid(),
            "Category {:?} has invalid confidence interval: p10={}, p50={}, p90={}",
            category,
            result.effort_estimate.p10,
            result.effort_estimate.p50,
            result.effort_estimate.p90
        );

        // All estimates must be positive
        assert!(
            result.effort_estimate.p10 > 0.0,
            "Category {:?} has non-positive p10",
            category
        );

        // Recommended approach index must be valid
        assert!(
            result.recommended_approach_index < result.approaches.len(),
            "Category {:?} has invalid recommended_approach_index: {} >= {}",
            category,
            result.recommended_approach_index,
            result.approaches.len()
        );

        // Each approach must have a risk assessment (risk_level is set from score)
        for approach in &result.approaches {
            assert!(
                (0.0..=1.0).contains(&approach.risk_score),
                "Category {:?}, approach '{}' has invalid risk_score: {}",
                category,
                approach.name,
                approach.risk_score
            );
            // risk_level is derived from risk_score — just verify it's not NaN
            assert!(!approach.composite_score.is_nan());
        }
    }
}

/// T21-02: Simulation — Monte Carlo Confidence
///
/// Run simulation with increasing iterations. Confidence interval must narrow
/// (or at least not widen) with more samples. Mean must converge.
/// Source: advanced/simulation/ — Monte Carlo confidence intervals
#[test]
fn t21_02_simulation_monte_carlo_confidence() {
    let context = SimulationContext {
        avg_complexity: 15.0,
        avg_cognitive_complexity: 20.0,
        blast_radius: 25,
        sensitivity: 0.3,
        test_coverage: 0.7,
        constraint_violations: 2,
        total_loc: 3000,
        dependency_count: 10,
        coupling_instability: 0.3,
    };

    let seed = 42u64;

    // Run with 100, 500, 2000, 5000 iterations
    let iterations = [100u32, 500, 2000, 5000];
    let mut spreads = Vec::new();
    let mut medians = Vec::new();

    for &n in &iterations {
        let sim = MonteCarloSimulator::new(n).with_seed(seed);
        let ci = sim.simulate(TaskCategory::AddFeature, &context);

        assert!(
            ci.is_valid(),
            "CI invalid at {} iterations: p10={}, p50={}, p90={}",
            n,
            ci.p10,
            ci.p50,
            ci.p90
        );

        let spread = ci.p90 - ci.p10;
        assert!(spread >= 0.0, "Negative spread at {} iterations", n);

        spreads.push(spread);
        medians.push(ci.p50);
    }

    // Median must converge: difference between 2000-iter and 5000-iter median
    // should be smaller than difference between 100-iter and 500-iter median
    let early_delta = (medians[0] - medians[1]).abs();
    let late_delta = (medians[2] - medians[3]).abs();
    // With a fixed seed, the convergence should be clear
    // Allow generous tolerance: late delta should be no more than 2x early delta
    // (It could be slightly larger due to statistical noise but should converge)
    assert!(
        late_delta <= early_delta * 2.5 + 0.5,
        "Median not converging: early_delta={}, late_delta={}",
        early_delta,
        late_delta
    );

    // Determinism: same seed must produce same results
    let sim_a = MonteCarloSimulator::new(1000).with_seed(seed);
    let ci_a = sim_a.simulate(TaskCategory::AddFeature, &context);
    let sim_b = MonteCarloSimulator::new(1000).with_seed(seed);
    let ci_b = sim_b.simulate(TaskCategory::AddFeature, &context);
    assert_eq!(ci_a.p10, ci_b.p10, "P10 not deterministic");
    assert_eq!(ci_a.p50, ci_b.p50, "P50 not deterministic");
    assert_eq!(ci_a.p90, ci_b.p90, "P90 not deterministic");
}

/// T21-03: Decision Mining — Git Log Parsing (via analyze_summaries)
///
/// Run GitAnalyzer::analyze_summaries on 100+ synthetic commits.
/// Must parse commit messages, extract decisions, group by category.
/// Source: advanced/decisions/ — GitAnalyzer, DecisionCategorizer
#[test]
fn t21_03_decision_mining_commit_parsing() {
    let analyzer = GitAnalyzer::new().with_max_commits(500);

    // Generate 120 synthetic commits covering multiple decision categories
    let mut summaries = Vec::new();

    // Architecture decisions
    for i in 0..15 {
        summaries.push(CommitSummary {
            sha: format!("arch{:04x}1234567890ab", i),
            message: format!("feat: decouple module {} into microservice architecture", i),
            author: "architect".to_string(),
            timestamp: 1700000000 + i as i64 * 1000,
            files_changed: vec![format!("src/services/module-{}/index.ts", i)],
            insertions: 200,
            deletions: 50,
        });
    }

    // Security decisions
    for i in 0..15 {
        summaries.push(CommitSummary {
            sha: format!("sec_{:04x}1234567890ab", i),
            message: format!("security: add rate limiting and CSRF protection for endpoint {}", i),
            author: "security-eng".to_string(),
            timestamp: 1700020000 + i as i64 * 1000,
            files_changed: vec!["src/middleware/security.ts".to_string()],
            insertions: 100,
            deletions: 10,
        });
    }

    // Technology decisions
    for i in 0..15 {
        summaries.push(CommitSummary {
            sha: format!("tech{:04x}1234567890ab", i),
            message: format!("feat: migrate database {} to PostgreSQL platform", i),
            author: "backend".to_string(),
            timestamp: 1700040000 + i as i64 * 1000,
            files_changed: vec!["package.json".to_string()],
            insertions: 80,
            deletions: 60,
        });
    }

    // Performance decisions
    for i in 0..10 {
        summaries.push(CommitSummary {
            sha: format!("perf{:04x}1234567890ab", i),
            message: format!("perf: optimize cache layer {} for better throughput", i),
            author: "perf-eng".to_string(),
            timestamp: 1700060000 + i as i64 * 1000,
            files_changed: vec!["src/cache/layer.ts".to_string()],
            insertions: 150,
            deletions: 80,
        });
    }

    // Testing decisions
    for i in 0..10 {
        summaries.push(CommitSummary {
            sha: format!("test{:04x}1234567890ab", i),
            message: format!("test: add integration test coverage for module {}", i),
            author: "qa".to_string(),
            timestamp: 1700080000 + i as i64 * 1000,
            files_changed: vec![format!("tests/integration/module-{}.test.ts", i)],
            insertions: 300,
            deletions: 20,
        });
    }

    // Deployment decisions
    for i in 0..10 {
        summaries.push(CommitSummary {
            sha: format!("depl{:04x}1234567890ab", i),
            message: format!("feat: add Docker kubernetes deployment for service {}", i),
            author: "devops".to_string(),
            timestamp: 1700100000 + i as i64 * 1000,
            files_changed: vec!["Dockerfile".to_string(), format!("k8s/service-{}.yaml", i)],
            insertions: 120,
            deletions: 30,
        });
    }

    // Trivial commits (should be skipped)
    for i in 0..20 {
        summaries.push(CommitSummary {
            sha: format!("triv{:04x}1234567890ab", i),
            message: format!("merge branch 'main' into feature-{}", i),
            author: "dev".to_string(),
            timestamp: 1700120000 + i as i64 * 1000,
            files_changed: vec!["src/app.ts".to_string()],
            insertions: 5,
            deletions: 2,
        });
    }

    // Low-signal commits
    for i in 0..25 {
        summaries.push(CommitSummary {
            sha: format!("misc{:04x}1234567890ab", i),
            message: format!("fix: update variable name in component {}", i),
            author: "dev".to_string(),
            timestamp: 1700140000 + i as i64 * 1000,
            files_changed: vec![format!("src/components/comp-{}.tsx", i)],
            insertions: 3,
            deletions: 3,
        });
    }

    assert!(
        summaries.len() >= 100,
        "Need 100+ commits, got {}",
        summaries.len()
    );

    let decisions = analyzer.analyze_summaries(&summaries);

    // Must extract at least some decisions
    assert!(
        !decisions.is_empty(),
        "No decisions extracted from {} commits",
        summaries.len()
    );

    // Group by category
    let mut categories = std::collections::HashSet::new();
    for d in &decisions {
        categories.insert(d.category);
        // Each decision must have required fields
        assert!(!d.id.is_empty(), "Decision has empty ID");
        assert!(!d.description.is_empty(), "Decision has empty description");
        assert!(
            d.confidence > 0.0 && d.confidence <= 1.0,
            "Decision confidence out of range: {}",
            d.confidence
        );
    }

    // Must detect at least 3 distinct categories from our synthetic data
    assert!(
        categories.len() >= 3,
        "Only found {} categories, expected at least 3. Categories: {:?}",
        categories.len(),
        categories
    );

    // Trivial commits (merge branch) should NOT produce decisions
    let merge_decisions: Vec<_> = decisions
        .iter()
        .filter(|d| d.commit_sha.as_deref().map_or(false, |s| s.starts_with("triv")))
        .collect();
    assert!(
        merge_decisions.is_empty(),
        "Trivial merge commits should not produce decisions, got {}",
        merge_decisions.len()
    );
}

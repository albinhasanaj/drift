//! Simulation engine types — tasks, approaches, results, confidence intervals.

use serde::{Deserialize, Serialize};

/// 13 task categories for simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskCategory {
    AddFeature,
    FixBug,
    Refactor,
    MigrateFramework,
    AddTest,
    SecurityFix,
    PerformanceOptimization,
    DependencyUpdate,
    ApiChange,
    DatabaseMigration,
    ConfigChange,
    Documentation,
    Infrastructure,
}

impl TaskCategory {
    /// All 13 categories.
    pub const ALL: &'static [TaskCategory] = &[
        Self::AddFeature, Self::FixBug, Self::Refactor, Self::MigrateFramework,
        Self::AddTest, Self::SecurityFix, Self::PerformanceOptimization,
        Self::DependencyUpdate, Self::ApiChange, Self::DatabaseMigration,
        Self::ConfigChange, Self::Documentation, Self::Infrastructure,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Self::AddFeature => "add_feature",
            Self::FixBug => "fix_bug",
            Self::Refactor => "refactor",
            Self::MigrateFramework => "migrate_framework",
            Self::AddTest => "add_test",
            Self::SecurityFix => "security_fix",
            Self::PerformanceOptimization => "performance_optimization",
            Self::DependencyUpdate => "dependency_update",
            Self::ApiChange => "api_change",
            Self::DatabaseMigration => "database_migration",
            Self::ConfigChange => "config_change",
            Self::Documentation => "documentation",
            Self::Infrastructure => "infrastructure",
        }
    }

    /// Base effort multiplier for this category (hours).
    pub fn base_effort_hours(&self) -> f64 {
        match self {
            Self::AddFeature => 16.0,
            Self::FixBug => 8.0,
            Self::Refactor => 12.0,
            Self::MigrateFramework => 40.0,
            Self::AddTest => 4.0,
            Self::SecurityFix => 10.0,
            Self::PerformanceOptimization => 14.0,
            Self::DependencyUpdate => 6.0,
            Self::ApiChange => 20.0,
            Self::DatabaseMigration => 24.0,
            Self::ConfigChange => 3.0,
            Self::Documentation => 4.0,
            Self::Infrastructure => 16.0,
        }
    }
}

impl std::fmt::Display for TaskCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Context for a simulation task — metrics from the analysis stack.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct SimulationContext {
    /// Average cyclomatic complexity of affected files.
    pub avg_complexity: f64,
    /// Average cognitive complexity of affected files.
    pub avg_cognitive_complexity: f64,
    /// Blast radius (transitive caller count) of affected functions.
    pub blast_radius: u32,
    /// Data sensitivity score (0.0-1.0).
    pub sensitivity: f64,
    /// Test coverage of affected code (0.0-1.0).
    pub test_coverage: f64,
    /// Number of constraint violations in affected code.
    pub constraint_violations: u32,
    /// Total lines of code in affected files.
    pub total_loc: u32,
    /// Number of dependencies of affected modules.
    pub dependency_count: u32,
    /// Coupling instability of affected modules (0.0-1.0).
    pub coupling_instability: f64,
}

/// A simulation task to evaluate.
#[derive(Debug, Clone)]
pub struct SimulationTask {
    pub category: TaskCategory,
    pub description: String,
    pub affected_files: Vec<String>,
    pub context: SimulationContext,
}

/// A candidate approach for completing a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationApproach {
    pub name: String,
    pub description: String,
    pub estimated_effort_hours: f64,
    pub risk_level: RiskLevel,
    pub affected_file_count: usize,
    pub complexity_score: f64,
    pub risk_score: f64,
    pub effort_score: f64,
    pub confidence_score: f64,
    pub composite_score: f64,
    pub tradeoffs: Vec<String>,
}

/// Risk level classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.75 { Self::Critical }
        else if score >= 0.50 { Self::High }
        else if score >= 0.25 { Self::Medium }
        else { Self::Low }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// P10/P50/P90 confidence interval for effort estimation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    /// 10th percentile (optimistic).
    pub p10: f64,
    /// 50th percentile (median).
    pub p50: f64,
    /// 90th percentile (pessimistic).
    pub p90: f64,
}

impl ConfidenceInterval {
    /// Validate the ordering invariant: p10 <= p50 <= p90.
    pub fn is_valid(&self) -> bool {
        self.p10 <= self.p50 && self.p50 <= self.p90 && self.p10 >= 0.0
    }
}

/// Complete simulation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub task_category: TaskCategory,
    pub task_description: String,
    pub approaches: Vec<SimulationApproach>,
    pub effort_estimate: ConfidenceInterval,
    pub recommended_approach_index: usize,
    pub simulation_iterations: u32,
}

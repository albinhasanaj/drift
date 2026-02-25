//! # drift-bench
//!
//! Benchmarks for the Drift analysis engine.
//! 4-level benchmark framework:
//! - **Micro**: Criterion-based function-level benchmarks
//! - **Component**: Integration benchmarks (single subsystem)
//! - **System**: End-to-end pipeline benchmarks
//! - **Regression**: CI-tracked benchmarks with baseline comparison
//!
//! Contains shared test fixtures, deterministic generators, and a
//! structured telemetry collector that produces machine-readable
//! benchmark reports with per-phase KPIs and regression detection.

// PH4-06: Blanket dead_code/unused suppression removed. Add targeted #[allow] on specific items if needed.

pub mod fixtures;
pub mod report;

/// Benchmark level — determines scope and CI behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BenchLevel {
    /// Function-level microbenchmarks (criterion). Run locally.
    Micro,
    /// Single-subsystem integration benchmarks. Run in CI.
    Component,
    /// Full pipeline end-to-end benchmarks. Run in CI nightly.
    System,
    /// Baseline-compared regression benchmarks. Block CI on regression.
    Regression,
}

impl BenchLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Component => "component",
            Self::System => "system",
            Self::Regression => "regression",
        }
    }

    /// Whether this level should block CI on regression.
    pub fn blocks_ci(&self) -> bool {
        matches!(self, Self::Regression)
    }

    /// Default regression threshold (percentage slower than baseline).
    pub fn regression_threshold(&self) -> f64 {
        match self {
            Self::Micro => 0.20,      // 20% regression allowed
            Self::Component => 0.50,  // 50% regression allowed
            Self::System => 1.00,     // 2x baseline allowed
            Self::Regression => 0.10, // 10% regression blocks CI
        }
    }
}

/// Benchmark result for CI comparison.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchResult {
    pub name: String,
    pub level: BenchLevel,
    pub duration_ms: f64,
    pub iterations: u64,
    pub throughput: Option<f64>,
}

impl BenchResult {
    /// Check if this result regresses vs a baseline.
    pub fn regresses_vs(&self, baseline: &BenchResult) -> bool {
        if baseline.duration_ms <= 0.0 {
            return false;
        }
        let ratio = self.duration_ms / baseline.duration_ms;
        ratio > (1.0 + self.level.regression_threshold())
    }
}

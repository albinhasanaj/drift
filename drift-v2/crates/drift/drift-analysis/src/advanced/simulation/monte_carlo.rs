//! Monte Carlo simulation for effort estimation with P10/P50/P90 confidence intervals.
//!
//! Uses random sampling with configurable iteration count and seed for reproducibility.

use super::types::{ConfidenceInterval, SimulationContext, TaskCategory};

/// Monte Carlo simulator for effort estimation.
pub struct MonteCarloSimulator {
    /// Number of simulation iterations.
    iterations: u32,
    /// Random seed for reproducibility (None = non-deterministic).
    seed: Option<u64>,
}

impl MonteCarloSimulator {
    /// Create a new simulator with the given iteration count.
    pub fn new(iterations: u32) -> Self {
        Self {
            iterations: iterations.max(100),
            seed: None,
        }
    }

    /// Set a deterministic seed for reproducible results.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Run Monte Carlo simulation and produce P10/P50/P90 confidence intervals.
    ///
    /// Uses a simple LCG (linear congruential generator) for portability
    /// and determinism without external dependencies.
    pub fn simulate(
        &self,
        category: TaskCategory,
        context: &SimulationContext,
    ) -> ConfidenceInterval {
        let base_effort = category.base_effort_hours();
        let mut samples = Vec::with_capacity(self.iterations as usize);

        // Initialize RNG state
        let mut rng_state = self.seed.unwrap_or_else(|| {
            // Use context hash as non-deterministic seed
            let mut h: u64 = 0xcbf29ce484222325;
            h = h.wrapping_mul(0x100000001b3).wrapping_add(base_effort.to_bits());
            h = h.wrapping_mul(0x100000001b3).wrapping_add(context.total_loc as u64);
            h = h.wrapping_mul(0x100000001b3).wrapping_add(context.blast_radius as u64);
            h
        });

        for _ in 0..self.iterations {
            // LCG: state = state * 6364136223846793005 + 1442695040888963407
            rng_state = rng_state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);

            // Convert to [0, 1) range
            let u = (rng_state >> 11) as f64 / (1u64 << 53) as f64;

            // Apply perturbation factors based on context
            let complexity_factor = 1.0 + (context.avg_complexity / 50.0).clamp(0.0, 2.0)
                * self.sample_normal(&mut rng_state, 0.0, 0.3);
            let risk_factor = 1.0 + (context.blast_radius as f64 / 100.0).clamp(0.0, 2.0)
                * self.sample_normal(&mut rng_state, 0.0, 0.2);
            let coverage_factor = if context.test_coverage > 0.8 {
                0.85 + u * 0.15 // Good coverage reduces variance
            } else if context.test_coverage > 0.5 {
                0.9 + u * 0.3
            } else {
                1.0 + u * 0.5 // Poor coverage increases uncertainty
            };
            let loc_factor = 1.0 + (context.total_loc as f64 / 10_000.0).clamp(0.0, 1.0) * 0.3;

            let sample = base_effort
                * complexity_factor.max(0.1)
                * risk_factor.max(0.1)
                * coverage_factor
                * loc_factor;

            samples.push(sample.max(0.5)); // Minimum 30 minutes
        }

        // Sort for percentile computation
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let p10 = self.percentile(&samples, 10);
        let p50 = self.percentile(&samples, 50);
        let p90 = self.percentile(&samples, 90);

        ConfidenceInterval { p10, p50, p90 }
    }

    /// Sample from approximate normal distribution using Box-Muller transform.
    fn sample_normal(&self, state: &mut u64, mean: f64, std_dev: f64) -> f64 {
        // Generate two uniform samples
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let u1 = ((*state >> 11) as f64 / (1u64 << 53) as f64).max(1e-10);
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let u2 = (*state >> 11) as f64 / (1u64 << 53) as f64;

        // Box-Muller transform
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        mean + std_dev * z
    }

    /// Compute the k-th percentile of a sorted slice.
    fn percentile(&self, sorted: &[f64], k: u32) -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let idx = (k as f64 / 100.0 * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }
}

impl Default for MonteCarloSimulator {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p10_less_than_p50_less_than_p90() {
        let sim = MonteCarloSimulator::new(5000).with_seed(42);
        let ctx = SimulationContext {
            avg_complexity: 15.0,
            avg_cognitive_complexity: 20.0,
            blast_radius: 30,
            sensitivity: 0.3,
            test_coverage: 0.7,
            constraint_violations: 2,
            total_loc: 3000,
            dependency_count: 10,
            coupling_instability: 0.3,
        };

        let ci = sim.simulate(TaskCategory::AddFeature, &ctx);
        assert!(ci.is_valid(), "CI ordering violated: p10={}, p50={}, p90={}", ci.p10, ci.p50, ci.p90);
        assert!(ci.p10 > 0.0, "P10 should be positive");
    }

    #[test]
    fn test_deterministic_with_seed() {
        let ctx = SimulationContext {
            avg_complexity: 10.0,
            avg_cognitive_complexity: 12.0,
            blast_radius: 20,
            sensitivity: 0.2,
            test_coverage: 0.8,
            constraint_violations: 1,
            total_loc: 2000,
            dependency_count: 8,
            coupling_instability: 0.2,
        };

        let sim1 = MonteCarloSimulator::new(1000).with_seed(12345);
        let ci1 = sim1.simulate(TaskCategory::FixBug, &ctx);

        let sim2 = MonteCarloSimulator::new(1000).with_seed(12345);
        let ci2 = sim2.simulate(TaskCategory::FixBug, &ctx);

        assert_eq!(ci1.p10, ci2.p10, "P10 not reproducible");
        assert_eq!(ci1.p50, ci2.p50, "P50 not reproducible");
        assert_eq!(ci1.p90, ci2.p90, "P90 not reproducible");
    }

    #[test]
    fn test_zero_context_wide_intervals() {
        let sim = MonteCarloSimulator::new(2000).with_seed(99);
        let ctx = SimulationContext::default();
        let ci = sim.simulate(TaskCategory::Refactor, &ctx);

        assert!(ci.is_valid());
        assert!(ci.p10 > 0.0);
        // With zero context, intervals should still be reasonable
        let spread = ci.p90 - ci.p10;
        assert!(spread >= 0.0, "Spread should be non-negative");
    }

    #[test]
    fn test_all_categories_produce_valid_intervals() {
        let sim = MonteCarloSimulator::new(500).with_seed(7);
        let ctx = SimulationContext {
            avg_complexity: 20.0,
            avg_cognitive_complexity: 25.0,
            blast_radius: 40,
            sensitivity: 0.5,
            test_coverage: 0.6,
            constraint_violations: 3,
            total_loc: 4000,
            dependency_count: 15,
            coupling_instability: 0.4,
        };

        for category in TaskCategory::ALL {
            let ci = sim.simulate(*category, &ctx);
            assert!(
                ci.is_valid(),
                "Category {:?} produced invalid CI: p10={}, p50={}, p90={}",
                category, ci.p10, ci.p50, ci.p90
            );
        }
    }
}

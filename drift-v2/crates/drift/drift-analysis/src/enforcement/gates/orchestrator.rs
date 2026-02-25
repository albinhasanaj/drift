//! DAG-based gate orchestrator — topological sort execution.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use super::types::*;
use super::progressive::{ProgressiveConfig, ProgressiveEnforcement};
use super::constraint_verification::ConstraintVerificationGate;
use super::error_handling::ErrorHandlingGate;
use super::pattern_compliance::PatternComplianceGate;
use super::regression::RegressionGate;
use super::security_boundaries::SecurityBoundariesGate;
use super::test_coverage::TestCoverageGate;

/// DAG-based gate orchestrator that respects gate dependencies.
pub struct GateOrchestrator {
    gates: Vec<Box<dyn QualityGate>>,
    progressive: Option<ProgressiveEnforcement>,
    /// Per-gate timeout. Default: 30 seconds.
    gate_timeout: Duration,
}

impl GateOrchestrator {
    /// Create a new orchestrator with all 6 default gates.
    pub fn new() -> Self {
        let gates: Vec<Box<dyn QualityGate>> = vec![
            Box::new(PatternComplianceGate),
            Box::new(ConstraintVerificationGate),
            Box::new(SecurityBoundariesGate),
            Box::new(TestCoverageGate),
            Box::new(ErrorHandlingGate),
            Box::new(RegressionGate),
        ];
        Self {
            gates,
            progressive: None,
            gate_timeout: Duration::from_secs(30),
        }
    }

    /// Create an orchestrator with custom gates.
    pub fn with_gates(gates: Vec<Box<dyn QualityGate>>) -> Self {
        Self {
            gates,
            progressive: None,
            gate_timeout: Duration::from_secs(30),
        }
    }

    /// Enable progressive enforcement with the given configuration.
    pub fn with_progressive(mut self, config: ProgressiveConfig) -> Self {
        if config.enabled {
            self.progressive = Some(ProgressiveEnforcement::new(config));
        }
        self
    }

    /// Set the per-gate execution timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.gate_timeout = timeout;
        self
    }

    /// Execute all gates in dependency order, returning results.
    ///
    /// If a gate's dependency failed, the dependent gate is skipped.
    /// Detects circular dependencies and returns an error.
    pub fn execute(&self, input: &GateInput) -> Result<Vec<GateResult>, String> {
        let order = self.topological_sort()?;
        let mut results: HashMap<GateId, GateResult> = HashMap::new();
        let mut output = Vec::new();

        for gate_id in &order {
            let gate = match self.gates.iter().find(|g| g.id() == *gate_id) {
                Some(g) => g,
                None => continue,
            };

            // Check if all dependencies passed
            let deps = gate.dependencies();
            let deps_met = deps.iter().all(|dep| {
                results.get(dep).is_some_and(|r| r.passed)
            });

            let result = if !deps_met {
                let failed_deps: Vec<String> = deps
                    .iter()
                    .filter(|dep| !results.get(dep).is_some_and(|r| r.passed))
                    .map(|d| d.to_string())
                    .collect();
                GateResult::skipped(
                    *gate_id,
                    format!(
                        "Skipped: dependencies not met ({})",
                        failed_deps.join(", ")
                    ),
                )
            } else {
                let mut gate_input = input.clone();
                gate_input.predecessor_results = results.clone();
                let start = std::time::Instant::now();
                let mut result = gate.evaluate(&gate_input);
                let elapsed = start.elapsed();
                result.execution_time_ms = elapsed.as_millis() as u64;

                // Check timeout
                if elapsed > self.gate_timeout {
                    result = GateResult::errored(
                        *gate_id,
                        format!(
                            "Gate execution timed out after {:.1}s (limit: {:.1}s)",
                            elapsed.as_secs_f64(),
                            self.gate_timeout.as_secs_f64(),
                        ),
                    );
                    result.execution_time_ms = elapsed.as_millis() as u64;
                }

                // Apply progressive enforcement to violations
                if let Some(ref progressive) = self.progressive {
                    let new_files: HashSet<&str> = input
                        .files
                        .iter()
                        .filter(|f| !input.all_files.contains(f))
                        .map(|f| f.as_str())
                        .collect();

                    for violation in &mut result.violations {
                        let is_new_file = new_files.contains(violation.file.as_str());
                        violation.severity =
                            progressive.effective_severity(violation.severity, is_new_file);
                    }
                }

                // Mark is_new based on baseline
                if !input.baseline_violations.is_empty() {
                    for violation in &mut result.violations {
                        let key = format!(
                            "{}:{}:{}",
                            violation.file, violation.line, violation.rule_id
                        );
                        violation.is_new = !input.baseline_violations.contains(&key);
                    }
                }

                result
            };

            results.insert(*gate_id, result.clone());
            output.push(result);
        }

        Ok(output)
    }

    /// Topological sort of gates based on dependencies.
    /// Returns an error if circular dependencies are detected.
    fn topological_sort(&self) -> Result<Vec<GateId>, String> {
        let mut in_degree: HashMap<GateId, usize> = HashMap::new();
        let mut adj: HashMap<GateId, Vec<GateId>> = HashMap::new();

        // Initialize
        for gate in &self.gates {
            in_degree.entry(gate.id()).or_insert(0);
            adj.entry(gate.id()).or_default();
        }

        // Build adjacency list
        for gate in &self.gates {
            for dep in gate.dependencies() {
                adj.entry(dep).or_default().push(gate.id());
                *in_degree.entry(gate.id()).or_insert(0) += 1;
            }
        }

        // Kahn's algorithm
        let mut queue: VecDeque<GateId> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut sorted = Vec::new();
        while let Some(node) = queue.pop_front() {
            sorted.push(node);
            if let Some(neighbors) = adj.get(&node) {
                for &neighbor in neighbors {
                    if let Some(deg) = in_degree.get_mut(&neighbor) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(neighbor);
                        }
                    }
                }
            }
        }

        if sorted.len() != self.gates.len() {
            return Err("Circular dependency detected in gate dependencies".to_string());
        }

        Ok(sorted)
    }

    /// Detect circular dependencies without executing.
    pub fn validate_dependencies(&self) -> Result<(), String> {
        self.topological_sort().map(|_| ())
    }
}

impl Default for GateOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

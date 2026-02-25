//! Structured benchmark telemetry collector and reporter.
//!
//! Transforms ad-hoc `Instant::now()` / `eprintln!` timing into a centralized
//! `BenchmarkRegistry` that collects per-phase metrics, computes KPIs, detects
//! regressions against a baseline, and emits machine-readable JSON reports.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Phase metric — one row in the report
// ---------------------------------------------------------------------------

/// A single phase measurement with derived KPIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseMetric {
    /// Human-readable phase name (e.g. "scanner", "parser", "analysis").
    pub name: String,
    /// Wall-clock duration in microseconds.
    pub duration_us: u64,
    /// Number of items processed (files, functions, patterns, rows …).
    pub items_processed: u64,
    /// Total bytes processed (source code bytes, DB payload …).
    pub bytes_processed: u64,
    /// Derived: items / second.
    pub items_per_second: f64,
    /// Derived: bytes / second.
    pub bytes_per_second: f64,
    /// Derived: microseconds per item.
    pub us_per_item: f64,
    /// Optional sub-metrics (e.g. per-language breakdown).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sub_metrics: BTreeMap<String, f64>,
}

impl PhaseMetric {
    /// Build a metric from raw measurements; derived fields are computed.
    pub fn new(
        name: impl Into<String>,
        duration: Duration,
        items_processed: u64,
        bytes_processed: u64,
    ) -> Self {
        let duration_us = duration.as_micros() as u64;
        let secs = duration.as_secs_f64().max(1e-9);
        Self {
            name: name.into(),
            duration_us,
            items_processed,
            bytes_processed,
            items_per_second: items_processed as f64 / secs,
            bytes_per_second: bytes_processed as f64 / secs,
            us_per_item: if items_processed > 0 {
                duration_us as f64 / items_processed as f64
            } else {
                0.0
            },
            sub_metrics: BTreeMap::new(),
        }
    }

    /// Attach an arbitrary sub-metric (e.g. "languages_detected", "cache_hit_rate").
    pub fn with_sub(mut self, key: impl Into<String>, value: f64) -> Self {
        self.sub_metrics.insert(key.into(), value);
        self
    }
}

// ---------------------------------------------------------------------------
// Environment metadata
// ---------------------------------------------------------------------------

/// Hardware / OS context captured at report time so that performance spikes
/// can be cross-referenced with the runner's specifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    pub os: String,
    pub arch: String,
    pub cpu_count: usize,
    pub hostname: String,
    pub rust_version: String,
    pub profile: String,
}

impl EnvironmentInfo {
    /// Capture the current environment.
    pub fn capture() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_count: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            hostname: std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "unknown".to_string()),
            rust_version: env!("CARGO_PKG_RUST_VERSION").to_string(),
            profile: if cfg!(debug_assertions) {
                "debug".to_string()
            } else {
                "release".to_string()
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Regression verdict
// ---------------------------------------------------------------------------

/// Per-phase regression check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionVerdict {
    pub phase: String,
    pub current_us: u64,
    pub baseline_us: u64,
    pub change_pct: f64,
    pub threshold_pct: f64,
    pub regressed: bool,
}

// ---------------------------------------------------------------------------
// Full benchmark report
// ---------------------------------------------------------------------------

/// The complete benchmark report — serializable to JSON for trend tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// ISO-8601 timestamp of when the report was generated.
    pub timestamp: String,
    /// Git commit SHA (if available).
    pub commit_sha: Option<String>,
    /// Environment metadata.
    pub environment: EnvironmentInfo,
    /// Fixture description (size, file count, total lines).
    pub fixture: FixtureInfo,
    /// Per-phase metrics.
    pub phases: Vec<PhaseMetric>,
    /// Aggregate KPIs.
    pub kpis: KpiSummary,
    /// Regression verdicts (only present when compared to a baseline).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regressions: Vec<RegressionVerdict>,
}

/// Fixture metadata embedded in the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureInfo {
    pub size_label: String,
    pub file_count: usize,
    pub total_lines: usize,
    pub total_bytes: usize,
    pub language_count: usize,
}

/// Aggregate KPIs derived from all phases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KpiSummary {
    /// Total wall-clock time across all phases (µs).
    pub total_duration_us: u64,
    /// Files / second (scanner throughput).
    pub files_per_second: f64,
    /// Lines of code / second (parser throughput).
    pub loc_per_second: f64,
    /// Functions extracted / second.
    pub functions_per_second: f64,
    /// Patterns matched / millisecond.
    pub patterns_per_ms: f64,
    /// Rows inserted / second (storage throughput).
    pub rows_per_second: f64,
    /// Phase-to-phase ratios.
    pub phase_ratios: BTreeMap<String, f64>,
}

// ---------------------------------------------------------------------------
// BenchmarkRegistry — the telemetry collector
// ---------------------------------------------------------------------------

/// Centralized telemetry collector. Wraps `Instant::now()` calls into
/// structured `PhaseMetric` entries and produces a `BenchmarkReport`.
pub struct BenchmarkRegistry {
    phases: Vec<PhaseMetric>,
    active_phase: Option<(String, Instant)>,
    fixture_info: Option<FixtureInfo>,
    commit_sha: Option<String>,
}

impl BenchmarkRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            phases: Vec::new(),
            active_phase: None,
            fixture_info: None,
            commit_sha: None,
        }
    }

    /// Set the fixture metadata for the report.
    pub fn set_fixture(&mut self, info: FixtureInfo) {
        self.fixture_info = Some(info);
    }

    /// Set the git commit SHA for the report.
    pub fn set_commit_sha(&mut self, sha: impl Into<String>) {
        self.commit_sha = Some(sha.into());
    }

    /// Start timing a phase. Returns the `Instant` for manual use if needed.
    pub fn start_phase(&mut self, name: impl Into<String>) -> Instant {
        let now = Instant::now();
        self.active_phase = Some((name.into(), now));
        now
    }

    /// End the active phase and record its metric.
    pub fn end_phase(&mut self, items_processed: u64, bytes_processed: u64) -> Option<&PhaseMetric> {
        let (name, start) = self.active_phase.take()?;
        let metric = PhaseMetric::new(name, start.elapsed(), items_processed, bytes_processed);
        self.phases.push(metric);
        self.phases.last()
    }

    /// Record a pre-built phase metric directly.
    pub fn record_phase(&mut self, metric: PhaseMetric) {
        self.phases.push(metric);
    }

    /// Get all recorded phases.
    pub fn phases(&self) -> &[PhaseMetric] {
        &self.phases
    }

    /// Find a phase by name.
    pub fn phase(&self, name: &str) -> Option<&PhaseMetric> {
        self.phases.iter().find(|p| p.name == name)
    }

    /// Build the final report with aggregate KPIs.
    pub fn build_report(&self) -> BenchmarkReport {
        let total_duration_us: u64 = self.phases.iter().map(|p| p.duration_us).sum();

        // Extract per-phase throughputs for KPI summary
        let files_per_second = self.phase("scanner")
            .map(|p| p.items_per_second)
            .unwrap_or(0.0);

        let loc_per_second = self.phase("parser")
            .and_then(|p| p.sub_metrics.get("lines_parsed"))
            .copied()
            .unwrap_or_else(|| {
                self.phase("parser").map(|p| p.bytes_per_second / 40.0).unwrap_or(0.0)
            });

        let functions_per_second = self.phase("parser")
            .and_then(|p| p.sub_metrics.get("functions_per_second"))
            .copied()
            .unwrap_or(0.0);

        let patterns_per_ms = self.phase("analysis")
            .and_then(|p| p.sub_metrics.get("patterns_per_ms"))
            .copied()
            .unwrap_or_else(|| {
                self.phase("analysis")
                    .map(|p| p.items_per_second / 1000.0)
                    .unwrap_or(0.0)
            });

        let rows_per_second = self.phase("storage")
            .map(|p| p.items_per_second)
            .unwrap_or(0.0);

        // Phase-to-phase ratios
        let mut phase_ratios = BTreeMap::new();
        let phase_names: Vec<_> = self.phases.iter().map(|p| p.name.clone()).collect();
        for i in 1..phase_names.len() {
            let prev = &self.phases[i - 1];
            let curr = &self.phases[i];
            if prev.duration_us > 0 {
                let ratio = curr.duration_us as f64 / prev.duration_us as f64;
                phase_ratios.insert(
                    format!("{}/{}", curr.name, prev.name),
                    (ratio * 100.0).round() / 100.0,
                );
            }
        }

        let fixture = self.fixture_info.clone().unwrap_or(FixtureInfo {
            size_label: "unknown".to_string(),
            file_count: 0,
            total_lines: 0,
            total_bytes: 0,
            language_count: 0,
        });

        BenchmarkReport {
            timestamp: chrono_lite_now(),
            commit_sha: self.commit_sha.clone(),
            environment: EnvironmentInfo::capture(),
            fixture,
            phases: self.phases.clone(),
            kpis: KpiSummary {
                total_duration_us,
                files_per_second,
                loc_per_second,
                functions_per_second,
                patterns_per_ms,
                rows_per_second,
                phase_ratios,
            },
            regressions: Vec::new(),
        }
    }

    /// Compare this run against a baseline report and produce regression verdicts.
    pub fn compare_to_baseline(
        &self,
        baseline: &BenchmarkReport,
        threshold_pct: f64,
    ) -> Vec<RegressionVerdict> {
        let mut verdicts = Vec::new();
        for current in &self.phases {
            if let Some(base) = baseline.phases.iter().find(|p| p.name == current.name) {
                let change_pct = if base.duration_us > 0 {
                    ((current.duration_us as f64 / base.duration_us as f64) - 1.0) * 100.0
                } else {
                    0.0
                };
                verdicts.push(RegressionVerdict {
                    phase: current.name.clone(),
                    current_us: current.duration_us,
                    baseline_us: base.duration_us,
                    change_pct: (change_pct * 100.0).round() / 100.0,
                    threshold_pct,
                    regressed: change_pct > threshold_pct,
                });
            }
        }
        verdicts
    }
}

impl Default for BenchmarkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BenchmarkReport {
    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Serialize to compact JSON (for CI artifacts).
    pub fn to_json_compact(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Write the report to a file.
    pub fn write_to_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_json())
    }

    /// Load a baseline report from a JSON file.
    pub fn load_from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Check if any phase regressed.
    pub fn has_regressions(&self) -> bool {
        self.regressions.iter().any(|r| r.regressed)
    }

    /// Human-readable summary for terminal output.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "╔══════════════════════════════════════════════════════════════╗\n"
        );
        out.push_str(&format!(
            "║  DRIFT BENCHMARK REPORT — {}  ║\n",
            &self.timestamp[..19]
        ));
        out.push_str(
            "╠══════════════════════════════════════════════════════════════╣\n"
        );
        out.push_str(&format!(
            "║  Fixture: {} ({} files, {} lines, {} bytes)\n",
            self.fixture.size_label,
            self.fixture.file_count,
            self.fixture.total_lines,
            self.fixture.total_bytes,
        ));
        out.push_str(&format!(
            "║  Env: {} {} ({} cores, {})\n",
            self.environment.os,
            self.environment.arch,
            self.environment.cpu_count,
            self.environment.profile,
        ));
        out.push_str(
            "╠══════════════════════════════════════════════════════════════╣\n"
        );
        out.push_str(&format!(
            "║  {:12} {:>10} {:>10} {:>12} {:>10}\n",
            "PHASE", "TIME(µs)", "ITEMS", "ITEMS/s", "µs/ITEM"
        ));
        out.push_str(&format!(
            "║  {:12} {:>10} {:>10} {:>12} {:>10}\n",
            "────────────", "──────────", "──────────", "────────────", "──────────"
        ));
        for p in &self.phases {
            out.push_str(&format!(
                "║  {:12} {:>10} {:>10} {:>12.1} {:>10.1}\n",
                p.name, p.duration_us, p.items_processed, p.items_per_second, p.us_per_item,
            ));
        }
        out.push_str(
            "╠══════════════════════════════════════════════════════════════╣\n"
        );
        out.push_str(&format!(
            "║  KPIs: {:.0} files/s | {:.0} LOC/s | {:.1} patterns/ms\n",
            self.kpis.files_per_second,
            self.kpis.loc_per_second,
            self.kpis.patterns_per_ms,
        ));
        out.push_str(&format!(
            "║  Total: {:.2}ms\n",
            self.kpis.total_duration_us as f64 / 1000.0,
        ));

        if !self.regressions.is_empty() {
            out.push_str(
                "╠══════════════════════════════════════════════════════════════╣\n"
            );
            for r in &self.regressions {
                let status = if r.regressed { "⚠ REGRESSED" } else { "✓ OK" };
                out.push_str(&format!(
                    "║  {} {:12} {:+.1}% (threshold: {:.0}%)\n",
                    status, r.phase, r.change_pct, r.threshold_pct,
                ));
            }
        }

        out.push_str(
            "╚══════════════════════════════════════════════════════════════╝\n"
        );
        out
    }
}

// ---------------------------------------------------------------------------
// Memory tracking
// ---------------------------------------------------------------------------

/// Memory snapshot at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemorySnapshot {
    /// Resident set size in bytes (platform-specific, best-effort).
    pub rss_bytes: u64,
    /// Virtual memory size in bytes.
    pub vms_bytes: u64,
}

impl MemorySnapshot {
    /// Capture current process memory (best-effort, platform-specific).
    pub fn capture() -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::capture_macos()
        }
        #[cfg(target_os = "linux")]
        {
            Self::capture_linux()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Self::default()
        }
    }

    #[cfg(target_os = "macos")]
    fn capture_macos() -> Self {
        use std::process::Command;
        // Use ps to get RSS in KB
        let output = Command::new("ps")
            .args(["-o", "rss=,vsz=", "-p", &std::process::id().to_string()])
            .output();
        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                let parts: Vec<&str> = text.split_whitespace().collect();
                let rss_kb = parts.first().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                let vsz_kb = parts.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                Self {
                    rss_bytes: rss_kb * 1024,
                    vms_bytes: vsz_kb * 1024,
                }
            }
            Err(_) => Self::default(),
        }
    }

    #[cfg(target_os = "linux")]
    fn capture_linux() -> Self {
        // Read /proc/self/statm: pages for total, resident
        match std::fs::read_to_string("/proc/self/statm") {
            Ok(content) => {
                let parts: Vec<&str> = content.split_whitespace().collect();
                let page_size = 4096u64; // typical
                let vms_pages = parts.first().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                let rss_pages = parts.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                Self {
                    rss_bytes: rss_pages * page_size,
                    vms_bytes: vms_pages * page_size,
                }
            }
            Err(_) => Self::default(),
        }
    }

    /// Human-readable RSS.
    pub fn rss_mb(&self) -> f64 {
        self.rss_bytes as f64 / (1024.0 * 1024.0)
    }
}

/// Memory delta between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryDelta {
    pub phase: String,
    pub before_rss_bytes: u64,
    pub after_rss_bytes: u64,
    pub delta_rss_bytes: i64,
    pub delta_rss_mb: f64,
}

// ---------------------------------------------------------------------------
// Scalability analysis
// ---------------------------------------------------------------------------

/// A data point for scalability analysis: (input_size, duration_us).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalabilityPoint {
    pub input_size: u64,
    pub duration_us: u64,
    pub items_per_second: f64,
}

/// Result of scalability analysis across multiple fixture sizes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalabilityResult {
    pub phase: String,
    pub points: Vec<ScalabilityPoint>,
    /// Scaling exponent: 1.0 = linear, 2.0 = quadratic.
    /// Computed via log-log regression.
    pub scaling_exponent: f64,
    /// R² of the log-log fit (1.0 = perfect fit).
    pub r_squared: f64,
    /// Whether the phase scales linearly (exponent < 1.3).
    pub is_linear: bool,
    /// Throughput efficiency: ratio of largest-tier throughput to smallest-tier.
    pub throughput_efficiency: f64,
}

/// Analyze scaling behavior from multiple (size, duration) data points.
/// Uses log-log linear regression to estimate the scaling exponent.
pub fn analyze_scalability(
    phase: &str,
    points: &[(u64, u64)],
) -> ScalabilityResult {
    let mut sp: Vec<ScalabilityPoint> = points
        .iter()
        .map(|&(size, dur)| {
            let secs = dur as f64 / 1_000_000.0;
            ScalabilityPoint {
                input_size: size,
                duration_us: dur,
                items_per_second: if secs > 0.0 { size as f64 / secs } else { 0.0 },
            }
        })
        .collect();
    sp.sort_by_key(|p| p.input_size);

    // Log-log regression: log(duration) = exponent * log(size) + intercept
    let n = sp.len() as f64;
    let (mut sum_x, mut sum_y, mut sum_xy, mut sum_x2) = (0.0, 0.0, 0.0, 0.0);
    for p in &sp {
        if p.input_size > 0 && p.duration_us > 0 {
            let x = (p.input_size as f64).ln();
            let y = (p.duration_us as f64).ln();
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
        }
    }

    let denom = n * sum_x2 - sum_x * sum_x;
    let (exponent, r_squared) = if denom.abs() > 1e-10 {
        let slope = (n * sum_xy - sum_x * sum_y) / denom;
        // R²
        let mean_y = sum_y / n;
        let mut ss_tot = 0.0;
        let mut ss_res = 0.0;
        let intercept = (sum_y - slope * sum_x) / n;
        for p in &sp {
            if p.input_size > 0 && p.duration_us > 0 {
                let x = (p.input_size as f64).ln();
                let y = (p.duration_us as f64).ln();
                let predicted = slope * x + intercept;
                ss_tot += (y - mean_y).powi(2);
                ss_res += (y - predicted).powi(2);
            }
        }
        let r2 = if ss_tot > 0.0 { 1.0 - ss_res / ss_tot } else { 0.0 };
        (slope, r2)
    } else {
        (1.0, 0.0)
    };

    let throughput_efficiency = if sp.len() >= 2 {
        let first = &sp[0];
        let last = &sp[sp.len() - 1];
        if first.items_per_second > 0.0 {
            last.items_per_second / first.items_per_second
        } else {
            0.0
        }
    } else {
        1.0
    };

    ScalabilityResult {
        phase: phase.to_string(),
        points: sp,
        scaling_exponent: (exponent * 1000.0).round() / 1000.0,
        r_squared: (r_squared * 1000.0).round() / 1000.0,
        is_linear: exponent < 1.3,
        throughput_efficiency: (throughput_efficiency * 1000.0).round() / 1000.0,
    }
}

// ---------------------------------------------------------------------------
// Performance budgets
// ---------------------------------------------------------------------------

/// A performance budget for a specific phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseBudget {
    pub phase: String,
    /// Maximum allowed µs per item.
    pub max_us_per_item: Option<f64>,
    /// Maximum allowed total duration in µs.
    pub max_total_us: Option<u64>,
    /// Maximum allowed memory delta in bytes.
    pub max_memory_delta_bytes: Option<i64>,
    /// Maximum allowed scaling exponent.
    pub max_scaling_exponent: Option<f64>,
}

/// Result of checking a phase against its budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetVerdict {
    pub phase: String,
    pub passed: bool,
    pub violations: Vec<String>,
}

/// A set of performance budgets for all phases.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceBudget {
    pub budgets: Vec<PhaseBudget>,
}

impl PerformanceBudget {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a budget for a phase.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, budget: PhaseBudget) -> Self {
        self.budgets.push(budget);
        self
    }

    /// Create enterprise-grade default budgets for Drift pipeline phases.
    pub fn enterprise_defaults() -> Self {
        Self::new()
            .add(PhaseBudget {
                phase: "scanner".to_string(),
                max_us_per_item: Some(500.0),       // 500µs/file max
                max_total_us: None,
                max_memory_delta_bytes: Some(100 * 1024 * 1024), // 100MB
                max_scaling_exponent: Some(1.2),
            })
            .add(PhaseBudget {
                phase: "parser".to_string(),
                max_us_per_item: Some(5000.0),      // 5ms/file max
                max_total_us: None,
                max_memory_delta_bytes: Some(500 * 1024 * 1024), // 500MB
                max_scaling_exponent: Some(1.2),
            })
            .add(PhaseBudget {
                phase: "analysis".to_string(),
                max_us_per_item: Some(10000.0),     // 10ms/file max
                max_total_us: None,
                max_memory_delta_bytes: Some(200 * 1024 * 1024), // 200MB
                max_scaling_exponent: Some(1.3),
            })
            .add(PhaseBudget {
                phase: "call_graph".to_string(),
                max_us_per_item: Some(2000.0),      // 2ms/file max
                max_total_us: None,
                max_memory_delta_bytes: None,
                max_scaling_exponent: Some(1.5),     // graph algos can be superlinear
            })
            .add(PhaseBudget {
                phase: "storage".to_string(),
                max_us_per_item: Some(1000.0),      // 1ms/row max
                max_total_us: None,
                max_memory_delta_bytes: Some(50 * 1024 * 1024), // 50MB
                max_scaling_exponent: Some(1.1),
            })
    }

    /// Check a report against all budgets.
    pub fn check(&self, report: &BenchmarkReport) -> Vec<BudgetVerdict> {
        self.budgets
            .iter()
            .filter_map(|budget| {
                let phase = report.phases.iter().find(|p| p.name == budget.phase)?;
                let mut violations = Vec::new();

                if let Some(max) = budget.max_us_per_item {
                    if phase.us_per_item > max {
                        violations.push(format!(
                            "us_per_item: {:.1} > {:.1} budget",
                            phase.us_per_item, max
                        ));
                    }
                }
                if let Some(max) = budget.max_total_us {
                    if phase.duration_us > max {
                        violations.push(format!(
                            "total_us: {} > {} budget",
                            phase.duration_us, max
                        ));
                    }
                }

                Some(BudgetVerdict {
                    phase: budget.phase.clone(),
                    passed: violations.is_empty(),
                    violations,
                })
            })
            .collect()
    }

    /// Check scalability results against budgets.
    pub fn check_scalability(&self, results: &[ScalabilityResult]) -> Vec<BudgetVerdict> {
        self.budgets
            .iter()
            .filter_map(|budget| {
                let result = results.iter().find(|r| r.phase == budget.phase)?;
                let mut violations = Vec::new();

                if let Some(max_exp) = budget.max_scaling_exponent {
                    if result.scaling_exponent > max_exp {
                        violations.push(format!(
                            "scaling_exponent: {:.3} > {:.1} budget ({})",
                            result.scaling_exponent,
                            max_exp,
                            if result.scaling_exponent > 2.0 { "QUADRATIC" }
                            else if result.scaling_exponent > 1.5 { "SUPERLINEAR" }
                            else { "SLIGHTLY SUPERLINEAR" }
                        ));
                    }
                }

                Some(BudgetVerdict {
                    phase: budget.phase.clone(),
                    passed: violations.is_empty(),
                    violations,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Trend ledger — append-only JSONL for historical tracking
// ---------------------------------------------------------------------------

/// Append-only ledger that stores one JSON report per line.
/// Enables multi-run trend analysis across commits.
pub struct TrendLedger {
    path: std::path::PathBuf,
}

impl TrendLedger {
    /// Open or create a ledger at the given path.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Append a report to the ledger (one JSON line).
    pub fn append(&self, report: &BenchmarkReport) -> std::io::Result<()> {
        use std::io::Write;
        let line = report.to_json_compact();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    /// Read all reports from the ledger.
    pub fn read_all(&self) -> std::io::Result<Vec<BenchmarkReport>> {
        let content = std::fs::read_to_string(&self.path)?;
        let mut reports = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<BenchmarkReport>(line) {
                Ok(r) => reports.push(r),
                Err(_) => continue, // skip malformed lines
            }
        }
        Ok(reports)
    }

    /// Get the last N reports.
    pub fn last_n(&self, n: usize) -> std::io::Result<Vec<BenchmarkReport>> {
        let all = self.read_all()?;
        let start = all.len().saturating_sub(n);
        Ok(all[start..].to_vec())
    }

    /// Compute trend for a specific phase across all reports.
    /// Returns (timestamp, duration_us) pairs.
    pub fn phase_trend(&self, phase: &str) -> std::io::Result<Vec<(String, u64)>> {
        let reports = self.read_all()?;
        Ok(reports
            .iter()
            .filter_map(|r| {
                r.phases
                    .iter()
                    .find(|p| p.name == phase)
                    .map(|p| (r.timestamp.clone(), p.duration_us))
            })
            .collect())
    }

    /// Detect if the latest report shows a sustained regression
    /// (last `window` runs all slower than the `window` before that).
    pub fn detect_sustained_regression(
        &self,
        phase: &str,
        window: usize,
    ) -> std::io::Result<Option<f64>> {
        let trend = self.phase_trend(phase)?;
        if trend.len() < window * 2 {
            return Ok(None);
        }
        let recent: Vec<u64> = trend[trend.len() - window..].iter().map(|t| t.1).collect();
        let previous: Vec<u64> = trend[trend.len() - 2 * window..trend.len() - window]
            .iter()
            .map(|t| t.1)
            .collect();

        let recent_avg = recent.iter().sum::<u64>() as f64 / recent.len() as f64;
        let prev_avg = previous.iter().sum::<u64>() as f64 / previous.len() as f64;

        if prev_avg > 0.0 {
            let change_pct = ((recent_avg / prev_avg) - 1.0) * 100.0;
            if change_pct > 5.0 {
                return Ok(Some(change_pct));
            }
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Enhanced BenchmarkRegistry — memory tracking
// ---------------------------------------------------------------------------

impl BenchmarkRegistry {
    /// Start a phase with memory snapshot.
    pub fn start_phase_with_memory(&mut self, name: impl Into<String>) -> (Instant, MemorySnapshot) {
        let snap = MemorySnapshot::capture();
        let now = self.start_phase(name);
        (now, snap)
    }

    /// End a phase and record memory delta.
    pub fn end_phase_with_memory(
        &mut self,
        items_processed: u64,
        bytes_processed: u64,
        before: &MemorySnapshot,
    ) -> Option<(&PhaseMetric, MemoryDelta)> {
        let after = MemorySnapshot::capture();
        let (name, start) = self.active_phase.take()?;
        let phase_name = name.clone();
        let metric = PhaseMetric::new(name, start.elapsed(), items_processed, bytes_processed);
        self.phases.push(metric);

        let delta = MemoryDelta {
            phase: phase_name,
            before_rss_bytes: before.rss_bytes,
            after_rss_bytes: after.rss_bytes,
            delta_rss_bytes: after.rss_bytes as i64 - before.rss_bytes as i64,
            delta_rss_mb: (after.rss_bytes as f64 - before.rss_bytes as f64) / (1024.0 * 1024.0),
        };

        // Store memory info as sub-metrics on the phase
        if let Some(phase) = self.phases.last_mut() {
            phase.sub_metrics.insert("memory_before_rss_mb".to_string(), before.rss_bytes as f64 / (1024.0 * 1024.0));
            phase.sub_metrics.insert("memory_after_rss_mb".to_string(), after.rss_bytes as f64 / (1024.0 * 1024.0));
            phase.sub_metrics.insert("memory_delta_mb".to_string(), delta.delta_rss_mb);
        }

        Some((self.phases.last().unwrap(), delta))
    }
}

// ---------------------------------------------------------------------------
// Enhanced BenchmarkReport — enterprise summary
// ---------------------------------------------------------------------------

impl BenchmarkReport {
    /// Enterprise-grade summary with memory, scalability, and budget info.
    pub fn enterprise_summary(
        &self,
        scalability: &[ScalabilityResult],
        budgets: &[BudgetVerdict],
        memory_deltas: &[MemoryDelta],
    ) -> String {
        let mut out = self.summary();

        // Remove the closing box line to append more sections
        if out.ends_with("╚══════════════════════════════════════════════════════════════╝\n") {
            out.truncate(out.len() - "╚══════════════════════════════════════════════════════════════╝\n".len());
        }

        // Memory section
        if !memory_deltas.is_empty() {
            out.push_str("╠══════════════════════════════════════════════════════════════╣\n");
            out.push_str("║  MEMORY PROFILE\n");
            for md in memory_deltas {
                out.push_str(&format!(
                    "║    {:12} {:+.1}MB (before: {:.1}MB, after: {:.1}MB)\n",
                    md.phase,
                    md.delta_rss_mb,
                    md.before_rss_bytes as f64 / (1024.0 * 1024.0),
                    md.after_rss_bytes as f64 / (1024.0 * 1024.0),
                ));
            }
        }

        // Scalability section
        if !scalability.is_empty() {
            out.push_str("╠══════════════════════════════════════════════════════════════╣\n");
            out.push_str("║  SCALABILITY ANALYSIS\n");
            for s in scalability {
                let status = if s.is_linear { "LINEAR" } else { "SUPERLINEAR" };
                out.push_str(&format!(
                    "║    {:12} O(n^{:.2}) R²={:.3} eff={:.1}% [{}]\n",
                    s.phase,
                    s.scaling_exponent,
                    s.r_squared,
                    s.throughput_efficiency * 100.0,
                    status,
                ));
            }
        }

        // Budget section
        if !budgets.is_empty() {
            out.push_str("╠══════════════════════════════════════════════════════════════╣\n");
            out.push_str("║  PERFORMANCE BUDGETS\n");
            for b in budgets {
                let status = if b.passed { "PASS" } else { "FAIL" };
                out.push_str(&format!("║    {:12} [{}]", b.phase, status));
                if !b.violations.is_empty() {
                    out.push_str(&format!(" — {}", b.violations.join("; ")));
                }
                out.push('\n');
            }
        }

        out.push_str("╚══════════════════════════════════════════════════════════════╝\n");
        out
    }
}

/// Lightweight ISO-8601 timestamp without pulling in chrono.
fn chrono_lite_now() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Approximate: good enough for benchmark reports
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Approximate date from days since epoch (not leap-second accurate, fine for reports)
    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let mut m = 1u32;
    let days_in_month = [31, if is_leap(y) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for &dim in &days_in_month {
        if remaining < dim {
            break;
        }
        remaining -= dim;
        m += 1;
    }
    let d = remaining + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_metric_derived_fields() {
        let m = PhaseMetric::new("test", Duration::from_millis(100), 50, 5000);
        assert_eq!(m.duration_us, 100_000);
        assert!((m.items_per_second - 500.0).abs() < 1.0);
        assert!((m.bytes_per_second - 50_000.0).abs() < 100.0);
        assert!((m.us_per_item - 2000.0).abs() < 1.0);
    }

    #[test]
    fn registry_phase_lifecycle() {
        let mut reg = BenchmarkRegistry::new();
        reg.start_phase("scanner");
        std::thread::sleep(Duration::from_millis(5));
        let metric = reg.end_phase(100, 10000);
        assert!(metric.is_some());
        assert_eq!(reg.phases().len(), 1);
        assert!(reg.phase("scanner").unwrap().duration_us >= 4000);
    }

    #[test]
    fn report_json_roundtrip() {
        let mut reg = BenchmarkRegistry::new();
        reg.set_fixture(FixtureInfo {
            size_label: "micro".to_string(),
            file_count: 10,
            total_lines: 500,
            total_bytes: 20000,
            language_count: 3,
        });
        reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(10), 10, 20000));
        reg.record_phase(PhaseMetric::new("parser", Duration::from_millis(50), 10, 20000));

        let report = reg.build_report();
        let json = report.to_json();
        let parsed: BenchmarkReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.phases.len(), 2);
        assert_eq!(parsed.fixture.file_count, 10);
    }

    #[test]
    fn regression_detection() {
        let mut reg = BenchmarkRegistry::new();
        reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(100), 10, 0));
        reg.record_phase(PhaseMetric::new("parser", Duration::from_millis(200), 10, 0));

        let mut baseline_reg = BenchmarkRegistry::new();
        baseline_reg.record_phase(PhaseMetric::new("scanner", Duration::from_millis(80), 10, 0));
        baseline_reg.record_phase(PhaseMetric::new("parser", Duration::from_millis(190), 10, 0));
        let baseline = baseline_reg.build_report();

        let verdicts = reg.compare_to_baseline(&baseline, 10.0);
        assert_eq!(verdicts.len(), 2);
        // scanner: 100ms vs 80ms = +25% → regressed (>10%)
        assert!(verdicts[0].regressed);
        // parser: 200ms vs 190ms = +5.3% → OK (<10%)
        assert!(!verdicts[1].regressed);
    }
}

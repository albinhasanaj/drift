//! Core types for quality gates.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// The 6 quality gate identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateId {
    PatternCompliance,
    ConstraintVerification,
    SecurityBoundaries,
    TestCoverage,
    ErrorHandling,
    Regression,
}

impl GateId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PatternCompliance => "pattern-compliance",
            Self::ConstraintVerification => "constraint-verification",
            Self::SecurityBoundaries => "security-boundaries",
            Self::TestCoverage => "test-coverage",
            Self::ErrorHandling => "error-handling",
            Self::Regression => "regression",
        }
    }

    pub fn all() -> &'static [GateId] {
        &[
            Self::PatternCompliance,
            Self::ConstraintVerification,
            Self::SecurityBoundaries,
            Self::TestCoverage,
            Self::ErrorHandling,
            Self::Regression,
        ]
    }
}

impl fmt::Display for GateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Gate execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateStatus {
    Passed,
    Failed,
    Warned,
    Skipped,
    Errored,
}

/// Result produced by each gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    pub gate_id: GateId,
    pub status: GateStatus,
    pub passed: bool,
    pub score: f64,
    pub summary: String,
    pub violations: Vec<super::super::rules::Violation>,
    pub warnings: Vec<String>,
    pub execution_time_ms: u64,
    pub details: serde_json::Value,
    pub error: Option<String>,
}

impl GateResult {
    /// Create a passing gate result.
    pub fn pass(gate_id: GateId, score: f64, summary: String) -> Self {
        Self {
            gate_id,
            status: GateStatus::Passed,
            passed: true,
            score,
            summary,
            violations: Vec::new(),
            warnings: Vec::new(),
            execution_time_ms: 0,
            details: serde_json::Value::Null,
            error: None,
        }
    }

    /// Create a failing gate result.
    pub fn fail(
        gate_id: GateId,
        score: f64,
        summary: String,
        violations: Vec<super::super::rules::Violation>,
    ) -> Self {
        Self {
            gate_id,
            status: GateStatus::Failed,
            passed: false,
            score,
            summary,
            violations,
            warnings: Vec::new(),
            execution_time_ms: 0,
            details: serde_json::Value::Null,
            error: None,
        }
    }

    /// Create a warned gate result.
    pub fn warn(gate_id: GateId, score: f64, summary: String, warnings: Vec<String>) -> Self {
        Self {
            gate_id,
            status: GateStatus::Warned,
            passed: true,
            score,
            summary,
            violations: Vec::new(),
            warnings,
            execution_time_ms: 0,
            details: serde_json::Value::Null,
            error: None,
        }
    }

    /// Create a skipped gate result.
    pub fn skipped(gate_id: GateId, reason: String) -> Self {
        Self {
            gate_id,
            status: GateStatus::Skipped,
            passed: true,
            score: 0.0,
            summary: reason,
            violations: Vec::new(),
            warnings: Vec::new(),
            execution_time_ms: 0,
            details: serde_json::Value::Null,
            error: None,
        }
    }

    /// Create an errored gate result.
    pub fn errored(gate_id: GateId, error: String) -> Self {
        Self {
            gate_id,
            status: GateStatus::Errored,
            passed: false,
            score: 0.0,
            summary: format!("Gate errored: {error}"),
            violations: Vec::new(),
            warnings: Vec::new(),
            execution_time_ms: 0,
            details: serde_json::Value::Null,
            error: Some(error),
        }
    }
}

/// Input provided to each gate by the orchestrator.
#[derive(Clone, Default)]
pub struct GateInput {
    pub files: Vec<String>,
    pub all_files: Vec<String>,
    pub patterns: Vec<super::super::rules::PatternInfo>,
    pub constraints: Vec<ConstraintInput>,
    pub security_findings: Vec<SecurityFindingInput>,
    pub test_coverage: Option<TestCoverageInput>,
    pub error_gaps: Vec<ErrorGapInput>,
    pub previous_health_score: Option<f64>,
    pub current_health_score: Option<f64>,
    pub predecessor_results: HashMap<GateId, GateResult>,
    /// Baseline violation keys (format: "file:line:rule_id") for is_new detection.
    pub baseline_violations: HashSet<String>,
    /// Optional feedback stats provider for FP-rate-aware gate evaluation.
    pub feedback_stats: Option<std::sync::Arc<dyn super::super::feedback::stats_provider::FeedbackStatsProvider>>,
}

impl std::fmt::Debug for GateInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateInput")
            .field("files", &self.files)
            .field("all_files", &self.all_files)
            .field("patterns", &self.patterns)
            .field("constraints", &self.constraints)
            .field("security_findings", &self.security_findings)
            .field("test_coverage", &self.test_coverage)
            .field("error_gaps", &self.error_gaps)
            .field("previous_health_score", &self.previous_health_score)
            .field("current_health_score", &self.current_health_score)
            .field("predecessor_results", &self.predecessor_results)
            .field("baseline_violations", &self.baseline_violations)
            .field("feedback_stats", &self.feedback_stats.as_ref().map(|_| "<FeedbackStatsProvider>"))
            .finish()
    }
}

/// Constraint data for the constraint verification gate.
#[derive(Debug, Clone)]
pub struct ConstraintInput {
    pub id: String,
    pub description: String,
    pub passed: bool,
    pub violations: Vec<ConstraintViolationInput>,
}

#[derive(Debug, Clone)]
pub struct ConstraintViolationInput {
    pub file: String,
    pub line: Option<u32>,
    pub message: String,
}

/// Security finding data for the security boundaries gate.
#[derive(Debug, Clone)]
pub struct SecurityFindingInput {
    pub file: String,
    pub line: u32,
    pub description: String,
    pub severity: String,
    pub cwe_ids: Vec<u32>,
    pub owasp_categories: Vec<String>,
}

/// Test coverage data for the test coverage gate.
#[derive(Debug, Clone)]
pub struct TestCoverageInput {
    pub overall_coverage: f64,
    pub threshold: f64,
    pub uncovered_files: Vec<String>,
}

/// Error handling gap data for the error handling gate.
#[derive(Debug, Clone)]
pub struct ErrorGapInput {
    pub file: String,
    pub line: u32,
    pub gap_type: String,
    pub message: String,
}

/// Gate dependency specification.
#[derive(Debug, Clone)]
pub struct GateDependency {
    pub gate_id: GateId,
    pub depends_on: Vec<GateId>,
}

/// Trait for quality gate implementations.
pub trait QualityGate: Send + Sync {
    fn id(&self) -> GateId;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn evaluate(&self, input: &GateInput) -> GateResult;
    fn dependencies(&self) -> Vec<GateId> {
        Vec::new()
    }
}

/// Builder for constructing a populated `GateInput` from upstream analysis results.
///
/// Maps taint flows → SecurityFindingInput, error gaps → ErrorGapInput,
/// coverage mapping → TestCoverageInput, and patterns → PatternInfo.
#[derive(Debug, Default)]
pub struct GateInputBuilder {
    input: GateInput,
}

impl GateInputBuilder {
    pub fn new() -> Self {
        Self {
            input: GateInput::default(),
        }
    }

    /// Set the list of files being analyzed in this run.
    pub fn files(mut self, files: Vec<String>) -> Self {
        self.input.files = files;
        self
    }

    /// Set the full list of files in the project (for new-file detection).
    pub fn all_files(mut self, all_files: Vec<String>) -> Self {
        self.input.all_files = all_files;
        self
    }

    /// Add detected patterns for the PatternCompliance gate.
    pub fn patterns(mut self, patterns: Vec<super::super::rules::PatternInfo>) -> Self {
        self.input.patterns = patterns;
        self
    }

    /// Add architectural constraints for the ConstraintVerification gate.
    pub fn constraints(mut self, constraints: Vec<ConstraintInput>) -> Self {
        self.input.constraints = constraints;
        self
    }

    /// Map taint flows to SecurityFindingInput for the SecurityBoundaries gate.
    ///
    /// Each unsanitized `TaintFlow` becomes a `SecurityFindingInput` with:
    /// - file/line from the sink (where the vulnerability manifests)
    /// - description from the flow path
    /// - severity based on sink type (SQL/OS command = "critical", XSS/redirect = "high", etc.)
    /// - CWE IDs from the sink type
    /// - OWASP categories mapped from CWE
    pub fn security_findings_from_taint_flows(
        mut self,
        flows: &[crate::graph::taint::types::TaintFlow],
    ) -> Self {
        for flow in flows {
            if flow.is_sanitized {
                continue;
            }

            let severity = taint_sink_to_severity(&flow.sink.sink_type);
            let cwe_ids = flow
                .sink
                .sink_type
                .cwe_id()
                .into_iter()
                .collect::<Vec<_>>();
            let owasp_categories = cwe_to_owasp(&cwe_ids);

            let description = format!(
                "Taint flow: {} ({}) → {} ({}) [{}hop path]",
                flow.source.expression,
                flow.source.source_type.name(),
                flow.sink.expression,
                flow.sink.sink_type.name(),
                flow.path.len() + 2,
            );

            self.input.security_findings.push(SecurityFindingInput {
                file: flow.sink.file.clone(),
                line: flow.sink.line,
                description,
                severity: severity.to_string(),
                cwe_ids,
                owasp_categories,
            });
        }
        self
    }

    /// Add security findings directly (for non-taint sources).
    pub fn security_findings(mut self, findings: Vec<SecurityFindingInput>) -> Self {
        self.input.security_findings.extend(findings);
        self
    }

    /// Map error handling gaps to ErrorGapInput for the ErrorHandling gate.
    ///
    /// Each `ErrorGap` from `graph/error_handling/` becomes an `ErrorGapInput` with:
    /// - gap_type from GapType enum name
    /// - message from remediation or a default description
    pub fn error_gaps_from_analysis(
        mut self,
        gaps: &[crate::graph::error_handling::types::ErrorGap],
    ) -> Self {
        for gap in gaps {
            let gap_type = match gap.gap_type {
                crate::graph::error_handling::types::GapType::EmptyCatch => "empty_catch",
                crate::graph::error_handling::types::GapType::SwallowedError => "swallowed",
                crate::graph::error_handling::types::GapType::GenericCatch => "generic_catch",
                crate::graph::error_handling::types::GapType::Unhandled => "unhandled",
                crate::graph::error_handling::types::GapType::UnhandledAsync => "unhandled",
                crate::graph::error_handling::types::GapType::MissingMiddleware => "unhandled",
                crate::graph::error_handling::types::GapType::InconsistentPattern => "generic_catch",
            };

            let message = gap
                .remediation
                .clone()
                .unwrap_or_else(|| {
                    format!(
                        "{} error handling gap in {}:{}",
                        gap.gap_type.name(),
                        gap.file,
                        gap.line
                    )
                });

            self.input.error_gaps.push(ErrorGapInput {
                file: gap.file.clone(),
                line: gap.line,
                gap_type: gap_type.to_string(),
                message,
            });
        }
        self
    }

    /// Add error gaps directly.
    pub fn error_gaps(mut self, gaps: Vec<ErrorGapInput>) -> Self {
        self.input.error_gaps.extend(gaps);
        self
    }

    /// Map test coverage data for the TestCoverage gate.
    ///
    /// Computes overall coverage percentage from source_to_test mapping
    /// and identifies uncovered files.
    pub fn test_coverage_from_mapping(
        mut self,
        total_source_functions: usize,
        covered_source_functions: usize,
        uncovered_files: Vec<String>,
        threshold: f64,
    ) -> Self {
        if total_source_functions == 0 {
            return self;
        }

        let overall_coverage =
            (covered_source_functions as f64 / total_source_functions as f64) * 100.0;

        self.input.test_coverage = Some(TestCoverageInput {
            overall_coverage,
            threshold,
            uncovered_files,
        });
        self
    }

    /// Set test coverage directly.
    pub fn test_coverage(mut self, coverage: TestCoverageInput) -> Self {
        self.input.test_coverage = Some(coverage);
        self
    }

    /// Set previous health score for the Regression gate.
    pub fn previous_health_score(mut self, score: f64) -> Self {
        self.input.previous_health_score = Some(score);
        self
    }

    /// Set current health score for the Regression gate.
    pub fn current_health_score(mut self, score: f64) -> Self {
        self.input.current_health_score = Some(score);
        self
    }

    /// Set baseline violation keys for is_new detection.
    /// Keys should be formatted as "file:line:rule_id".
    pub fn baseline_violations(mut self, baseline: HashSet<String>) -> Self {
        self.input.baseline_violations = baseline;
        self
    }

    /// Build the final `GateInput`.
    pub fn build(self) -> GateInput {
        self.input
    }
}

/// Map a taint sink type to a severity string for SecurityFindingInput.
fn taint_sink_to_severity(
    sink_type: &crate::graph::taint::types::SinkType,
) -> &'static str {
    use crate::graph::taint::types::SinkType;
    match sink_type {
        SinkType::SqlQuery | SinkType::OsCommand | SinkType::CodeExecution => "critical",
        SinkType::Deserialization | SinkType::FileWrite | SinkType::FileRead => "high",
        SinkType::HtmlOutput | SinkType::HttpRedirect | SinkType::HttpRequest => "high",
        SinkType::LdapQuery | SinkType::XpathQuery | SinkType::XmlParsing => "high",
        SinkType::TemplateRender | SinkType::HeaderInjection | SinkType::FileUpload => "medium",
        SinkType::LogOutput | SinkType::RegexConstruction => "medium",
        SinkType::Custom(_) => "medium",
    }
}

/// Map CWE IDs to OWASP Top 10 (2021) categories.
fn cwe_to_owasp(cwe_ids: &[u32]) -> Vec<String> {
    let mut categories = Vec::new();
    for &cwe in cwe_ids {
        let owasp = match cwe {
            89 | 90 | 643 => "A03:2021-Injection",
            78 | 94 => "A03:2021-Injection",
            79 | 1336 => "A03:2021-Injection",
            22 => "A01:2021-Broken Access Control",
            601 => "A01:2021-Broken Access Control",
            918 => "A10:2021-Server-Side Request Forgery",
            502 => "A08:2021-Software and Data Integrity Failures",
            117 | 113 => "A09:2021-Security Logging and Monitoring Failures",
            1333 => "A06:2021-Vulnerable and Outdated Components",
            611 => "A05:2021-Security Misconfiguration",
            434 => "A04:2021-Insecure Design",
            _ => continue,
        };
        if !categories.contains(&owasp.to_string()) {
            categories.push(owasp.to_string());
        }
    }
    categories
}

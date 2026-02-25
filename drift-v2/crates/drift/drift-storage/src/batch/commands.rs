//! BatchCommand enum — all write operations that can be batched.

/// A command sent to the batch writer thread.
#[derive(Debug)]
pub enum BatchCommand {
    /// Insert or update file metadata rows.
    UpsertFileMetadata(Vec<FileMetadataRow>),
    /// Insert parse cache entries.
    InsertParseCache(Vec<ParseCacheRow>),
    /// Insert function rows.
    InsertFunctions(Vec<FunctionRow>),
    /// Delete file metadata for removed files.
    DeleteFileMetadata(Vec<String>),
    /// Flush any pending writes immediately (fire-and-forget).
    Flush,
    /// Flush and signal completion via the provided sender (synchronous).
    FlushSync(std::sync::mpsc::SyncSender<()>),
    /// Shut down the writer thread.
    Shutdown,
    /// Insert call edge rows.
    InsertCallEdges(Vec<CallEdgeRow>),
    /// Insert detection rows.
    InsertDetections(Vec<DetectionRow>),
    /// Insert boundary rows.
    InsertBoundaries(Vec<BoundaryRow>),
    /// Insert pattern confidence rows.
    InsertPatternConfidence(Vec<PatternConfidenceRow>),
    /// Insert outlier rows.
    InsertOutliers(Vec<OutlierDetectionRow>),
    /// Insert convention rows.
    InsertConventions(Vec<ConventionInsertRow>),
    /// Insert scan history rows.
    InsertScanHistory(Vec<ScanHistoryInsertRow>),
    /// Insert data access rows.
    InsertDataAccess(Vec<DataAccessInsertRow>),
    // ─── v004: Graph Intelligence ────────────────────────────────────
    /// Insert or replace reachability cache entries.
    InsertReachabilityCache(Vec<ReachabilityCacheRow>),
    /// Insert taint flow rows.
    InsertTaintFlows(Vec<TaintFlowInsertRow>),
    /// Insert error gap rows.
    InsertErrorGaps(Vec<ErrorGapInsertRow>),
    /// Insert or replace impact score rows.
    InsertImpactScores(Vec<ImpactScoreInsertRow>),
    /// Insert test quality rows.
    InsertTestQuality(Vec<TestQualityInsertRow>),
    // ─── v005: Structural Intelligence ───────────────────────────────
    /// Insert or replace coupling metrics.
    InsertCouplingMetrics(Vec<CouplingMetricInsertRow>),
    /// Insert coupling cycle rows.
    InsertCouplingCycles(Vec<CouplingCycleInsertRow>),
    /// Insert violation rows.
    InsertViolations(Vec<ViolationInsertRow>),
    /// Insert gate result rows.
    InsertGateResults(Vec<GateResultInsertRow>),
    /// Insert degradation alert rows.
    InsertDegradationAlerts(Vec<DegradationAlertInsertRow>),
    // ─── v007: Remaining Structural Entities ─────────────────────────
    /// Insert wrapper rows.
    InsertWrappers(Vec<WrapperInsertRow>),
    /// Insert crypto finding rows.
    InsertCryptoFindings(Vec<CryptoFindingInsertRow>),
    /// Insert DNA gene rows.
    InsertDnaGenes(Vec<DnaGeneInsertRow>),
    /// Insert DNA mutation rows.
    InsertDnaMutations(Vec<DnaMutationInsertRow>),
    /// Insert secret rows.
    InsertSecrets(Vec<SecretInsertRow>),
    /// Insert constant rows (includes magic numbers).
    InsertConstants(Vec<ConstantInsertRow>),
    // ─── v008: Remaining Unwired Tables ──────────────────────────────
    /// Insert environment variable rows.
    InsertEnvVariables(Vec<EnvVariableInsertRow>),
    /// Insert OWASP finding rows.
    InsertOwaspFindings(Vec<OwaspFindingInsertRow>),
    /// Insert decomposition decision rows.
    InsertDecompositionDecisions(Vec<DecompositionDecisionInsertRow>),
    // ─── v009: Contract Extraction Pipeline ──────────────────────────
    /// Insert contract rows (API endpoints per file).
    InsertContracts(Vec<ContractInsertRow>),
    /// Insert contract mismatch rows (BE↔FE mismatches).
    InsertContractMismatches(Vec<ContractMismatchInsertRow>),
}

/// A row for the file_metadata table.
#[derive(Debug, Clone)]
pub struct FileMetadataRow {
    pub path: String,
    pub language: Option<String>,
    pub file_size: i64,
    pub content_hash: Vec<u8>,
    pub mtime_secs: i64,
    pub mtime_nanos: i64,
    pub last_scanned_at: i64,
    pub scan_duration_us: Option<i64>,
}

/// A row for the parse_cache table.
#[derive(Debug, Clone)]
pub struct ParseCacheRow {
    pub content_hash: Vec<u8>,
    pub language: String,
    pub parse_result_json: String,
    pub created_at: i64,
}

/// A row for the functions table.
#[derive(Debug, Clone)]
pub struct FunctionRow {
    pub file: String,
    pub name: String,
    pub qualified_name: Option<String>,
    pub language: String,
    pub line: i64,
    pub end_line: i64,
    pub parameter_count: i64,
    pub return_type: Option<String>,
    pub is_exported: bool,
    pub is_async: bool,
    pub body_hash: Vec<u8>,
    pub signature_hash: Vec<u8>,
}

/// A row for the call_edges table.
#[derive(Debug, Clone)]
pub struct CallEdgeRow {
    pub caller_id: i64,
    pub callee_id: i64,
    pub resolution: String,
    pub confidence: f64,
    pub call_site_line: i64,
}

/// A row for the detections table.
#[derive(Debug, Clone)]
pub struct DetectionRow {
    pub file: String,
    pub line: i64,
    pub column_num: i64,
    pub pattern_id: String,
    pub category: String,
    pub confidence: f64,
    pub detection_method: String,
    pub cwe_ids: Option<String>,
    pub owasp: Option<String>,
    pub matched_text: Option<String>,
}

/// A row for the boundaries table.
#[derive(Debug, Clone)]
pub struct BoundaryRow {
    pub file: String,
    pub framework: String,
    pub model_name: String,
    pub table_name: Option<String>,
    pub field_name: Option<String>,
    pub sensitivity: Option<String>,
    pub confidence: f64,
}

/// A row for the pattern_confidence table.
#[derive(Debug, Clone)]
pub struct PatternConfidenceRow {
    pub pattern_id: String,
    pub alpha: f64,
    pub beta: f64,
    pub posterior_mean: f64,
    pub credible_interval_low: f64,
    pub credible_interval_high: f64,
    pub tier: String,
    pub momentum: String,
}

/// A row for the outliers table.
#[derive(Debug, Clone)]
pub struct OutlierDetectionRow {
    pub pattern_id: String,
    pub file: String,
    pub line: i64,
    pub deviation_score: f64,
    pub significance: String,
    pub method: String,
}

/// A row for the conventions table.
#[derive(Debug, Clone)]
pub struct ConventionInsertRow {
    pub pattern_id: String,
    pub category: String,
    pub scope: String,
    pub dominance_ratio: f64,
    pub promotion_status: String,
    pub discovered_at: i64,
    pub last_seen: i64,
    pub expires_at: Option<i64>,
}

/// A row for the scan_history table (insert at scan start).
#[derive(Debug, Clone)]
pub struct ScanHistoryInsertRow {
    pub started_at: i64,
    pub root_path: String,
}

/// A row for the data_access table.
#[derive(Debug, Clone)]
pub struct DataAccessInsertRow {
    pub function_id: i64,
    pub table_name: String,
    pub operation: String,
    pub framework: Option<String>,
    pub line: i64,
    pub confidence: f64,
}

// ─── v004: Graph Intelligence Row Types ─────────────────────────────

/// A row for the reachability_cache table.
#[derive(Debug, Clone)]
pub struct ReachabilityCacheRow {
    pub source_node: String,
    pub direction: String,
    pub reachable_set: String,
    pub sensitivity: String,
}

/// A row for the taint_flows table.
#[derive(Debug, Clone)]
pub struct TaintFlowInsertRow {
    pub source_file: String,
    pub source_line: i64,
    pub source_type: String,
    pub sink_file: String,
    pub sink_line: i64,
    pub sink_type: String,
    pub cwe_id: Option<i64>,
    pub is_sanitized: bool,
    pub path: String,
    pub confidence: f64,
}

/// A row for the error_gaps table.
#[derive(Debug, Clone)]
pub struct ErrorGapInsertRow {
    pub file: String,
    pub function_id: String,
    pub gap_type: String,
    pub error_type: Option<String>,
    pub propagation_chain: Option<String>,
    pub framework: Option<String>,
    pub cwe_id: Option<i64>,
    pub severity: String,
}

/// A row for the impact_scores table.
#[derive(Debug, Clone)]
pub struct ImpactScoreInsertRow {
    pub function_id: String,
    pub blast_radius: i64,
    pub risk_score: f64,
    pub is_dead_code: bool,
    pub dead_code_reason: Option<String>,
    pub exclusion_category: Option<String>,
}

/// A row for the test_quality table.
#[derive(Debug, Clone)]
pub struct TestQualityInsertRow {
    pub function_id: String,
    pub coverage_breadth: Option<f64>,
    pub coverage_depth: Option<f64>,
    pub assertion_density: Option<f64>,
    pub mock_ratio: Option<f64>,
    pub isolation: Option<f64>,
    pub freshness: Option<f64>,
    pub stability: Option<f64>,
    pub overall_score: f64,
    pub smells: Option<String>,
}

// ─── v005: Structural Intelligence Row Types ────────────────────────

/// A row for the coupling_metrics table.
#[derive(Debug, Clone)]
pub struct CouplingMetricInsertRow {
    pub module: String,
    pub ce: i64,
    pub ca: i64,
    pub instability: f64,
    pub abstractness: f64,
    pub distance: f64,
    pub zone: String,
}

/// A row for the coupling_cycles table.
#[derive(Debug, Clone)]
pub struct CouplingCycleInsertRow {
    pub members: String,
    pub break_suggestions: String,
}

// ─── v006: Enforcement Row Types ────────────────────────────────────

/// A row for the violations table (batch insert).
#[derive(Debug, Clone)]
pub struct ViolationInsertRow {
    pub id: String,
    pub file: String,
    pub line: i64,
    pub column_num: Option<i64>,
    pub end_line: Option<i64>,
    pub end_column: Option<i64>,
    pub severity: String,
    pub pattern_id: String,
    pub rule_id: String,
    pub message: String,
    pub quick_fix_strategy: Option<String>,
    pub quick_fix_description: Option<String>,
    pub cwe_id: Option<i64>,
    pub owasp_category: Option<String>,
    pub suppressed: bool,
    pub is_new: bool,
}

/// A row for the gate_results table (batch insert).
#[derive(Debug, Clone)]
pub struct GateResultInsertRow {
    pub gate_id: String,
    pub status: String,
    pub passed: bool,
    pub score: f64,
    pub summary: String,
    pub violation_count: i64,
    pub warning_count: i64,
    pub execution_time_ms: i64,
    pub details: Option<String>,
    pub error: Option<String>,
}

/// A row for the degradation_alerts table (batch insert).
#[derive(Debug, Clone)]
pub struct DegradationAlertInsertRow {
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub current_value: f64,
    pub previous_value: f64,
    pub delta: f64,
}

// ─── v007: Remaining Structural Entity Row Types ────────────────────

/// A row for the wrappers table (batch insert).
#[derive(Debug, Clone)]
pub struct WrapperInsertRow {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub category: String,
    pub wrapped_primitives: String,
    pub framework: String,
    pub confidence: f64,
    pub is_multi_primitive: bool,
    pub is_exported: bool,
    pub usage_count: u32,
}

/// A row for the crypto_findings table (batch insert).
#[derive(Debug, Clone)]
pub struct CryptoFindingInsertRow {
    pub file: String,
    pub line: u32,
    pub category: String,
    pub description: String,
    pub code: String,
    pub confidence: f64,
    pub cwe_id: u32,
    pub owasp: String,
    pub remediation: String,
    pub language: String,
}

/// A row for the dna_genes table (batch insert).
#[derive(Debug, Clone)]
pub struct DnaGeneInsertRow {
    pub gene_id: String,
    pub name: String,
    pub description: String,
    pub dominant_allele: Option<String>,
    pub alleles: String,
    pub confidence: f64,
    pub consistency: f64,
    pub exemplars: String,
}

/// A row for the dna_mutations table (batch insert).
#[derive(Debug, Clone)]
pub struct DnaMutationInsertRow {
    pub id: String,
    pub file: String,
    pub line: u32,
    pub gene_id: String,
    pub expected: String,
    pub actual: String,
    pub impact: String,
    pub code: String,
    pub suggestion: String,
    pub detected_at: i64,
}

/// A row for the secrets table (batch insert).
#[derive(Debug, Clone)]
pub struct SecretInsertRow {
    pub pattern_name: String,
    pub redacted_value: String,
    pub file: String,
    pub line: u32,
    pub severity: String,
    pub entropy: f64,
    pub confidence: f64,
    pub cwe_ids: String,
}

/// A row for the constants table (batch insert).
#[derive(Debug, Clone)]
pub struct ConstantInsertRow {
    pub name: String,
    pub value: String,
    pub file: String,
    pub line: i64,
    pub is_used: bool,
    pub language: String,
    pub is_named: bool,
}

// ─── v008: Remaining Unwired Table Row Types ────────────────────────

/// A row for the env_variables table (batch insert).
#[derive(Debug, Clone)]
pub struct EnvVariableInsertRow {
    pub name: String,
    pub file: String,
    pub line: i64,
    pub access_method: String,
    pub has_default: bool,
    pub defined_in_env: bool,
    pub framework_prefix: Option<String>,
}

/// A row for the owasp_findings table (batch insert).
#[derive(Debug, Clone)]
pub struct OwaspFindingInsertRow {
    pub id: String,
    pub detector: String,
    pub file: String,
    pub line: i64,
    pub description: String,
    pub severity: f64,
    pub cwes: String,
    pub owasp_categories: String,
    pub confidence: f64,
    pub remediation: Option<String>,
}

/// A row for the decomposition_decisions table (batch insert).
#[derive(Debug, Clone)]
pub struct DecompositionDecisionInsertRow {
    pub dna_profile_hash: String,
    pub adjustment: String,
    pub confidence: f64,
    pub dna_similarity: f64,
    pub narrative: String,
    pub source_dna_hash: String,
    pub applied_weight: f64,
}

// ─── v009: Contract Extraction Pipeline Row Types ────────────────────

/// A row for the contracts table (batch insert).
#[derive(Debug, Clone)]
pub struct ContractInsertRow {
    pub id: String,
    pub paradigm: String,
    pub source_file: String,
    pub framework: String,
    pub confidence: f64,
    pub endpoints: String,
}

/// A row for the contract_mismatches table (batch insert).
#[derive(Debug, Clone)]
pub struct ContractMismatchInsertRow {
    pub backend_endpoint: String,
    pub frontend_call: String,
    pub mismatch_type: String,
    pub severity: String,
    pub message: String,
}

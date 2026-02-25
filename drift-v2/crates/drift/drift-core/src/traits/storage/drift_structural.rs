//! `IDriftStructural` trait — structural intelligence systems.
//!
//! Maps to `drift-storage/src/queries/structural.rs`, `queries/constants.rs`,
//! `queries/env_variables.rs`, `queries/data_access.rs`, and graph intelligence
//! from `queries/graph.rs`.

use crate::errors::StorageError;
use std::sync::Arc;

// ─── Row Types ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CouplingMetricsRow {
    pub module: String,
    pub ce: u32,
    pub ca: u32,
    pub instability: f64,
    pub abstractness: f64,
    pub distance: f64,
    pub zone: String,
}

#[derive(Debug, Clone)]
pub struct CouplingCycleRow {
    pub id: i64,
    pub members: String,
    pub break_suggestions: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct ConstraintRow {
    pub id: String,
    pub description: String,
    pub invariant_type: String,
    pub target: String,
    pub scope: Option<String>,
    pub source: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct ConstraintVerificationRow {
    pub id: i64,
    pub constraint_id: String,
    pub passed: bool,
    pub violations: String,
    pub verified_at: i64,
}

#[derive(Debug, Clone)]
pub struct ContractRow {
    pub id: String,
    pub paradigm: String,
    pub source_file: String,
    pub framework: String,
    pub confidence: f64,
    pub endpoints: String,
}

#[derive(Debug, Clone)]
pub struct ContractMismatchRow {
    pub id: i64,
    pub backend_endpoint: String,
    pub frontend_call: String,
    pub mismatch_type: String,
    pub severity: String,
    pub message: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct SecretRow {
    pub id: Option<i64>,
    pub pattern_name: String,
    pub redacted_value: String,
    pub file: String,
    pub line: u32,
    pub severity: String,
    pub entropy: f64,
    pub confidence: f64,
    pub cwe_ids: String,
}

#[derive(Debug, Clone)]
pub struct WrapperRow {
    pub id: Option<i64>,
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

#[derive(Debug, Clone)]
pub struct DnaGeneRow {
    pub gene_id: String,
    pub name: String,
    pub description: String,
    pub dominant_allele: Option<String>,
    pub alleles: String,
    pub confidence: f64,
    pub consistency: f64,
    pub exemplars: String,
}

#[derive(Debug, Clone)]
pub struct DnaMutationRow {
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
    pub resolved: bool,
    pub resolved_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CryptoFindingRow {
    pub id: Option<i64>,
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

#[derive(Debug, Clone)]
pub struct OwaspFindingRow {
    pub id: String,
    pub detector: String,
    pub file: String,
    pub line: u32,
    pub description: String,
    pub severity: f64,
    pub cwes: String,
    pub owasp_categories: String,
    pub confidence: f64,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DecompositionDecisionRow {
    pub id: Option<i64>,
    pub dna_profile_hash: String,
    pub adjustment: String,
    pub confidence: f64,
    pub dna_similarity: f64,
    pub narrative: String,
    pub source_dna_hash: String,
    pub applied_weight: f64,
}

#[derive(Debug, Clone)]
pub struct ConstantRow {
    pub id: i64,
    pub name: String,
    pub value: String,
    pub file: String,
    pub line: i64,
    pub is_used: bool,
    pub language: String,
    pub is_named: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct EnvVariableRow {
    pub id: Option<i64>,
    pub name: String,
    pub file: String,
    pub line: i64,
    pub access_method: String,
    pub has_default: bool,
    pub defined_in_env: bool,
    pub framework_prefix: Option<String>,
    pub created_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct DataAccessRow {
    pub id: Option<i64>,
    pub function_id: i64,
    pub table_name: String,
    pub operation: String,
    pub framework: Option<String>,
    pub line: i64,
    pub confidence: f64,
}

// ─── Graph intelligence row types ───────────────────────────────────

#[derive(Debug, Clone)]
pub struct ReachabilityCacheRow {
    pub source_node: String,
    pub direction: String,
    pub reachable_set: String,
    pub sensitivity: String,
}

#[derive(Debug, Clone)]
pub struct TaintFlowRow {
    pub id: Option<i64>,
    pub source_file: String,
    pub source_line: u32,
    pub source_type: String,
    pub sink_file: String,
    pub sink_line: u32,
    pub sink_type: String,
    pub cwe_id: Option<u32>,
    pub is_sanitized: bool,
    pub path: String,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct ErrorGapRow {
    pub id: Option<i64>,
    pub file: String,
    pub function_id: String,
    pub gap_type: String,
    pub error_type: Option<String>,
    pub propagation_chain: Option<String>,
    pub framework: Option<String>,
    pub cwe_id: Option<u32>,
    pub severity: String,
}

#[derive(Debug, Clone)]
pub struct ImpactScoreRow {
    pub function_id: String,
    pub blast_radius: u32,
    pub risk_score: f64,
    pub is_dead_code: bool,
    pub dead_code_reason: Option<String>,
    pub exclusion_category: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TestCoverageRow {
    pub test_function_id: String,
    pub source_function_id: String,
    pub coverage_type: String,
}

#[derive(Debug, Clone)]
pub struct TestQualityRow {
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

// ─── Trait ───────────────────────────────────────────────────────────

/// Structural intelligence storage operations.
///
/// Covers: coupling_metrics, coupling_cycles, constraints, constraint_verifications,
/// contracts, contract_mismatches, secrets, wrappers, dna_genes, dna_mutations,
/// crypto_findings, owasp_findings, decomposition_decisions, constants,
/// env_variables, data_access, and all graph intelligence tables.
pub trait IDriftStructural: Send + Sync {
    // ── coupling_metrics ──

    fn upsert_coupling_metrics(&self, row: &CouplingMetricsRow) -> Result<(), StorageError>;
    fn get_coupling_metrics(&self, module: &str) -> Result<Option<CouplingMetricsRow>, StorageError>;
    fn get_all_coupling_metrics(&self) -> Result<Vec<CouplingMetricsRow>, StorageError>;
    fn get_coupling_metrics_by_zone(&self, zone: &str) -> Result<Vec<CouplingMetricsRow>, StorageError>;

    // ── coupling_cycles ──

    fn insert_coupling_cycle(&self, members: &str, break_suggestions: &str) -> Result<(), StorageError>;
    fn query_coupling_cycles(&self) -> Result<Vec<CouplingCycleRow>, StorageError>;

    // ── constraints ──

    fn upsert_constraint(&self, row: &ConstraintRow) -> Result<(), StorageError>;
    fn get_constraint(&self, id: &str) -> Result<Option<ConstraintRow>, StorageError>;
    fn get_enabled_constraints(&self) -> Result<Vec<ConstraintRow>, StorageError>;

    // ── constraint_verifications ──

    fn insert_constraint_verification(&self, constraint_id: &str, passed: bool, violations: &str) -> Result<(), StorageError>;
    fn query_constraint_verifications(&self, constraint_id: &str) -> Result<Vec<ConstraintVerificationRow>, StorageError>;

    // ── contracts ──

    fn upsert_contract(&self, row: &ContractRow) -> Result<(), StorageError>;
    fn get_contract(&self, id: &str) -> Result<Option<ContractRow>, StorageError>;
    fn get_contracts_by_paradigm(&self, paradigm: &str) -> Result<Vec<ContractRow>, StorageError>;

    // ── contract_mismatches ──

    fn insert_contract_mismatch(&self, row: &ContractMismatchRow) -> Result<(), StorageError>;
    fn query_contract_mismatches(&self) -> Result<Vec<ContractMismatchRow>, StorageError>;
    fn query_contract_mismatches_by_type(&self, mismatch_type: &str) -> Result<Vec<ContractMismatchRow>, StorageError>;

    // ── secrets ──

    fn insert_secret(&self, row: &SecretRow) -> Result<i64, StorageError>;
    fn get_secrets_by_file(&self, file: &str) -> Result<Vec<SecretRow>, StorageError>;
    fn get_secrets_by_severity(&self, severity: &str) -> Result<Vec<SecretRow>, StorageError>;

    // ── wrappers ──

    fn insert_wrapper(&self, row: &WrapperRow) -> Result<i64, StorageError>;
    fn get_wrappers_by_file(&self, file: &str) -> Result<Vec<WrapperRow>, StorageError>;
    fn get_wrappers_by_category(&self, category: &str) -> Result<Vec<WrapperRow>, StorageError>;

    // ── dna_genes ──

    fn upsert_dna_gene(&self, row: &DnaGeneRow) -> Result<(), StorageError>;
    fn get_dna_gene(&self, gene_id: &str) -> Result<Option<DnaGeneRow>, StorageError>;
    fn get_all_dna_genes(&self) -> Result<Vec<DnaGeneRow>, StorageError>;

    // ── dna_mutations ──

    fn upsert_dna_mutation(&self, row: &DnaMutationRow) -> Result<(), StorageError>;
    fn get_dna_mutations_by_gene(&self, gene_id: &str) -> Result<Vec<DnaMutationRow>, StorageError>;
    fn get_unresolved_mutations(&self) -> Result<Vec<DnaMutationRow>, StorageError>;

    // ── crypto_findings ──

    fn insert_crypto_finding(&self, row: &CryptoFindingRow) -> Result<i64, StorageError>;
    fn get_crypto_findings_by_file(&self, file: &str) -> Result<Vec<CryptoFindingRow>, StorageError>;
    fn get_crypto_findings_by_category(&self, category: &str) -> Result<Vec<CryptoFindingRow>, StorageError>;

    // ── owasp_findings ──

    fn upsert_owasp_finding(&self, row: &OwaspFindingRow) -> Result<(), StorageError>;
    fn get_owasp_findings_by_file(&self, file: &str) -> Result<Vec<OwaspFindingRow>, StorageError>;
    fn get_owasp_findings_by_detector(&self, detector: &str) -> Result<Vec<OwaspFindingRow>, StorageError>;

    // ── decomposition_decisions ──

    fn insert_decomposition_decision(&self, row: &DecompositionDecisionRow) -> Result<i64, StorageError>;
    fn get_decomposition_decisions(&self, dna_profile_hash: &str) -> Result<Vec<DecompositionDecisionRow>, StorageError>;

    // ── constants ──

    fn insert_constant(&self, row: &ConstantRow) -> Result<(), StorageError>;
    fn insert_constants_batch(&self, rows: &[ConstantRow]) -> Result<(), StorageError>;
    fn query_constants_by_file(&self, file: &str) -> Result<Vec<ConstantRow>, StorageError>;
    fn query_unused_constants(&self) -> Result<Vec<ConstantRow>, StorageError>;
    fn query_magic_numbers(&self) -> Result<Vec<ConstantRow>, StorageError>;
    fn delete_constants_by_file(&self, file: &str) -> Result<usize, StorageError>;
    fn count_constants(&self) -> Result<i64, StorageError>;

    // ── env_variables ──

    fn insert_env_variable(&self, row: &EnvVariableRow) -> Result<(), StorageError>;
    fn insert_env_variables_batch(&self, rows: &[EnvVariableRow]) -> Result<(), StorageError>;
    fn query_env_variables_by_name(&self, name: &str) -> Result<Vec<EnvVariableRow>, StorageError>;
    fn query_env_variables_by_file(&self, file: &str) -> Result<Vec<EnvVariableRow>, StorageError>;
    fn query_missing_env_variables(&self) -> Result<Vec<EnvVariableRow>, StorageError>;
    fn delete_env_variables_by_file(&self, file: &str) -> Result<usize, StorageError>;
    fn count_env_variables(&self) -> Result<i64, StorageError>;

    // ── data_access ──

    fn insert_data_access(&self, row: &DataAccessRow) -> Result<(), StorageError>;
    fn insert_data_access_batch(&self, rows: &[DataAccessRow]) -> Result<(), StorageError>;
    fn query_data_access_by_function(&self, function_id: i64) -> Result<Vec<DataAccessRow>, StorageError>;
    fn query_data_access_by_table(&self, table_name: &str) -> Result<Vec<DataAccessRow>, StorageError>;
    fn delete_data_access_by_function(&self, function_id: i64) -> Result<usize, StorageError>;
    fn count_data_access(&self) -> Result<i64, StorageError>;

    // ── reachability_cache ──

    fn upsert_reachability(&self, row: &ReachabilityCacheRow) -> Result<(), StorageError>;
    fn get_reachability(&self, source_node: &str, direction: &str) -> Result<Option<ReachabilityCacheRow>, StorageError>;
    fn clear_reachability_cache(&self) -> Result<(), StorageError>;

    // ── taint_flows ──

    fn insert_taint_flow(&self, row: &TaintFlowRow) -> Result<i64, StorageError>;
    fn get_taint_flows_by_file(&self, file: &str) -> Result<Vec<TaintFlowRow>, StorageError>;
    fn get_taint_flows_by_cwe(&self, cwe_id: u32) -> Result<Vec<TaintFlowRow>, StorageError>;

    // ── error_gaps ──

    fn insert_error_gap(&self, row: &ErrorGapRow) -> Result<i64, StorageError>;
    fn get_error_gaps_by_file(&self, file: &str) -> Result<Vec<ErrorGapRow>, StorageError>;

    // ── impact_scores ──

    fn upsert_impact_score(&self, row: &ImpactScoreRow) -> Result<(), StorageError>;
    fn get_impact_score(&self, function_id: &str) -> Result<Option<ImpactScoreRow>, StorageError>;

    // ── test_coverage ──

    fn insert_test_coverage(&self, row: &TestCoverageRow) -> Result<(), StorageError>;
    fn get_test_coverage_for_source(&self, source_function_id: &str) -> Result<Vec<TestCoverageRow>, StorageError>;

    // ── test_quality ──

    fn upsert_test_quality(&self, row: &TestQualityRow) -> Result<(), StorageError>;
    fn get_test_quality(&self, function_id: &str) -> Result<Option<TestQualityRow>, StorageError>;
}

// ─── Arc blanket impl ───────────────────────────────────────────────

impl<T: IDriftStructural + ?Sized> IDriftStructural for Arc<T> {
    fn upsert_coupling_metrics(&self, row: &CouplingMetricsRow) -> Result<(), StorageError> { (**self).upsert_coupling_metrics(row) }
    fn get_coupling_metrics(&self, module: &str) -> Result<Option<CouplingMetricsRow>, StorageError> { (**self).get_coupling_metrics(module) }
    fn get_all_coupling_metrics(&self) -> Result<Vec<CouplingMetricsRow>, StorageError> { (**self).get_all_coupling_metrics() }
    fn get_coupling_metrics_by_zone(&self, zone: &str) -> Result<Vec<CouplingMetricsRow>, StorageError> { (**self).get_coupling_metrics_by_zone(zone) }
    fn insert_coupling_cycle(&self, members: &str, break_suggestions: &str) -> Result<(), StorageError> { (**self).insert_coupling_cycle(members, break_suggestions) }
    fn query_coupling_cycles(&self) -> Result<Vec<CouplingCycleRow>, StorageError> { (**self).query_coupling_cycles() }
    fn upsert_constraint(&self, row: &ConstraintRow) -> Result<(), StorageError> { (**self).upsert_constraint(row) }
    fn get_constraint(&self, id: &str) -> Result<Option<ConstraintRow>, StorageError> { (**self).get_constraint(id) }
    fn get_enabled_constraints(&self) -> Result<Vec<ConstraintRow>, StorageError> { (**self).get_enabled_constraints() }
    fn insert_constraint_verification(&self, cid: &str, passed: bool, violations: &str) -> Result<(), StorageError> { (**self).insert_constraint_verification(cid, passed, violations) }
    fn query_constraint_verifications(&self, cid: &str) -> Result<Vec<ConstraintVerificationRow>, StorageError> { (**self).query_constraint_verifications(cid) }
    fn upsert_contract(&self, row: &ContractRow) -> Result<(), StorageError> { (**self).upsert_contract(row) }
    fn get_contract(&self, id: &str) -> Result<Option<ContractRow>, StorageError> { (**self).get_contract(id) }
    fn get_contracts_by_paradigm(&self, p: &str) -> Result<Vec<ContractRow>, StorageError> { (**self).get_contracts_by_paradigm(p) }
    fn insert_contract_mismatch(&self, row: &ContractMismatchRow) -> Result<(), StorageError> { (**self).insert_contract_mismatch(row) }
    fn query_contract_mismatches(&self) -> Result<Vec<ContractMismatchRow>, StorageError> { (**self).query_contract_mismatches() }
    fn query_contract_mismatches_by_type(&self, mt: &str) -> Result<Vec<ContractMismatchRow>, StorageError> { (**self).query_contract_mismatches_by_type(mt) }
    fn insert_secret(&self, row: &SecretRow) -> Result<i64, StorageError> { (**self).insert_secret(row) }
    fn get_secrets_by_file(&self, file: &str) -> Result<Vec<SecretRow>, StorageError> { (**self).get_secrets_by_file(file) }
    fn get_secrets_by_severity(&self, sev: &str) -> Result<Vec<SecretRow>, StorageError> { (**self).get_secrets_by_severity(sev) }
    fn insert_wrapper(&self, row: &WrapperRow) -> Result<i64, StorageError> { (**self).insert_wrapper(row) }
    fn get_wrappers_by_file(&self, file: &str) -> Result<Vec<WrapperRow>, StorageError> { (**self).get_wrappers_by_file(file) }
    fn get_wrappers_by_category(&self, cat: &str) -> Result<Vec<WrapperRow>, StorageError> { (**self).get_wrappers_by_category(cat) }
    fn upsert_dna_gene(&self, row: &DnaGeneRow) -> Result<(), StorageError> { (**self).upsert_dna_gene(row) }
    fn get_dna_gene(&self, gene_id: &str) -> Result<Option<DnaGeneRow>, StorageError> { (**self).get_dna_gene(gene_id) }
    fn get_all_dna_genes(&self) -> Result<Vec<DnaGeneRow>, StorageError> { (**self).get_all_dna_genes() }
    fn upsert_dna_mutation(&self, row: &DnaMutationRow) -> Result<(), StorageError> { (**self).upsert_dna_mutation(row) }
    fn get_dna_mutations_by_gene(&self, gid: &str) -> Result<Vec<DnaMutationRow>, StorageError> { (**self).get_dna_mutations_by_gene(gid) }
    fn get_unresolved_mutations(&self) -> Result<Vec<DnaMutationRow>, StorageError> { (**self).get_unresolved_mutations() }
    fn insert_crypto_finding(&self, row: &CryptoFindingRow) -> Result<i64, StorageError> { (**self).insert_crypto_finding(row) }
    fn get_crypto_findings_by_file(&self, file: &str) -> Result<Vec<CryptoFindingRow>, StorageError> { (**self).get_crypto_findings_by_file(file) }
    fn get_crypto_findings_by_category(&self, cat: &str) -> Result<Vec<CryptoFindingRow>, StorageError> { (**self).get_crypto_findings_by_category(cat) }
    fn upsert_owasp_finding(&self, row: &OwaspFindingRow) -> Result<(), StorageError> { (**self).upsert_owasp_finding(row) }
    fn get_owasp_findings_by_file(&self, file: &str) -> Result<Vec<OwaspFindingRow>, StorageError> { (**self).get_owasp_findings_by_file(file) }
    fn get_owasp_findings_by_detector(&self, det: &str) -> Result<Vec<OwaspFindingRow>, StorageError> { (**self).get_owasp_findings_by_detector(det) }
    fn insert_decomposition_decision(&self, row: &DecompositionDecisionRow) -> Result<i64, StorageError> { (**self).insert_decomposition_decision(row) }
    fn get_decomposition_decisions(&self, hash: &str) -> Result<Vec<DecompositionDecisionRow>, StorageError> { (**self).get_decomposition_decisions(hash) }
    fn insert_constant(&self, row: &ConstantRow) -> Result<(), StorageError> { (**self).insert_constant(row) }
    fn insert_constants_batch(&self, rows: &[ConstantRow]) -> Result<(), StorageError> { (**self).insert_constants_batch(rows) }
    fn query_constants_by_file(&self, file: &str) -> Result<Vec<ConstantRow>, StorageError> { (**self).query_constants_by_file(file) }
    fn query_unused_constants(&self) -> Result<Vec<ConstantRow>, StorageError> { (**self).query_unused_constants() }
    fn query_magic_numbers(&self) -> Result<Vec<ConstantRow>, StorageError> { (**self).query_magic_numbers() }
    fn delete_constants_by_file(&self, file: &str) -> Result<usize, StorageError> { (**self).delete_constants_by_file(file) }
    fn count_constants(&self) -> Result<i64, StorageError> { (**self).count_constants() }
    fn insert_env_variable(&self, row: &EnvVariableRow) -> Result<(), StorageError> { (**self).insert_env_variable(row) }
    fn insert_env_variables_batch(&self, rows: &[EnvVariableRow]) -> Result<(), StorageError> { (**self).insert_env_variables_batch(rows) }
    fn query_env_variables_by_name(&self, name: &str) -> Result<Vec<EnvVariableRow>, StorageError> { (**self).query_env_variables_by_name(name) }
    fn query_env_variables_by_file(&self, file: &str) -> Result<Vec<EnvVariableRow>, StorageError> { (**self).query_env_variables_by_file(file) }
    fn query_missing_env_variables(&self) -> Result<Vec<EnvVariableRow>, StorageError> { (**self).query_missing_env_variables() }
    fn delete_env_variables_by_file(&self, file: &str) -> Result<usize, StorageError> { (**self).delete_env_variables_by_file(file) }
    fn count_env_variables(&self) -> Result<i64, StorageError> { (**self).count_env_variables() }
    fn insert_data_access(&self, row: &DataAccessRow) -> Result<(), StorageError> { (**self).insert_data_access(row) }
    fn insert_data_access_batch(&self, rows: &[DataAccessRow]) -> Result<(), StorageError> { (**self).insert_data_access_batch(rows) }
    fn query_data_access_by_function(&self, fid: i64) -> Result<Vec<DataAccessRow>, StorageError> { (**self).query_data_access_by_function(fid) }
    fn query_data_access_by_table(&self, tbl: &str) -> Result<Vec<DataAccessRow>, StorageError> { (**self).query_data_access_by_table(tbl) }
    fn delete_data_access_by_function(&self, fid: i64) -> Result<usize, StorageError> { (**self).delete_data_access_by_function(fid) }
    fn count_data_access(&self) -> Result<i64, StorageError> { (**self).count_data_access() }
    fn upsert_reachability(&self, row: &ReachabilityCacheRow) -> Result<(), StorageError> { (**self).upsert_reachability(row) }
    fn get_reachability(&self, sn: &str, dir: &str) -> Result<Option<ReachabilityCacheRow>, StorageError> { (**self).get_reachability(sn, dir) }
    fn clear_reachability_cache(&self) -> Result<(), StorageError> { (**self).clear_reachability_cache() }
    fn insert_taint_flow(&self, row: &TaintFlowRow) -> Result<i64, StorageError> { (**self).insert_taint_flow(row) }
    fn get_taint_flows_by_file(&self, file: &str) -> Result<Vec<TaintFlowRow>, StorageError> { (**self).get_taint_flows_by_file(file) }
    fn get_taint_flows_by_cwe(&self, cwe: u32) -> Result<Vec<TaintFlowRow>, StorageError> { (**self).get_taint_flows_by_cwe(cwe) }
    fn insert_error_gap(&self, row: &ErrorGapRow) -> Result<i64, StorageError> { (**self).insert_error_gap(row) }
    fn get_error_gaps_by_file(&self, file: &str) -> Result<Vec<ErrorGapRow>, StorageError> { (**self).get_error_gaps_by_file(file) }
    fn upsert_impact_score(&self, row: &ImpactScoreRow) -> Result<(), StorageError> { (**self).upsert_impact_score(row) }
    fn get_impact_score(&self, fid: &str) -> Result<Option<ImpactScoreRow>, StorageError> { (**self).get_impact_score(fid) }
    fn insert_test_coverage(&self, row: &TestCoverageRow) -> Result<(), StorageError> { (**self).insert_test_coverage(row) }
    fn get_test_coverage_for_source(&self, sfid: &str) -> Result<Vec<TestCoverageRow>, StorageError> { (**self).get_test_coverage_for_source(sfid) }
    fn upsert_test_quality(&self, row: &TestQualityRow) -> Result<(), StorageError> { (**self).upsert_test_quality(row) }
    fn get_test_quality(&self, fid: &str) -> Result<Option<TestQualityRow>, StorageError> { (**self).get_test_quality(fid) }
}

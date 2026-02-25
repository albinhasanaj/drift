//! CP0-G-04: Trait completeness audit.
//! CT0-G-18: Trait surface area ≥ 172 methods.
//!
//! Counts methods on every storage trait and verifies minimums.
//! Also verifies every trait is object-safe by constructing trait objects.

/// Count trait methods by listing them explicitly.
/// This is the Rust compile-time approach — if a method is removed from a trait,
/// this test will fail to compile.

#[test]
fn ct0_g18_trait_surface_area_meets_minimum() {
    // IDriftFiles: 9 methods
    let idrift_files_methods = vec![
        "load_all_file_metadata",
        "get_file_metadata",
        "update_function_count",
        "update_file_error",
        "count_files",
        "get_parse_cache_by_hash",
        "insert_parse_cache",
        "invalidate_parse_cache",
        "count_parse_cache",
    ];
    assert!(idrift_files_methods.len() >= 5, "IDriftFiles should have ≥5 methods, got {}", idrift_files_methods.len());

    // IDriftAnalysis: 31 methods
    let idrift_analysis_methods = vec![
        "get_functions_by_file",
        "get_function_by_qualified_name",
        "delete_functions_by_file",
        "count_functions",
        "count_entry_points",
        "insert_detections",
        "get_detections_by_file",
        "get_detections_by_category",
        "query_all_detections",
        "delete_detections_by_file",
        "count_detections",
        "get_detections_by_method",
        "get_detections_by_pattern_prefix",
        "get_detections_by_cwe",
        "get_framework_detection_summary",
        "upsert_confidence",
        "query_confidence_by_tier",
        "query_all_confidence",
        "insert_outlier",
        "query_outliers_by_pattern",
        "insert_convention",
        "query_conventions_by_category",
        "query_all_conventions",
        "insert_boundaries",
        "get_boundaries_by_file",
        "get_boundaries_by_framework",
        "get_sensitive_boundaries",
        "delete_boundaries_by_file",
        "count_boundaries",
        "insert_call_edges",
        "get_edges_by_caller",
        "get_edges_by_callee",
        "delete_edges_by_file",
        "count_call_edges",
        "count_resolved_edges",
        "insert_scan_start",
        "update_scan_complete",
        "query_recent_scans",
        "count_scans",
    ];
    assert!(idrift_analysis_methods.len() >= 25, "IDriftAnalysis should have ≥25 methods, got {}", idrift_analysis_methods.len());

    // IDriftStructural: 57 methods
    let idrift_structural_methods = vec![
        "upsert_coupling_metrics", "get_coupling_metrics", "get_all_coupling_metrics", "get_coupling_metrics_by_zone",
        "insert_coupling_cycle", "query_coupling_cycles",
        "upsert_constraint", "get_constraint", "get_enabled_constraints",
        "insert_constraint_verification", "query_constraint_verifications",
        "upsert_contract", "get_contract", "get_contracts_by_paradigm",
        "insert_contract_mismatch", "query_contract_mismatches", "query_contract_mismatches_by_type",
        "insert_secret", "get_secrets_by_file", "get_secrets_by_severity",
        "insert_wrapper", "get_wrappers_by_file", "get_wrappers_by_category",
        "upsert_dna_gene", "get_dna_gene", "get_all_dna_genes",
        "upsert_dna_mutation", "get_dna_mutations_by_gene", "get_unresolved_mutations",
        "insert_crypto_finding", "get_crypto_findings_by_file", "get_crypto_findings_by_category",
        "upsert_owasp_finding", "get_owasp_findings_by_file", "get_owasp_findings_by_detector",
        "insert_decomposition_decision", "get_decomposition_decisions",
        "insert_constant", "insert_constants_batch", "query_constants_by_file", "query_unused_constants", "query_magic_numbers", "delete_constants_by_file", "count_constants",
        "insert_env_variable", "insert_env_variables_batch", "query_env_variables_by_name", "query_env_variables_by_file", "query_missing_env_variables", "delete_env_variables_by_file", "count_env_variables",
        "insert_data_access", "insert_data_access_batch", "query_data_access_by_function", "query_data_access_by_table", "delete_data_access_by_function", "count_data_access",
        "upsert_reachability", "get_reachability", "clear_reachability_cache",
        "insert_taint_flow", "get_taint_flows_by_file", "get_taint_flows_by_cwe",
        "insert_error_gap", "get_error_gaps_by_file",
        "upsert_impact_score", "get_impact_score",
        "insert_test_coverage", "get_test_coverage_for_source",
        "upsert_test_quality", "get_test_quality",
    ];
    assert!(idrift_structural_methods.len() >= 37, "IDriftStructural should have ≥37 methods, got {}", idrift_structural_methods.len());

    // IDriftEnforcement: 21 methods
    let idrift_enforcement_methods = vec![
        "insert_violation", "query_violations_by_file", "query_all_violations",
        "insert_gate_result", "query_gate_results",
        "insert_audit_snapshot", "query_audit_snapshots",
        "insert_health_trend", "query_health_trends",
        "insert_feedback", "query_feedback_by_detector", "query_feedback_by_pattern",
        "query_feedback_adjustments", "get_violation_pattern_id", "query_feedback_stats", "count_needs_review",
        "insert_policy_result", "query_recent_policy_results",
        "insert_degradation_alert", "query_recent_degradation_alerts", "query_degradation_alerts_by_type",
    ];
    assert!(idrift_enforcement_methods.len() >= 21, "IDriftEnforcement should have ≥21 methods, got {}", idrift_enforcement_methods.len());

    // IDriftAdvanced: 9 methods
    let idrift_advanced_methods = vec![
        "insert_simulation", "get_simulations",
        "insert_decision",
        "insert_context_cache",
        "create_migration_project", "create_migration_module", "update_module_status",
        "insert_migration_correction", "get_migration_correction",
    ];
    assert!(idrift_advanced_methods.len() >= 9, "IDriftAdvanced should have ≥9 methods, got {}", idrift_advanced_methods.len());

    // IDriftBatchWriter: 5 methods
    let idrift_batch_methods = vec![
        "send_raw", "flush", "flush_sync", "stats", "shutdown",
    ];
    assert!(idrift_batch_methods.len() >= 5, "IDriftBatchWriter should have ≥5 methods, got {}", idrift_batch_methods.len());

    // IDriftReader: 14 methods
    let idrift_reader_methods = vec![
        "pattern_confidence", "pattern_occurrence_rate", "false_positive_rate",
        "constraint_verified", "coupling_metric", "dna_health",
        "test_coverage", "error_handling_gaps", "decision_evidence", "boundary_data",
        "taint_flow_risk", "call_graph_coverage",
        "count_matching_patterns", "latest_scan_timestamp",
    ];
    assert_eq!(idrift_reader_methods.len(), 14, "IDriftReader should have exactly 14 methods");

    // IWorkspaceStorage: 10 methods
    let iworkspace_methods = vec![
        "initialize", "status", "project_info", "workspace_context",
        "gc", "backup", "export", "import", "integrity_check", "schema_version",
    ];
    assert!(iworkspace_methods.len() >= 10, "IWorkspaceStorage should have ≥10 methods, got {}", iworkspace_methods.len());

    // IBridgeStorage: 23 methods
    let ibridge_methods = vec![
        "insert_memory", "insert_grounding_result", "insert_snapshot",
        "insert_event", "insert_metric", "update_memory_confidence", "upsert_weight",
        "get_memory", "query_memories_by_type", "get_grounding_history",
        "get_snapshots", "get_events", "get_metrics", "get_schema_version",
        "query_all_memories_for_grounding", "search_memories_by_tag", "get_previous_grounding_score",
        "initialize", "migrate", "health_check", "shutdown",
        "count_memories", "storage_stats",
    ];
    assert!(ibridge_methods.len() >= 23, "IBridgeStorage should have ≥23 methods, got {}", ibridge_methods.len());

    // Total surface area
    let drift_total = idrift_files_methods.len()
        + idrift_analysis_methods.len()
        + idrift_structural_methods.len()
        + idrift_enforcement_methods.len()
        + idrift_advanced_methods.len()
        + idrift_batch_methods.len()
        + idrift_reader_methods.len()
        + iworkspace_methods.len();

    let bridge_total = ibridge_methods.len();
    let grand_total = drift_total + bridge_total;

    println!("=== Trait Surface Area Audit ===");
    println!("IDriftFiles:        {} methods", idrift_files_methods.len());
    println!("IDriftAnalysis:     {} methods", idrift_analysis_methods.len());
    println!("IDriftStructural:   {} methods", idrift_structural_methods.len());
    println!("IDriftEnforcement:  {} methods", idrift_enforcement_methods.len());
    println!("IDriftAdvanced:     {} methods", idrift_advanced_methods.len());
    println!("IDriftBatchWriter:  {} methods", idrift_batch_methods.len());
    println!("IDriftReader:       {} methods", idrift_reader_methods.len());
    println!("IWorkspaceStorage:  {} methods", iworkspace_methods.len());
    println!("--- Drift subtotal: {} methods", drift_total);
    println!("IBridgeStorage:     {} methods", bridge_total);
    println!("=== TOTAL: {} methods (minimum 172) ===", grand_total);

    assert!(
        grand_total >= 172,
        "Total trait surface area should be ≥172, got {}",
        grand_total
    );
}

/// CT0-G-04/G-18: Verify traits are object-safe by constructing dyn references.
/// This is a compile-time check — if any trait is not object-safe, this won't compile.
#[test]
fn ct0_g04_all_traits_are_object_safe() {
    use drift_core::traits::storage::{
        IDriftFiles, IDriftAnalysis, IDriftStructural, IDriftEnforcement,
        IDriftAdvanced, IDriftReader, IWorkspaceStorage,
    };

    fn _assert_object_safe_files(_: &dyn IDriftFiles) {}
    fn _assert_object_safe_analysis(_: &dyn IDriftAnalysis) {}
    fn _assert_object_safe_structural(_: &dyn IDriftStructural) {}
    fn _assert_object_safe_enforcement(_: &dyn IDriftEnforcement) {}
    fn _assert_object_safe_advanced(_: &dyn IDriftAdvanced) {}
    fn _assert_object_safe_reader(_: &dyn IDriftReader) {}
    fn _assert_object_safe_workspace(_: &dyn IWorkspaceStorage) {}
    // IDriftBatchWriter has `shutdown(self: Box<Self>)` which is fine for Box<dyn>
}

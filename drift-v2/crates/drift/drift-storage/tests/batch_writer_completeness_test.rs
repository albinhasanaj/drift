//! Tests for the 12 BatchCommand variants that had no dedicated test coverage.
//! Each test sends commands through the BatchWriter, shuts down, then verifies
//! the data was persisted via query functions.

use drift_storage::batch::commands::*;
use drift_storage::batch::writer::BatchWriter;
use drift_storage::migrations::run_migrations;
use drift_storage::queries::{enforcement, graph, scan_history, structural};
use rusqlite::Connection;

fn make_batch_writer() -> (BatchWriter, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("batch-test.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    run_migrations(&conn).unwrap();
    (BatchWriter::new(conn), dir)
}

fn read_conn(dir: &tempfile::TempDir) -> Connection {
    let db_path = dir.path().join("batch-test.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertScanHistory
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_scan_history() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertScanHistory(vec![
            ScanHistoryInsertRow { started_at: 1700000000, root_path: "/project".to_string() },
            ScanHistoryInsertRow { started_at: 1700000100, root_path: "/project".to_string() },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.scan_history_rows, 2);

    let conn = read_conn(&dir);
    let count = scan_history::count(&conn).unwrap();
    assert_eq!(count, 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertDataAccess
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_data_access() {
    let (writer, dir) = make_batch_writer();

    // Need a function row first for the function_id reference
    writer
        .send(BatchCommand::InsertFunctions(vec![FunctionRow {
            file: "src/db.ts".to_string(),
            name: "query".to_string(),
            qualified_name: Some("db.ts::query".to_string()),
            language: "typescript".to_string(),
            line: 1,
            end_line: 10,
            parameter_count: 1,
            return_type: None,
            is_exported: true,
            is_async: true,
            body_hash: vec![1, 2, 3],
            signature_hash: vec![4, 5, 6],
        }]))
        .unwrap();
    writer.flush().unwrap();

    // Get the function ID
    let conn = read_conn(&dir);
    let fid: i64 = conn
        .query_row("SELECT id FROM functions WHERE name = 'query'", [], |r| r.get(0))
        .unwrap();
    drop(conn);

    writer
        .send(BatchCommand::InsertDataAccess(vec![
            DataAccessInsertRow {
                function_id: fid,
                table_name: "users".to_string(),
                operation: "SELECT".to_string(),
                framework: Some("prisma".to_string()),
                line: 5,
                confidence: 0.9,
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.data_access_rows, 1);

    let conn = read_conn(&dir);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM data_access", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertReachabilityCache
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_reachability_cache() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertReachabilityCache(vec![
            ReachabilityCacheRow {
                source_node: "auth::login".to_string(),
                direction: "forward".to_string(),
                reachable_set: r#"["db::query"]"#.to_string(),
                sensitivity: "critical".to_string(),
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.reachability_cache_rows, 1);

    let conn = read_conn(&dir);
    let result = graph::get_reachability(&conn, "auth::login", "forward").unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().sensitivity, "critical");
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertTaintFlows
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_taint_flows() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertTaintFlows(vec![TaintFlowInsertRow {
            source_file: "handler.ts".to_string(),
            source_line: 5,
            source_type: "UserInput".to_string(),
            sink_file: "db.ts".to_string(),
            sink_line: 20,
            sink_type: "SqlQuery".to_string(),
            cwe_id: Some(89),
            is_sanitized: false,
            path: "[]".to_string(),
            confidence: 0.85,
        }]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.taint_flow_rows, 1);

    let conn = read_conn(&dir);
    let flows = graph::get_taint_flows_by_file(&conn, "handler.ts").unwrap();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].cwe_id, Some(89));
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertErrorGaps
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_error_gaps() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertErrorGaps(vec![ErrorGapInsertRow {
            file: "handler.ts".to_string(),
            function_id: "handler.ts::process".to_string(),
            gap_type: "empty_catch".to_string(),
            error_type: Some("Error".to_string()),
            propagation_chain: None,
            framework: None,
            cwe_id: Some(390),
            severity: "high".to_string(),
        }]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.error_gap_rows, 1);

    let conn = read_conn(&dir);
    let gaps = graph::get_error_gaps_by_file(&conn, "handler.ts").unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].gap_type, "empty_catch");
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertImpactScores
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_impact_scores() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertImpactScores(vec![ImpactScoreInsertRow {
            function_id: "auth::login".to_string(),
            blast_radius: 42,
            risk_score: 0.75,
            is_dead_code: false,
            dead_code_reason: None,
            exclusion_category: None,
        }]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.impact_score_rows, 1);

    let conn = read_conn(&dir);
    let result = graph::get_impact_score(&conn, "auth::login").unwrap().unwrap();
    assert_eq!(result.blast_radius, 42);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertTestQuality
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_test_quality() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertTestQuality(vec![TestQualityInsertRow {
            function_id: "test::login".to_string(),
            coverage_breadth: Some(0.8),
            coverage_depth: Some(0.6),
            assertion_density: Some(0.9),
            mock_ratio: Some(0.3),
            isolation: Some(1.0),
            freshness: Some(0.95),
            stability: Some(1.0),
            overall_score: 0.82,
            smells: Some(r#"["eager_test"]"#.to_string()),
        }]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.test_quality_rows, 1);

    let conn = read_conn(&dir);
    let result = graph::get_test_quality(&conn, "test::login").unwrap().unwrap();
    assert!((result.overall_score - 0.82).abs() < 0.001);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertCouplingMetrics
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_coupling_metrics() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertCouplingMetrics(vec![
            CouplingMetricInsertRow {
                module: "src/auth".to_string(),
                ce: 5,
                ca: 3,
                instability: 0.625,
                abstractness: 0.2,
                distance: 0.175,
                zone: "main_sequence".to_string(),
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.coupling_metric_rows, 1);

    let conn = read_conn(&dir);
    let result = structural::get_coupling_metrics(&conn, "src/auth").unwrap().unwrap();
    assert_eq!(result.ce, 5);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertCouplingCycles
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_coupling_cycles() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertCouplingCycles(vec![
            CouplingCycleInsertRow {
                members: r#"["a","b","c"]"#.to_string(),
                break_suggestions: r#"["remove a->b"]"#.to_string(),
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.coupling_cycle_rows, 1);

    let conn = read_conn(&dir);
    let cycles = structural::query_coupling_cycles(&conn).unwrap();
    assert_eq!(cycles.len(), 1);
    assert!(cycles[0].members.contains("a"));
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertViolations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_violations() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertViolations(vec![ViolationInsertRow {
            id: "v-001".to_string(),
            file: "src/auth.ts".to_string(),
            line: 42,
            column_num: Some(5),
            end_line: Some(42),
            end_column: Some(20),
            severity: "error".to_string(),
            pattern_id: "no-eval".to_string(),
            rule_id: "security/no-eval".to_string(),
            message: "eval() is dangerous".to_string(),
            quick_fix_strategy: Some("replace".to_string()),
            quick_fix_description: Some("Use JSON.parse instead".to_string()),
            cwe_id: Some(95),
            owasp_category: Some("A03:2021".to_string()),
            suppressed: false,
            is_new: true,
        }]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.violation_rows, 1);

    let conn = read_conn(&dir);
    let violations = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].id, "v-001");
    assert_eq!(violations[0].cwe_id, Some(95));
    assert!(violations[0].is_new);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertGateResults
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_gate_results() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertGateResults(vec![GateResultInsertRow {
            gate_id: "confidence".to_string(),
            status: "passed".to_string(),
            passed: true,
            score: 0.95,
            summary: "All patterns above threshold".to_string(),
            violation_count: 0,
            warning_count: 2,
            execution_time_ms: 150,
            details: Some(r#"{"threshold":0.7}"#.to_string()),
            error: None,
        }]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.gate_result_rows, 1);

    let conn = read_conn(&dir);
    let results = enforcement::query_gate_results(&conn).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].gate_id, "confidence");
    assert!(results[0].passed);
    assert_eq!(results[0].warning_count, 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertDegradationAlerts
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_degradation_alerts() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertDegradationAlerts(vec![
            DegradationAlertInsertRow {
                alert_type: "confidence_drop".to_string(),
                severity: "warning".to_string(),
                message: "Pattern confidence dropped 15%".to_string(),
                current_value: 0.65,
                previous_value: 0.80,
                delta: -0.15,
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.degradation_alert_rows, 1);

    let conn = read_conn(&dir);
    let alerts = enforcement::query_recent_degradation_alerts(&conn, 10).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].alert_type, "confidence_drop");
    assert!((alerts[0].delta - (-0.15)).abs() < 0.001);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertWrappers
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_wrappers() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertWrappers(vec![WrapperInsertRow {
            name: "useAuth".to_string(),
            file: "hooks/auth.ts".to_string(),
            line: 10,
            category: "Hook".to_string(),
            wrapped_primitives: r#"["useState","useEffect"]"#.to_string(),
            framework: "react".to_string(),
            confidence: 0.92,
            is_multi_primitive: true,
            is_exported: true,
            usage_count: 15,
        }]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.wrapper_rows, 1);

    let conn = read_conn(&dir);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM wrappers", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertCryptoFindings
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_crypto_findings() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertCryptoFindings(vec![
            CryptoFindingInsertRow {
                file: "crypto.ts".to_string(),
                line: 42,
                category: "WeakHash".to_string(),
                description: "MD5 usage detected".to_string(),
                code: "crypto.createHash('md5')".to_string(),
                confidence: 0.95,
                cwe_id: 328,
                owasp: "A02".to_string(),
                remediation: "Use SHA-256 instead".to_string(),
                language: "typescript".to_string(),
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.crypto_finding_rows, 1);

    let conn = read_conn(&dir);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM crypto_findings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertDnaGenes
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_dna_genes() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertDnaGenes(vec![DnaGeneInsertRow {
            gene_id: "naming_convention".to_string(),
            name: "NamingConvention".to_string(),
            description: "Variable naming patterns".to_string(),
            dominant_allele: Some("camelCase".to_string()),
            alleles: r#"[{"name":"camelCase","count":120}]"#.to_string(),
            confidence: 0.88,
            consistency: 0.95,
            exemplars: "[]".to_string(),
        }]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.dna_gene_rows, 1);

    let conn = read_conn(&dir);
    let genes = structural::get_all_dna_genes(&conn).unwrap();
    assert_eq!(genes.len(), 1);
    assert_eq!(genes[0].name, "NamingConvention");
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertDnaMutations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_dna_mutations() {
    let (writer, dir) = make_batch_writer();
    // Need a gene first for FK
    writer
        .send(BatchCommand::InsertDnaGenes(vec![DnaGeneInsertRow {
            gene_id: "naming".to_string(),
            name: "Naming".to_string(),
            description: "desc".to_string(),
            dominant_allele: Some("camelCase".to_string()),
            alleles: "[]".to_string(),
            confidence: 0.9,
            consistency: 0.9,
            exemplars: "[]".to_string(),
        }]))
        .unwrap();
    writer
        .send(BatchCommand::InsertDnaMutations(vec![
            DnaMutationInsertRow {
                id: "mut-001".to_string(),
                file: "utils.ts".to_string(),
                line: 55,
                gene_id: "naming".to_string(),
                expected: "camelCase".to_string(),
                actual: "snake_case".to_string(),
                impact: "Medium".to_string(),
                code: "let my_var = 1".to_string(),
                suggestion: "Use camelCase".to_string(),
                detected_at: 1700000000,
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.dna_gene_rows, 1);
    assert_eq!(stats.dna_mutation_rows, 1);

    let conn = read_conn(&dir);
    let mutations = structural::get_unresolved_mutations(&conn).unwrap();
    assert_eq!(mutations.len(), 1);
    assert_eq!(mutations[0].expected, "camelCase");
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertSecrets
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_secrets() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertSecrets(vec![SecretInsertRow {
            pattern_name: "aws_key".to_string(),
            redacted_value: "AKIA****XXXX".to_string(),
            file: "config.ts".to_string(),
            line: 3,
            severity: "Critical".to_string(),
            entropy: 4.5,
            confidence: 0.99,
            cwe_ids: "[798]".to_string(),
        }]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.secret_rows, 1);

    let conn = read_conn(&dir);
    let secrets = structural::get_secrets_by_severity(&conn, "Critical").unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].pattern_name, "aws_key");
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertConstants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_constants() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertConstants(vec![ConstantInsertRow {
            name: "MAX_RETRIES".to_string(),
            value: "3".to_string(),
            file: "config.ts".to_string(),
            line: 1,
            is_used: true,
            language: "typescript".to_string(),
            is_named: true,
        }]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.constant_rows, 1);

    let conn = read_conn(&dir);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM constants", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertEnvVariables
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_env_variables() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertEnvVariables(vec![
            EnvVariableInsertRow {
                name: "DATABASE_URL".to_string(),
                file: "config.ts".to_string(),
                line: 5,
                access_method: "process.env".to_string(),
                has_default: false,
                defined_in_env: true,
                framework_prefix: None,
            },
            EnvVariableInsertRow {
                name: "NEXT_PUBLIC_API_URL".to_string(),
                file: "api.ts".to_string(),
                line: 1,
                access_method: "process.env".to_string(),
                has_default: true,
                defined_in_env: false,
                framework_prefix: Some("Next.js".to_string()),
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.env_variable_rows, 2);

    let conn = read_conn(&dir);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM env_variables", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2);

    // Verify the data was persisted correctly
    let name: String = conn
        .query_row(
            "SELECT name FROM env_variables WHERE has_default = 0 LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(name, "DATABASE_URL");
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertOwaspFindings
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_owasp_findings() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertOwaspFindings(vec![
            OwaspFindingInsertRow {
                id: "owasp-auth-1".to_string(),
                detector: "SEC-AUTH-001".to_string(),
                file: "auth.ts".to_string(),
                line: 42,
                description: "Hardcoded credentials detected".to_string(),
                severity: 0.95,
                cwes: r#"["798"]"#.to_string(),
                owasp_categories: "A07:2021".to_string(),
                confidence: 0.92,
                remediation: Some("Use environment variables".to_string()),
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.owasp_finding_rows, 1);

    let conn = read_conn(&dir);
    let findings = structural::get_owasp_findings_by_file(&conn, "auth.ts").unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector, "SEC-AUTH-001");
    assert_eq!(findings[0].owasp_categories, "A07:2021");
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertDecompositionDecisions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_decomposition_decisions() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertDecompositionDecisions(vec![
            DecompositionDecisionInsertRow {
                dna_profile_hash: "abc123".to_string(),
                adjustment: r#"{"Split":{"module":"core","into":["core-auth","core-db"]}}"#
                    .to_string(),
                confidence: 0.85,
                dna_similarity: 0.90,
                narrative: "Core module is too large, split by concern".to_string(),
                source_dna_hash: "ref-project-xyz".to_string(),
                applied_weight: 0.765,
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.decomposition_decision_rows, 1);

    let conn = read_conn(&dir);
    let decisions =
        structural::get_decomposition_decisions(&conn, "abc123").unwrap();
    assert_eq!(decisions.len(), 1);
    assert!((decisions[0].confidence - 0.85).abs() < 0.001);
    assert_eq!(decisions[0].source_dna_hash, "ref-project-xyz");
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertContracts
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_contracts() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertContracts(vec![
            ContractInsertRow {
                id: "src/app.ts:express".to_string(),
                paradigm: "rest".to_string(),
                source_file: "src/app.ts".to_string(),
                framework: "express".to_string(),
                confidence: 0.8,
                endpoints: r#"[{"method":"GET","path":"/users"}]"#.to_string(),
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.contract_rows, 1);

    let conn = read_conn(&dir);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM contracts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// InsertContractMismatches
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_insert_contract_mismatches() {
    let (writer, dir) = make_batch_writer();
    writer
        .send(BatchCommand::InsertContractMismatches(vec![
            ContractMismatchInsertRow {
                backend_endpoint: "GET /users".to_string(),
                frontend_call: "fetch('/api/users')".to_string(),
                mismatch_type: "FieldMissing".to_string(),
                severity: "High".to_string(),
                message: "Field 'email' missing from frontend".to_string(),
            },
        ]))
        .unwrap();
    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.contract_mismatch_rows, 1);

    let conn = read_conn(&dir);
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM contract_mismatches", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// Mixed batch: all 23 variants in one transaction
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn batch_mixed_all_new_variants() {
    let (writer, _dir) = make_batch_writer();

    writer.send(BatchCommand::InsertScanHistory(vec![
        ScanHistoryInsertRow { started_at: 1700000000, root_path: "/p".into() },
    ])).unwrap();
    writer.send(BatchCommand::InsertReachabilityCache(vec![
        ReachabilityCacheRow { source_node: "n".into(), direction: "fwd".into(), reachable_set: "[]".into(), sensitivity: "low".into() },
    ])).unwrap();
    writer.send(BatchCommand::InsertCouplingMetrics(vec![
        CouplingMetricInsertRow { module: "m".into(), ce: 1, ca: 1, instability: 0.5, abstractness: 0.5, distance: 0.0, zone: "ms".into() },
    ])).unwrap();
    writer.send(BatchCommand::InsertViolations(vec![
        ViolationInsertRow { id: "v1".into(), file: "f".into(), line: 1, column_num: None, end_line: None, end_column: None, severity: "warning".into(), pattern_id: "p".into(), rule_id: "r".into(), message: "m".into(), quick_fix_strategy: None, quick_fix_description: None, cwe_id: None, owasp_category: None, suppressed: false, is_new: false },
    ])).unwrap();
    writer.send(BatchCommand::InsertDegradationAlerts(vec![
        DegradationAlertInsertRow { alert_type: "t".into(), severity: "info".into(), message: "m".into(), current_value: 1.0, previous_value: 0.5, delta: 0.5 },
    ])).unwrap();
    writer.send(BatchCommand::InsertWrappers(vec![
        WrapperInsertRow { name: "w".into(), file: "f".into(), line: 1, category: "c".into(), wrapped_primitives: "[]".into(), framework: "react".into(), confidence: 0.9, is_multi_primitive: false, is_exported: true, usage_count: 1 },
    ])).unwrap();
    writer.send(BatchCommand::InsertCryptoFindings(vec![
        CryptoFindingInsertRow { file: "f".into(), line: 1, category: "c".into(), description: "d".into(), code: "c".into(), confidence: 0.9, cwe_id: 327, owasp: "A02".into(), remediation: "r".into(), language: "ts".into() },
    ])).unwrap();
    writer.send(BatchCommand::InsertDnaGenes(vec![
        DnaGeneInsertRow { gene_id: "g1".into(), name: "n".into(), description: "d".into(), dominant_allele: None, alleles: "[]".into(), confidence: 0.9, consistency: 0.9, exemplars: "[]".into() },
    ])).unwrap();
    writer.send(BatchCommand::InsertSecrets(vec![
        SecretInsertRow { pattern_name: "p".into(), redacted_value: "r".into(), file: "f".into(), line: 1, severity: "High".into(), entropy: 3.0, confidence: 0.9, cwe_ids: "[]".into() },
    ])).unwrap();
    writer.send(BatchCommand::InsertConstants(vec![
        ConstantInsertRow { name: "C".into(), value: "1".into(), file: "f".into(), line: 1, is_used: true, language: "ts".into(), is_named: true },
    ])).unwrap();
    writer.send(BatchCommand::InsertEnvVariables(vec![
        EnvVariableInsertRow { name: "DB_URL".into(), file: "f".into(), line: 1, access_method: "process.env".into(), has_default: false, defined_in_env: false, framework_prefix: None },
    ])).unwrap();
    writer.send(BatchCommand::InsertOwaspFindings(vec![
        OwaspFindingInsertRow { id: "o1".into(), detector: "d".into(), file: "f".into(), line: 1, description: "d".into(), severity: 0.9, cwes: "[]".into(), owasp_categories: "A01".into(), confidence: 0.9, remediation: None },
    ])).unwrap();
    writer.send(BatchCommand::InsertDecompositionDecisions(vec![
        DecompositionDecisionInsertRow { dna_profile_hash: "h".into(), adjustment: "{}".into(), confidence: 0.9, dna_similarity: 0.9, narrative: "n".into(), source_dna_hash: "s".into(), applied_weight: 0.8 },
    ])).unwrap();
    writer.send(BatchCommand::InsertContracts(vec![
        ContractInsertRow { id: "f:fw".into(), paradigm: "rest".into(), source_file: "f".into(), framework: "fw".into(), confidence: 0.8, endpoints: "[]".into() },
    ])).unwrap();
    writer.send(BatchCommand::InsertContractMismatches(vec![
        ContractMismatchInsertRow { backend_endpoint: "GET /x".into(), frontend_call: "fetch".into(), mismatch_type: "FieldMissing".into(), severity: "High".into(), message: "m".into() },
    ])).unwrap();

    let stats = writer.shutdown().unwrap();
    assert_eq!(stats.scan_history_rows, 1);
    assert_eq!(stats.reachability_cache_rows, 1);
    assert_eq!(stats.coupling_metric_rows, 1);
    assert_eq!(stats.violation_rows, 1);
    assert_eq!(stats.degradation_alert_rows, 1);
    assert_eq!(stats.wrapper_rows, 1);
    assert_eq!(stats.crypto_finding_rows, 1);
    assert_eq!(stats.dna_gene_rows, 1);
    assert_eq!(stats.secret_rows, 1);
    assert_eq!(stats.constant_rows, 1);
    assert_eq!(stats.env_variable_rows, 1);
    assert_eq!(stats.owasp_finding_rows, 1);
    assert_eq!(stats.decomposition_decision_rows, 1);
    assert_eq!(stats.contract_rows, 1);
    assert_eq!(stats.contract_mismatch_rows, 1);
    assert!(stats.flushes >= 1);
}

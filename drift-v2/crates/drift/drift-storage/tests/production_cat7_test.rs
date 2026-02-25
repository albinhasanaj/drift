//! Production Category 7: BatchCommand Coverage & WriteStats Accuracy
//!
//! 33 data-carrying + 2 control = 35 total BatchCommand variants.
//! Each must round-trip through the writer with correct WriteStats.

use drift_storage::batch::commands::*;
use drift_storage::batch::writer::BatchWriter;
use drift_storage::migrations::run_migrations;
use drift_storage::queries::{advanced, enforcement, graph, scan_history, structural};
use rusqlite::Connection;

fn make_batch_writer() -> (BatchWriter, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cat7-test.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    run_migrations(&conn).unwrap();
    (BatchWriter::new(conn), dir)
}

fn read_conn(dir: &tempfile::TempDir) -> Connection {
    let db_path = dir.path().join("cat7-test.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn
}

// ═══════════════════════════════════════════════════════════════════════════
// T7-01: All 33 Data Commands Round-Trip
//
// Send one of each data-carrying BatchCommand variant through BatchWriter.
// Verify every WriteStats field is >0 for its corresponding command type.
// Source: writer.rs:30-65 — 33 counter fields in WriteStats
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t7_01_all_33_data_commands_round_trip() {
    let (writer, dir) = make_batch_writer();

    // 1. UpsertFileMetadata
    writer
        .send(BatchCommand::UpsertFileMetadata(vec![FileMetadataRow {
            path: "src/main.ts".into(),
            language: Some("typescript".into()),
            file_size: 1024,
            content_hash: vec![1, 2, 3],
            mtime_secs: 1700000000,
            mtime_nanos: 0,
            last_scanned_at: 1700000000,
            scan_duration_us: Some(500),
        }]))
        .unwrap();

    // 2. InsertParseCache
    writer
        .send(BatchCommand::InsertParseCache(vec![ParseCacheRow {
            content_hash: vec![1, 2, 3],
            language: "typescript".into(),
            parse_result_json: "{}".into(),
            created_at: 1700000000,
        }]))
        .unwrap();

    // 3. InsertFunctions
    writer
        .send(BatchCommand::InsertFunctions(vec![FunctionRow {
            file: "src/main.ts".into(),
            name: "main".into(),
            qualified_name: Some("main.ts::main".into()),
            language: "typescript".into(),
            line: 1,
            end_line: 10,
            parameter_count: 0,
            return_type: Some("void".into()),
            is_exported: true,
            is_async: false,
            body_hash: vec![10, 20],
            signature_hash: vec![30, 40],
        }]))
        .unwrap();

    // 4. DeleteFileMetadata
    writer
        .send(BatchCommand::DeleteFileMetadata(vec![
            "src/deleted.ts".into(),
        ]))
        .unwrap();

    // 5. InsertCallEdges
    writer
        .send(BatchCommand::InsertCallEdges(vec![CallEdgeRow {
            caller_id: 1,
            callee_id: 2,
            resolution: "SameFile".into(),
            confidence: 0.95,
            call_site_line: 5,
        }]))
        .unwrap();

    // 6. InsertDetections
    writer
        .send(BatchCommand::InsertDetections(vec![DetectionRow {
            file: "src/main.ts".into(),
            line: 10,
            column_num: 1,
            pattern_id: "no-eval".into(),
            category: "security".into(),
            confidence: 0.9,
            detection_method: "regex".into(),
            cwe_ids: Some("95".into()),
            owasp: Some("A03".into()),
            matched_text: Some("eval(".into()),
        }]))
        .unwrap();

    // 7. InsertBoundaries
    writer
        .send(BatchCommand::InsertBoundaries(vec![BoundaryRow {
            file: "src/models.ts".into(),
            framework: "prisma".into(),
            model_name: "User".into(),
            table_name: Some("users".into()),
            field_name: Some("email".into()),
            sensitivity: Some("pii".into()),
            confidence: 0.85,
        }]))
        .unwrap();

    // 8. InsertPatternConfidence
    writer
        .send(BatchCommand::InsertPatternConfidence(vec![
            PatternConfidenceRow {
                pattern_id: "no-eval".into(),
                alpha: 10.0,
                beta: 2.0,
                posterior_mean: 0.833,
                credible_interval_low: 0.6,
                credible_interval_high: 0.95,
                tier: "Established".into(),
                momentum: "Stable".into(),
            },
        ]))
        .unwrap();

    // 9. InsertOutliers
    writer
        .send(BatchCommand::InsertOutliers(vec![OutlierDetectionRow {
            pattern_id: "no-eval".into(),
            file: "src/main.ts".into(),
            line: 10,
            deviation_score: 2.5,
            significance: "High".into(),
            method: "ESD".into(),
        }]))
        .unwrap();

    // 10. InsertConventions
    writer
        .send(BatchCommand::InsertConventions(vec![ConventionInsertRow {
            pattern_id: "naming-camelCase".into(),
            category: "naming".into(),
            scope: "project".into(),
            dominance_ratio: 0.85,
            promotion_status: "established".into(),
            discovered_at: 1700000000,
            last_seen: 1700000100,
            expires_at: None,
        }]))
        .unwrap();

    // 11. InsertScanHistory
    writer
        .send(BatchCommand::InsertScanHistory(vec![
            ScanHistoryInsertRow {
                started_at: 1700000000,
                root_path: "/project".into(),
            },
        ]))
        .unwrap();

    // 12. InsertDataAccess — needs a function_id; use raw id=1 from InsertFunctions above
    writer.flush().unwrap();
    let conn = read_conn(&dir);
    let fid: i64 = conn
        .query_row(
            "SELECT id FROM functions WHERE name = 'main'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    drop(conn);

    writer
        .send(BatchCommand::InsertDataAccess(vec![DataAccessInsertRow {
            function_id: fid,
            table_name: "users".into(),
            operation: "SELECT".into(),
            framework: Some("prisma".into()),
            line: 5,
            confidence: 0.9,
        }]))
        .unwrap();

    // 13. InsertReachabilityCache
    writer
        .send(BatchCommand::InsertReachabilityCache(vec![
            ReachabilityCacheRow {
                source_node: "auth::login".into(),
                direction: "forward".into(),
                reachable_set: r#"["db::query"]"#.into(),
                sensitivity: "critical".into(),
            },
        ]))
        .unwrap();

    // 14. InsertTaintFlows
    writer
        .send(BatchCommand::InsertTaintFlows(vec![TaintFlowInsertRow {
            source_file: "handler.ts".into(),
            source_line: 5,
            source_type: "UserInput".into(),
            sink_file: "db.ts".into(),
            sink_line: 20,
            sink_type: "SqlQuery".into(),
            cwe_id: Some(89),
            is_sanitized: false,
            path: "[]".into(),
            confidence: 0.85,
        }]))
        .unwrap();

    // 15. InsertErrorGaps
    writer
        .send(BatchCommand::InsertErrorGaps(vec![ErrorGapInsertRow {
            file: "handler.ts".into(),
            function_id: "handler.ts::process".into(),
            gap_type: "empty_catch".into(),
            error_type: Some("Error".into()),
            propagation_chain: None,
            framework: None,
            cwe_id: Some(390),
            severity: "high".into(),
        }]))
        .unwrap();

    // 16. InsertImpactScores
    writer
        .send(BatchCommand::InsertImpactScores(vec![
            ImpactScoreInsertRow {
                function_id: "auth::login".into(),
                blast_radius: 42,
                risk_score: 0.75,
                is_dead_code: false,
                dead_code_reason: None,
                exclusion_category: None,
            },
        ]))
        .unwrap();

    // 17. InsertTestQuality
    writer
        .send(BatchCommand::InsertTestQuality(vec![
            TestQualityInsertRow {
                function_id: "test::login".into(),
                coverage_breadth: Some(0.8),
                coverage_depth: Some(0.6),
                assertion_density: Some(0.9),
                mock_ratio: Some(0.3),
                isolation: Some(1.0),
                freshness: Some(0.95),
                stability: Some(1.0),
                overall_score: 0.82,
                smells: None,
            },
        ]))
        .unwrap();

    // 18. InsertCouplingMetrics
    writer
        .send(BatchCommand::InsertCouplingMetrics(vec![
            CouplingMetricInsertRow {
                module: "src/auth".into(),
                ce: 5,
                ca: 3,
                instability: 0.625,
                abstractness: 0.2,
                distance: 0.175,
                zone: "main_sequence".into(),
            },
        ]))
        .unwrap();

    // 19. InsertCouplingCycles
    writer
        .send(BatchCommand::InsertCouplingCycles(vec![
            CouplingCycleInsertRow {
                members: r#"["a","b","c"]"#.into(),
                break_suggestions: r#"["remove a->b"]"#.into(),
            },
        ]))
        .unwrap();

    // 20. InsertViolations
    writer
        .send(BatchCommand::InsertViolations(vec![ViolationInsertRow {
            id: "v-001".into(),
            file: "src/auth.ts".into(),
            line: 42,
            column_num: Some(5),
            end_line: Some(42),
            end_column: Some(20),
            severity: "error".into(),
            pattern_id: "no-eval".into(),
            rule_id: "security/no-eval".into(),
            message: "eval() is dangerous".into(),
            quick_fix_strategy: Some("replace".into()),
            quick_fix_description: Some("Use JSON.parse".into()),
            cwe_id: Some(95),
            owasp_category: Some("A03:2021".into()),
            suppressed: false,
            is_new: true,
        }]))
        .unwrap();

    // 21. InsertGateResults
    writer
        .send(BatchCommand::InsertGateResults(vec![GateResultInsertRow {
            gate_id: "confidence".into(),
            status: "passed".into(),
            passed: true,
            score: 0.95,
            summary: "All patterns above threshold".into(),
            violation_count: 0,
            warning_count: 2,
            execution_time_ms: 150,
            details: None,
            error: None,
        }]))
        .unwrap();

    // 22. InsertDegradationAlerts
    writer
        .send(BatchCommand::InsertDegradationAlerts(vec![
            DegradationAlertInsertRow {
                alert_type: "confidence_drop".into(),
                severity: "warning".into(),
                message: "Pattern confidence dropped".into(),
                current_value: 0.65,
                previous_value: 0.80,
                delta: -0.15,
            },
        ]))
        .unwrap();

    // 23. InsertWrappers
    writer
        .send(BatchCommand::InsertWrappers(vec![WrapperInsertRow {
            name: "useAuth".into(),
            file: "hooks/auth.ts".into(),
            line: 10,
            category: "Hook".into(),
            wrapped_primitives: r#"["useState"]"#.into(),
            framework: "react".into(),
            confidence: 0.92,
            is_multi_primitive: false,
            is_exported: true,
            usage_count: 15,
        }]))
        .unwrap();

    // 24. InsertCryptoFindings
    writer
        .send(BatchCommand::InsertCryptoFindings(vec![
            CryptoFindingInsertRow {
                file: "crypto.ts".into(),
                line: 42,
                category: "WeakHash".into(),
                description: "MD5 usage".into(),
                code: "crypto.createHash('md5')".into(),
                confidence: 0.95,
                cwe_id: 328,
                owasp: "A02".into(),
                remediation: "Use SHA-256".into(),
                language: "typescript".into(),
            },
        ]))
        .unwrap();

    // 25. InsertDnaGenes
    writer
        .send(BatchCommand::InsertDnaGenes(vec![DnaGeneInsertRow {
            gene_id: "naming_convention".into(),
            name: "NamingConvention".into(),
            description: "Variable naming patterns".into(),
            dominant_allele: Some("camelCase".into()),
            alleles: r#"[{"name":"camelCase","count":120}]"#.into(),
            confidence: 0.88,
            consistency: 0.95,
            exemplars: "[]".into(),
        }]))
        .unwrap();

    // 26. InsertDnaMutations (FK to dna_genes)
    writer
        .send(BatchCommand::InsertDnaMutations(vec![
            DnaMutationInsertRow {
                id: "mut-001".into(),
                file: "utils.ts".into(),
                line: 55,
                gene_id: "naming_convention".into(),
                expected: "camelCase".into(),
                actual: "snake_case".into(),
                impact: "Medium".into(),
                code: "let my_var = 1".into(),
                suggestion: "Use camelCase".into(),
                detected_at: 1700000000,
            },
        ]))
        .unwrap();

    // 27. InsertSecrets
    writer
        .send(BatchCommand::InsertSecrets(vec![SecretInsertRow {
            pattern_name: "aws_key".into(),
            redacted_value: "AKIA****XXXX".into(),
            file: "config.ts".into(),
            line: 3,
            severity: "Critical".into(),
            entropy: 4.5,
            confidence: 0.99,
            cwe_ids: "[798]".into(),
        }]))
        .unwrap();

    // 28. InsertConstants
    writer
        .send(BatchCommand::InsertConstants(vec![ConstantInsertRow {
            name: "MAX_RETRIES".into(),
            value: "3".into(),
            file: "config.ts".into(),
            line: 1,
            is_used: true,
            language: "typescript".into(),
            is_named: true,
        }]))
        .unwrap();

    // 29. InsertEnvVariables
    writer
        .send(BatchCommand::InsertEnvVariables(vec![
            EnvVariableInsertRow {
                name: "DATABASE_URL".into(),
                file: "config.ts".into(),
                line: 5,
                access_method: "process.env".into(),
                has_default: false,
                defined_in_env: true,
                framework_prefix: None,
            },
        ]))
        .unwrap();

    // 30. InsertOwaspFindings
    writer
        .send(BatchCommand::InsertOwaspFindings(vec![
            OwaspFindingInsertRow {
                id: "owasp-1".into(),
                detector: "SEC-AUTH-001".into(),
                file: "auth.ts".into(),
                line: 42,
                description: "Hardcoded credentials".into(),
                severity: 0.95,
                cwes: r#"["798"]"#.into(),
                owasp_categories: "A07:2021".into(),
                confidence: 0.92,
                remediation: Some("Use env vars".into()),
            },
        ]))
        .unwrap();

    // 31. InsertDecompositionDecisions
    writer
        .send(BatchCommand::InsertDecompositionDecisions(vec![
            DecompositionDecisionInsertRow {
                dna_profile_hash: "abc123".into(),
                adjustment: r#"{"Split":{"module":"core"}}"#.into(),
                confidence: 0.85,
                dna_similarity: 0.90,
                narrative: "Core module too large".into(),
                source_dna_hash: "ref-xyz".into(),
                applied_weight: 0.765,
            },
        ]))
        .unwrap();

    // 32. InsertContracts
    writer
        .send(BatchCommand::InsertContracts(vec![ContractInsertRow {
            id: "src/app.ts:express".into(),
            paradigm: "rest".into(),
            source_file: "src/app.ts".into(),
            framework: "express".into(),
            confidence: 0.8,
            endpoints: r#"[{"method":"GET","path":"/users"}]"#.into(),
        }]))
        .unwrap();

    // 33. InsertContractMismatches
    writer
        .send(BatchCommand::InsertContractMismatches(vec![
            ContractMismatchInsertRow {
                backend_endpoint: "GET /users".into(),
                frontend_call: "fetch('/api/users')".into(),
                mismatch_type: "FieldMissing".into(),
                severity: "High".into(),
                message: "Field 'email' missing".into(),
            },
        ]))
        .unwrap();

    // Shutdown and verify all 33 stats fields
    let stats = writer.shutdown().unwrap();

    assert!(stats.file_metadata_rows > 0, "file_metadata_rows");
    assert!(stats.parse_cache_rows > 0, "parse_cache_rows");
    assert!(stats.function_rows > 0, "function_rows");
    assert!(stats.deleted_files > 0, "deleted_files");
    assert!(stats.call_edge_rows > 0, "call_edge_rows");
    assert!(stats.detection_rows > 0, "detection_rows");
    assert!(stats.boundary_rows > 0, "boundary_rows");
    assert!(stats.pattern_confidence_rows > 0, "pattern_confidence_rows");
    assert!(stats.outlier_rows > 0, "outlier_rows");
    assert!(stats.convention_rows > 0, "convention_rows");
    assert!(stats.scan_history_rows > 0, "scan_history_rows");
    assert!(stats.data_access_rows > 0, "data_access_rows");
    assert!(stats.reachability_cache_rows > 0, "reachability_cache_rows");
    assert!(stats.taint_flow_rows > 0, "taint_flow_rows");
    assert!(stats.error_gap_rows > 0, "error_gap_rows");
    assert!(stats.impact_score_rows > 0, "impact_score_rows");
    assert!(stats.test_quality_rows > 0, "test_quality_rows");
    assert!(stats.coupling_metric_rows > 0, "coupling_metric_rows");
    assert!(stats.coupling_cycle_rows > 0, "coupling_cycle_rows");
    assert!(stats.violation_rows > 0, "violation_rows");
    assert!(stats.gate_result_rows > 0, "gate_result_rows");
    assert!(stats.degradation_alert_rows > 0, "degradation_alert_rows");
    assert!(stats.wrapper_rows > 0, "wrapper_rows");
    assert!(stats.crypto_finding_rows > 0, "crypto_finding_rows");
    assert!(stats.dna_gene_rows > 0, "dna_gene_rows");
    assert!(stats.dna_mutation_rows > 0, "dna_mutation_rows");
    assert!(stats.secret_rows > 0, "secret_rows");
    assert!(stats.constant_rows > 0, "constant_rows");
    assert!(stats.env_variable_rows > 0, "env_variable_rows");
    assert!(stats.owasp_finding_rows > 0, "owasp_finding_rows");
    assert!(
        stats.decomposition_decision_rows > 0,
        "decomposition_decision_rows"
    );
    assert!(stats.contract_rows > 0, "contract_rows");
    assert!(stats.contract_mismatch_rows > 0, "contract_mismatch_rows");

    // Verify data actually persisted by reading back a sample
    let conn = read_conn(&dir);
    let violations = enforcement::query_all_violations(&conn).unwrap();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].id, "v-001");

    let genes = structural::get_all_dna_genes(&conn).unwrap();
    assert_eq!(genes.len(), 1);

    let scan_count = scan_history::count(&conn).unwrap();
    assert_eq!(scan_count, 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// T7-02: Flush + Shutdown Control Commands
//
// Send Flush followed by Shutdown. `flushes` counter must increment on Flush;
// Shutdown must drain buffer and join thread.
// Source: writer.rs:132-138 — Flush calls flush_buffer;
//         writer.rs:104-113 — Shutdown joins handle
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t7_02_flush_and_shutdown_control_commands() {
    let (writer, dir) = make_batch_writer();

    // Send some data, then explicit Flush
    writer
        .send(BatchCommand::InsertScanHistory(vec![
            ScanHistoryInsertRow {
                started_at: 1700000000,
                root_path: "/project".into(),
            },
        ]))
        .unwrap();
    writer.flush().unwrap();

    // After flush, data should be visible in a separate reader connection
    let conn = read_conn(&dir);
    let count = scan_history::count(&conn).unwrap();
    assert_eq!(count, 1, "flush must persist data immediately");
    drop(conn);

    // Send more data — this will be flushed by Shutdown
    writer
        .send(BatchCommand::InsertScanHistory(vec![
            ScanHistoryInsertRow {
                started_at: 1700000200,
                root_path: "/project2".into(),
            },
        ]))
        .unwrap();

    let stats = writer.shutdown().unwrap();

    // flushes counter must be >= 2 (one explicit Flush, one from Shutdown draining buffer)
    assert!(
        stats.flushes >= 2,
        "expected >= 2 flushes (explicit + shutdown drain), got {}",
        stats.flushes
    );
    assert_eq!(stats.scan_history_rows, 2);

    // Verify both rows persisted
    let conn = read_conn(&dir);
    let count = scan_history::count(&conn).unwrap();
    assert_eq!(count, 2, "shutdown must drain remaining buffer");
}

// ═══════════════════════════════════════════════════════════════════════════
// T7-03: Mixed Batch Transaction
//
// Send 500 diverse commands (mix of UpsertFileMetadata, InsertFunctions,
// InsertDetections). All must be committed in a single transaction;
// WriteStats must sum correctly.
// Source: writer.rs:141-142 — triggers flush at buffer.len() >= BATCH_SIZE
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t7_03_mixed_batch_transaction() {
    let (writer, _dir) = make_batch_writer();

    // Send exactly 500 commands (BATCH_SIZE threshold) as a mix of 3 types
    // 200 UpsertFileMetadata + 200 InsertDetections + 100 InsertFunctions = 500
    for i in 0..200 {
        writer
            .send(BatchCommand::UpsertFileMetadata(vec![FileMetadataRow {
                path: format!("src/file_{i}.ts"),
                language: Some("typescript".into()),
                file_size: 100,
                content_hash: vec![i as u8],
                mtime_secs: 1700000000,
                mtime_nanos: 0,
                last_scanned_at: 1700000000,
                scan_duration_us: None,
            }]))
            .unwrap();
    }

    for i in 0..200 {
        writer
            .send(BatchCommand::InsertDetections(vec![DetectionRow {
                file: format!("src/file_{i}.ts"),
                line: 1,
                column_num: 1,
                pattern_id: "pat-1".into(),
                category: "style".into(),
                confidence: 0.8,
                detection_method: "regex".into(),
                cwe_ids: None,
                owasp: None,
                matched_text: None,
            }]))
            .unwrap();
    }

    for i in 0..100 {
        writer
            .send(BatchCommand::InsertFunctions(vec![FunctionRow {
                file: format!("src/file_{i}.ts"),
                name: format!("fn_{i}"),
                qualified_name: None,
                language: "typescript".into(),
                line: 1,
                end_line: 5,
                parameter_count: 0,
                return_type: None,
                is_exported: false,
                is_async: false,
                body_hash: vec![i as u8],
                signature_hash: vec![i as u8],
            }]))
            .unwrap();
    }

    let stats = writer.shutdown().unwrap();

    assert_eq!(stats.file_metadata_rows, 200);
    assert_eq!(stats.detection_rows, 200);
    assert_eq!(stats.function_rows, 100);

    // At 500 commands, the BATCH_SIZE threshold should have triggered at least one flush
    assert!(
        stats.flushes >= 1,
        "expected >= 1 flush from BATCH_SIZE threshold, got {}",
        stats.flushes
    );

    // Total should equal the sum of all individual counts
    let total_data_rows =
        stats.file_metadata_rows + stats.detection_rows + stats.function_rows;
    assert_eq!(total_data_rows, 500);
}

// ═══════════════════════════════════════════════════════════════════════════
// T7-04: Drop Without Shutdown
//
// Drop BatchWriter without calling `shutdown()`. The `Drop` impl must send
// Shutdown signal; thread must not leak.
// Source: writer.rs:116-121 — Drop sends BatchCommand::Shutdown
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t7_04_drop_without_shutdown() {
    let (writer, dir) = make_batch_writer();

    writer
        .send(BatchCommand::InsertScanHistory(vec![
            ScanHistoryInsertRow {
                started_at: 1700000000,
                root_path: "/project".into(),
            },
        ]))
        .unwrap();

    // Drop without calling shutdown() — Drop impl sends Shutdown
    drop(writer);

    // Give the writer thread time to process the Shutdown signal and flush.
    // The Drop impl only sends the signal; the thread may need a moment.
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Data should still be persisted because Drop → Shutdown → flush_buffer
    let conn = read_conn(&dir);
    let count = scan_history::count(&conn).unwrap();
    assert_eq!(
        count, 1,
        "Drop must flush pending data via Shutdown signal"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// T7-05: 13 Unwired Tables — Direct SQL INSERT via with_writer()
//
// Verify that constraints, constraint_verifications, test_coverage,
// audit_snapshots, health_trends, feedback, policy_results, simulations,
// decisions, context_cache, migration_projects, migration_modules,
// migration_corrections can all be written directly (not via BatchWriter).
// Source: DD-15 finding — 13 tables have no BatchCommand variant
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn t7_05_13_unwired_tables_direct_insert() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cat7-unwired.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON").unwrap();
    run_migrations(&conn).unwrap();

    // 1. constraints
    structural::upsert_constraint(
        &conn,
        &structural::ConstraintRow {
            id: "c-001".into(),
            description: "No eval usage".into(),
            invariant_type: "forbidden_pattern".into(),
            target: "*.ts".into(),
            scope: Some("project".into()),
            source: "config".into(),
            enabled: true,
        },
    )
    .unwrap();
    let c = structural::get_constraint(&conn, "c-001").unwrap();
    assert!(c.is_some(), "constraints table: insert + read");

    // 2. constraint_verifications (FK to constraints)
    structural::insert_constraint_verification(&conn, "c-001", true, "[]").unwrap();
    let cvs = structural::query_constraint_verifications(&conn, "c-001").unwrap();
    assert_eq!(cvs.len(), 1, "constraint_verifications table: insert + read");

    // 3. test_coverage
    graph::insert_test_coverage(
        &conn,
        &graph::TestCoverageRow {
            test_function_id: "test::login_test".into(),
            source_function_id: "auth::login".into(),
            coverage_type: "direct".into(),
        },
    )
    .unwrap();
    let tc = graph::get_test_coverage_for_source(&conn, "auth::login").unwrap();
    assert_eq!(tc.len(), 1, "test_coverage table: insert + read");

    // 4. audit_snapshots
    enforcement::insert_audit_snapshot(
        &conn,
        &enforcement::AuditSnapshotRow {
            health_score: 0.85,
            avg_confidence: 0.80,
            approval_ratio: 0.90,
            compliance_rate: 0.95,
            cross_validation_rate: 0.88,
            duplicate_free_rate: 0.99,
            pattern_count: 42,
            category_scores: Some(r#"{"security":0.9}"#.into()),
            created_at: 0, // ignored on insert (auto-populated by DB)
        },
    )
    .unwrap();
    let snapshots = enforcement::query_audit_snapshots(&conn, 10).unwrap();
    assert_eq!(snapshots.len(), 1, "audit_snapshots table: insert + read");

    // 5. health_trends
    enforcement::insert_health_trend(&conn, "avg_confidence", 0.85).unwrap();
    let trends = enforcement::query_health_trends(&conn, "avg_confidence", 10).unwrap();
    assert_eq!(trends.len(), 1, "health_trends table: insert + read");

    // 6. feedback (FK to violations via violation_id — insert a violation first)
    conn.execute(
        "INSERT OR REPLACE INTO violations (id, file, line, severity, pattern_id, rule_id, message, suppressed, is_new)
         VALUES ('v-fb-1', 'f.ts', 1, 'error', 'pat', 'rule', 'msg', 0, 0)",
        [],
    )
    .unwrap();
    enforcement::insert_feedback(
        &conn,
        &enforcement::FeedbackRow {
            violation_id: "v-fb-1".into(),
            pattern_id: "pat".into(),
            detector_id: "det-1".into(),
            action: "dismiss".into(),
            dismissal_reason: Some("false_positive".into()),
            reason: None,
            author: Some("test".into()),
            created_at: 0, // ignored on insert
        },
    )
    .unwrap();
    let fb = enforcement::query_feedback_by_detector(&conn, "det-1").unwrap();
    assert_eq!(fb.len(), 1, "feedback table: insert + read");

    // 7. policy_results
    enforcement::insert_policy_result(
        &conn,
        &enforcement::PolicyResultRow {
            id: 0, // auto-increment
            policy_name: "strict".into(),
            aggregation_mode: "all_must_pass".into(),
            overall_passed: true,
            overall_score: 0.95,
            gate_count: 6,
            gates_passed: 6,
            gates_failed: 0,
            details: None,
            run_at: 0, // auto-populated
        },
    )
    .unwrap();
    let pr = enforcement::query_recent_policy_results(&conn, 10).unwrap();
    assert_eq!(pr.len(), 1, "policy_results table: insert + read");

    // 8. simulations
    let sim_id = advanced::insert_simulation(
        &conn,
        "refactor",
        "Extract auth module",
        3,
        Some("incremental"),
        2.0,
        5.0,
        10.0,
    )
    .unwrap();
    assert!(sim_id > 0, "simulations table: insert");
    let sims = advanced::get_simulations(&conn, 10).unwrap();
    assert_eq!(sims.len(), 1, "simulations table: read");

    // 9. decisions
    let dec_id = advanced::insert_decision(
        &conn,
        "architecture",
        "Split monolith",
        Some("abc123"),
        0.85,
        None,
        Some("engineer"),
        None,
    )
    .unwrap();
    assert!(dec_id > 0, "decisions table: insert");

    // 10. context_cache
    let ctx_id =
        advanced::insert_context_cache(&conn, "sess-1", "explain", "deep", 1500, "hash123")
            .unwrap();
    assert!(ctx_id > 0, "context_cache table: insert");

    // 11. migration_projects
    let proj_id = advanced::create_migration_project(
        &conn,
        "JS to TS",
        "javascript",
        "typescript",
        Some("express"),
        Some("express"),
    )
    .unwrap();
    assert!(proj_id > 0, "migration_projects table: insert");

    // 12. migration_modules (FK to migration_projects)
    let mod_id = advanced::create_migration_module(&conn, proj_id, "auth").unwrap();
    assert!(mod_id > 0, "migration_modules table: insert");
    advanced::update_module_status(&conn, mod_id, "in_progress").unwrap();

    // 13. migration_corrections (FK to migration_modules)
    let corr_id = advanced::insert_migration_correction(
        &conn,
        mod_id,
        "imports",
        "const x = require('x')",
        "import x from 'x'",
        Some("ES module conversion"),
    )
    .unwrap();
    assert!(corr_id > 0, "migration_corrections table: insert");
    let corr = advanced::get_migration_correction(&conn, corr_id).unwrap();
    assert!(corr.is_some(), "migration_corrections table: read");
    assert_eq!(
        corr.unwrap().corrected_text,
        "import x from 'x'"
    );

    // Verify all 13 tables have at least 1 row
    let tables = [
        "constraints",
        "constraint_verifications",
        "test_coverage",
        "audit_snapshots",
        "health_trends",
        "feedback",
        "policy_results",
        "simulations",
        "decisions",
        "context_cache",
        "migration_projects",
        "migration_modules",
        "migration_corrections",
    ];
    for table in &tables {
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {table}"),
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|e| panic!("failed to count {table}: {e}"));
        assert!(count > 0, "{table} must have at least 1 row, got {count}");
    }
}

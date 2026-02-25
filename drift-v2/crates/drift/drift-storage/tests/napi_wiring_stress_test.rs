//! Stress test that exercises every NAPI-wired DB path end-to-end.
//!
//! Uses a file-backed DatabaseManager (like production) to verify:
//! 1. Write → read round-trip through writer + read pool
//! 2. Concurrent reads while writes are happening
//! 3. BatchWriter → read pool visibility
//! 4. Edge cases: empty tables, Unicode, large payloads, special chars
//! 5. Every query module the NAPI bindings touch

use std::sync::{Arc, Barrier};
use std::thread;

use drift_storage::batch::commands::{
    BatchCommand, FileMetadataRow as BatchFileMetadataRow,
};
use drift_storage::batch::writer::BatchWriter;
use drift_storage::queries::*;
use drift_storage::DatabaseManager;
use tempfile::TempDir;

fn setup() -> (TempDir, DatabaseManager) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("stress.db");
    let db = DatabaseManager::open(&db_path).unwrap();
    (dir, db)
}

// ─── 1. ENFORCEMENT: violations → gates → audit → feedback ─────────

#[test]
fn stress_enforcement_full_pipeline() {
    let (_dir, db) = setup();

    // Write 500 violations
    db.with_writer(|conn| {
        for i in 0..500 {
            enforcement::insert_violation(conn, &enforcement::ViolationRow {
                id: format!("v-{i}"),
                file: format!("src/mod_{}.ts", i % 20),
                line: (i * 3) as u32,
                column: if i % 3 == 0 { Some(10) } else { None },
                end_line: None,
                end_column: None,
                severity: match i % 4 {
                    0 => "critical".to_string(),
                    1 => "high".to_string(),
                    2 => "medium".to_string(),
                    _ => "low".to_string(),
                },
                pattern_id: format!("pat-{}", i % 10),
                rule_id: format!("rule-{}", i % 5),
                message: format!("Violation #{i}: something is wrong in the code"),
                quick_fix_strategy: None,
                quick_fix_description: None,
                cwe_id: if i % 2 == 0 { Some(79) } else { None },
                owasp_category: if i % 3 == 0 { Some("A01:2021".to_string()) } else { None },
                suppressed: i % 7 == 0,
                is_new: false,
            })?;
        }
        Ok(())
    }).unwrap();

    // Read all violations through read pool
    let all = db.with_reader(|conn| {
        enforcement::query_all_violations(conn)
    }).unwrap();
    assert_eq!(all.len(), 500, "all 500 violations should be readable from read pool");

    // Verify CWE filter works
    let with_cwe: Vec<_> = all.iter().filter(|v| v.cwe_id.is_some()).collect();
    assert_eq!(with_cwe.len(), 250);

    // Write gate results
    db.with_writer(|conn| {
        for i in 0..10 {
            enforcement::insert_gate_result(conn, &enforcement::GateResultRow {
                gate_id: format!("gate-{i}"),
                status: if i % 3 == 0 { "failed".to_string() } else { "passed".to_string() },
                passed: i % 3 != 0,
                score: (100 - i * 5) as f64,
                summary: format!("Gate {i} summary"),
                violation_count: (i * 50) as u32,
                warning_count: 0,
                execution_time_ms: 100 + i as u64,
                details: Some(format!("{{\"gate\": {i}}}")),
                error: None,
                run_at: 1700000000 + i as u64,
            })?;
        }
        Ok(())
    }).unwrap();

    let gates = db.with_reader(enforcement::query_gate_results).unwrap();
    assert_eq!(gates.len(), 10);
    assert!(!gates[0].passed || gates[0].gate_id != "gate-0", "gate-0 should fail");

    // Write feedback (the NAPI write path)
    db.with_writer(|conn| {
        enforcement::insert_feedback(conn, &enforcement::FeedbackRow {
            violation_id: "v-0".to_string(),
            pattern_id: "pat-0".to_string(),
            detector_id: "det-0".to_string(),
            action: "dismiss".to_string(),
            dismissal_reason: Some("false positive".to_string()),
            reason: Some("false positive".to_string()),
            author: Some("test-user".to_string()),
            created_at: 0,
        })
    }).unwrap();

    let fb = db.with_reader(|conn| {
        enforcement::query_feedback_by_detector(conn, "det-0")
    }).unwrap();
    assert_eq!(fb.len(), 1);
    assert_eq!(fb[0].action, "dismiss");

    // Write degradation alerts
    db.with_writer(|conn| {
        for i in 0..20 {
            enforcement::insert_degradation_alert(conn, &enforcement::DegradationAlertRow {
                id: 0,
                alert_type: "confidence_drop".to_string(),
                severity: "high".to_string(),
                message: format!("Confidence dropped by {i}%"),
                current_value: 80.0 - i as f64,
                previous_value: 80.0,
                delta: -(i as f64),
                created_at: 0,
            })?;
        }
        Ok(())
    }).unwrap();

    let alerts = db.with_reader(|conn| {
        enforcement::query_recent_degradation_alerts(conn, 50)
    }).unwrap();
    assert_eq!(alerts.len(), 20);
}

// ─── 2. PATTERNS: confidence → outliers → conventions ───────────────

#[test]
fn stress_patterns_full_pipeline() {
    let (_dir, db) = setup();

    // Write 200 confidence scores
    db.with_writer(|conn| {
        for i in 0..200 {
            patterns::upsert_confidence(conn, &patterns::PatternConfidenceRow {
                pattern_id: format!("pattern-{i}"),
                alpha: 10.0 + i as f64,
                beta: 2.0 + (i as f64 * 0.1),
                posterior_mean: (10.0 + i as f64) / (12.0 + i as f64 * 1.1),
                credible_interval_low: 0.3,
                credible_interval_high: 0.95,
                tier: match i % 3 {
                    0 => "Established".to_string(),
                    1 => "Emerging".to_string(),
                    _ => "Experimental".to_string(),
                },
                momentum: "Rising".to_string(),
                last_updated: 1700000000 + i as i64,
            })?;
        }
        Ok(())
    }).unwrap();

    // Read all
    let all = db.with_reader(patterns::query_all_confidence).unwrap();
    assert_eq!(all.len(), 200);

    // Keyset pagination by tier
    let page1 = db.with_reader(|conn| {
        patterns::query_confidence_by_tier(conn, "Established", None, 10)
    }).unwrap();
    assert!(page1.len() <= 10);
    assert!(page1.iter().all(|s| s.tier == "Established"));

    if !page1.is_empty() {
        let cursor = &page1.last().unwrap().pattern_id;
        let page2 = db.with_reader(|conn| {
            patterns::query_confidence_by_tier(conn, "Established", Some(cursor.as_str()), 10)
        }).unwrap();
        // Ensure cursor actually advanced (no overlap)
        if !page2.is_empty() {
            assert!(page2[0].pattern_id > *cursor, "keyset cursor must advance");
        }
    }

    // Write outliers
    db.with_writer(|conn| {
        for i in 0..50 {
            patterns::insert_outlier(conn, &patterns::OutlierRow {
                id: 0,
                pattern_id: format!("pattern-{}", i % 10),
                file: format!("src/file_{i}.ts"),
                line: i as i64,
                deviation_score: 2.5 + (i as f64 * 0.1),
                significance: if i % 2 == 0 { "high".to_string() } else { "medium".to_string() },
                method: "z_score".to_string(),
                created_at: 0,
            })?;
        }
        Ok(())
    }).unwrap();

    let outliers = db.with_reader(|conn| {
        patterns::query_outliers_by_pattern(conn, "pattern-0")
    }).unwrap();
    assert!(!outliers.is_empty());

    // Write conventions
    db.with_writer(|conn| {
        for i in 0..30 {
            patterns::insert_convention(conn, &patterns::ConventionRow {
                id: 0,
                pattern_id: format!("pattern-{i}"),
                category: match i % 3 {
                    0 => "naming".to_string(),
                    1 => "structure".to_string(),
                    _ => "error_handling".to_string(),
                },
                scope: "Project".to_string(),
                dominance_ratio: 0.7 + (i as f64 * 0.01),
                promotion_status: "candidate".to_string(),
                discovered_at: 1700000000,
                last_seen: 1700000000 + i as i64,
                expires_at: None,
            })?;
        }
        Ok(())
    }).unwrap();

    let naming = db.with_reader(|conn| {
        patterns::query_conventions_by_category(conn, "naming")
    }).unwrap();
    assert_eq!(naming.len(), 10);

    let all_conv = db.with_reader(patterns::query_all_conventions).unwrap();
    assert_eq!(all_conv.len(), 30);
}

// ─── 3. GRAPH: reachability → taint → errors → impact → test quality ─

#[test]
fn stress_graph_full_pipeline() {
    let (_dir, db) = setup();

    // Reachability cache
    db.with_writer(|conn| {
        graph::upsert_reachability(conn, &graph::ReachabilityCacheRow {
            source_node: "fn::main".to_string(),
            direction: "forward".to_string(),
            reachable_set: r#"["fn::a","fn::b","fn::c"]"#.to_string(),
            sensitivity: "high".to_string(),
        })
    }).unwrap();

    let cached = db.with_reader(|conn| {
        graph::get_reachability(conn, "fn::main", "forward")
    }).unwrap();
    assert!(cached.is_some());
    let row = cached.unwrap();
    assert_eq!(row.sensitivity, "high");

    // Miss returns None
    let miss = db.with_reader(|conn| {
        graph::get_reachability(conn, "fn::nonexistent", "forward")
    }).unwrap();
    assert!(miss.is_none());

    // Taint flows — 100 flows
    db.with_writer(|conn| {
        for i in 0..100 {
            graph::insert_taint_flow(conn, &graph::TaintFlowRow {
                id: None,
                source_file: format!("src/input_{}.ts", i % 5),
                source_line: (i * 2) as u32,
                source_type: "user_input".to_string(),
                sink_file: format!("src/db_{}.ts", i % 3),
                sink_line: (i * 3) as u32,
                sink_type: "sql_query".to_string(),
                cwe_id: if i % 2 == 0 { Some(89) } else { None },
                is_sanitized: i % 5 == 0,
                path: format!(r#"["node_{i}_a","node_{i}_b"]"#),
                confidence: 0.5 + (i as f64 * 0.005),
            })?;
        }
        Ok(())
    }).unwrap();

    let flows = db.with_reader(|conn| {
        graph::get_taint_flows_by_file(conn, "src/input_0.ts")
    }).unwrap();
    assert!(!flows.is_empty());

    let cwe_flows = db.with_reader(|conn| graph::get_taint_flows_by_cwe(conn, 89)).unwrap();
    assert_eq!(cwe_flows.len(), 50);

    // Error gaps
    db.with_writer(|conn| {
        for i in 0..30 {
            graph::insert_error_gap(conn, &graph::ErrorGapRow {
                id: None,
                file: format!("src/handler_{i}.ts"),
                function_id: format!("handleRequest_{i}"),
                gap_type: "uncaught_promise".to_string(),
                error_type: Some("Promise<void>".to_string()),
                propagation_chain: None,
                framework: Some("express".to_string()),
                cwe_id: Some(755),
                severity: "high".to_string(),
            })?;
        }
        Ok(())
    }).unwrap();

    let gaps = db.with_reader(|conn| {
        graph::get_error_gaps_by_file(conn, "src/handler_0.ts")
    }).unwrap();
    assert_eq!(gaps.len(), 1);

    // Impact scores
    db.with_writer(|conn| {
        for i in 0..50 {
            graph::upsert_impact_score(conn, &graph::ImpactScoreRow {
                function_id: format!("fn_{i}"),
                blast_radius: (i * 3) as u32,
                risk_score: i as f64 * 0.02,
                is_dead_code: i % 10 == 0,
                dead_code_reason: if i % 10 == 0 { Some("no callers".to_string()) } else { None },
                exclusion_category: None,
            })?;
        }
        Ok(())
    }).unwrap();

    let impact = db.with_reader(|conn| {
        graph::get_impact_score(conn, "fn_0")
    }).unwrap();
    assert!(impact.is_some());
    assert!(impact.unwrap().is_dead_code);

    // Test quality
    db.with_writer(|conn| {
        for i in 0..20 {
            graph::upsert_test_quality(conn, &graph::TestQualityRow {
                function_id: format!("test_{i}"),
                coverage_breadth: Some(0.8),
                coverage_depth: Some(0.6),
                assertion_density: Some(2.5),
                mock_ratio: Some(0.3),
                isolation: Some(0.9),
                freshness: Some(0.95),
                stability: Some(1.0),
                overall_score: 0.82,
                smells: Some(r#"["long_test","magic_number"]"#.to_string()),
            })?;
        }
        Ok(())
    }).unwrap();

    let tq = db.with_reader(|conn| graph::get_test_quality(conn, "test_0")).unwrap();
    assert!(tq.is_some());
    assert!((tq.unwrap().overall_score - 0.82).abs() < 0.001);
}

// ─── 4. STRUCTURAL: coupling → constraints → contracts → DNA → crypto ─

#[test]
fn stress_structural_full_pipeline() {
    let (_dir, db) = setup();

    // Coupling metrics — 100 modules
    db.with_writer(|conn| {
        for i in 0..100 {
            structural::upsert_coupling_metrics(conn, &structural::CouplingMetricsRow {
                module: format!("src/modules/mod_{i}"),
                ce: (i * 2) as u32,
                ca: (i + 5) as u32,
                instability: i as f64 / 100.0,
                abstractness: 1.0 - (i as f64 / 100.0),
                distance: (i as f64 / 100.0 - 0.5).abs(),
                zone: match i % 3 {
                    0 => "zone_of_pain".to_string(),
                    1 => "zone_of_uselessness".to_string(),
                    _ => "main_sequence".to_string(),
                },
            })?;
        }
        Ok(())
    }).unwrap();

    let metrics = db.with_reader(structural::get_all_coupling_metrics).unwrap();
    assert_eq!(metrics.len(), 100);

    let pain = db.with_reader(|conn| {
        structural::get_coupling_metrics_by_zone(conn, "zone_of_pain")
    }).unwrap();
    assert!(!pain.is_empty());

    // Coupling cycles
    db.with_writer(|conn| {
        structural::insert_coupling_cycle(
            conn,
            r#"["mod_0","mod_1","mod_2"]"#,
            r#"[{"break":"mod_1→mod_2"}]"#,
        )
    }).unwrap();

    let cycles = db.with_reader(structural::query_coupling_cycles).unwrap();
    assert_eq!(cycles.len(), 1);

    // Constraints + verifications
    db.with_writer(|conn| {
        structural::upsert_constraint(conn, &structural::ConstraintRow {
            id: "no-circular-deps".to_string(),
            description: "No circular dependencies allowed".to_string(),
            invariant_type: "dependency".to_string(),
            target: "**".to_string(),
            scope: Some("project".to_string()),
            source: "drift.toml".to_string(),
            enabled: true,
        })?;
        structural::insert_constraint_verification(
            conn, "no-circular-deps", false,
            "mod_0 → mod_1 → mod_2 → mod_0",
        )?;
        structural::insert_constraint_verification(
            conn, "no-circular-deps", true, "",
        )?;
        Ok(())
    }).unwrap();

    let constraints = db.with_reader(structural::get_enabled_constraints).unwrap();
    assert_eq!(constraints.len(), 1);

    let verifs = db.with_reader(|conn| {
        structural::query_constraint_verifications(conn, "no-circular-deps")
    }).unwrap();
    assert_eq!(verifs.len(), 2);
    assert!(!verifs[0].passed || !verifs[1].passed); // at least one fails

    // Contracts
    db.with_writer(|conn| {
        structural::upsert_contract(conn, &structural::ContractRow {
            id: "api-users".to_string(),
            paradigm: "REST".to_string(),
            source_file: "src/routes/users.ts".to_string(),
            framework: "express".to_string(),
            confidence: 0.95,
            endpoints: r#"[{"method":"GET","path":"/users"}]"#.to_string(),
        })
    }).unwrap();

    let contract = db.with_reader(|conn| structural::get_contract(conn, "api-users")).unwrap();
    assert!(contract.is_some());

    // Secrets
    db.with_writer(|conn| {
        structural::insert_secret(conn, &structural::SecretRow {
            id: None,
            pattern_name: "aws_key".to_string(),
            redacted_value: "AKIA****".to_string(),
            file: "src/config.ts".to_string(),
            line: 42,
            severity: "critical".to_string(),
            entropy: 4.5,
            confidence: 0.99,
            cwe_ids: "[798]".to_string(),
        })
    }).unwrap();

    let secrets = db.with_reader(|conn| {
        structural::get_secrets_by_severity(conn, "critical")
    }).unwrap();
    assert_eq!(secrets.len(), 1);

    // Wrappers
    db.with_writer(|conn| {
        structural::insert_wrapper(conn, &structural::WrapperRow {
            id: None,
            name: "useApi".to_string(),
            file: "src/hooks/useApi.ts".to_string(),
            line: 10,
            category: "http".to_string(),
            wrapped_primitives: r#"["fetch"]"#.to_string(),
            framework: "react".to_string(),
            confidence: 0.85,
            is_multi_primitive: false,
            is_exported: true,
            usage_count: 42,
        })
    }).unwrap();

    let wrappers = db.with_reader(|conn| {
        structural::get_wrappers_by_category(conn, "http")
    }).unwrap();
    assert_eq!(wrappers.len(), 1);
    assert_eq!(wrappers[0].usage_count, 42);

    // DNA genes + mutations
    db.with_writer(|conn| {
        structural::upsert_dna_gene(conn, &structural::DnaGeneRow {
            gene_id: "error-handling-pattern".to_string(),
            name: "Error Handling".to_string(),
            description: "How the project handles errors".to_string(),
            dominant_allele: Some("try-catch".to_string()),
            alleles: r#"["try-catch","error-boundary","result-type"]"#.to_string(),
            confidence: 0.9,
            consistency: 0.85,
            exemplars: r#"["src/api.ts:45"]"#.to_string(),
        })?;
        structural::upsert_dna_mutation(conn, &structural::DnaMutationRow {
            id: "mut-001".to_string(),
            file: "src/legacy.ts".to_string(),
            line: 100,
            gene_id: "error-handling-pattern".to_string(),
            expected: "try-catch".to_string(),
            actual: "callback-error".to_string(),
            impact: "high".to_string(),
            code: "cb(err)".to_string(),
            suggestion: "Use try-catch instead of callback error pattern".to_string(),
            detected_at: 1700000000,
            resolved: false,
            resolved_at: None,
        })?;
        Ok(())
    }).unwrap();

    let genes = db.with_reader(structural::get_all_dna_genes).unwrap();
    assert_eq!(genes.len(), 1);

    let mutations = db.with_reader(structural::get_unresolved_mutations).unwrap();
    assert_eq!(mutations.len(), 1);

    // Crypto findings
    db.with_writer(|conn| {
        structural::insert_crypto_finding(conn, &structural::CryptoFindingRow {
            id: None,
            file: "src/auth.ts".to_string(),
            line: 55,
            category: "weak_hash".to_string(),
            description: "MD5 used for password hashing".to_string(),
            code: "crypto.createHash('md5')".to_string(),
            confidence: 0.98,
            cwe_id: 328,
            owasp: "A02:2021".to_string(),
            remediation: "Use bcrypt or argon2".to_string(),
            language: "TypeScript".to_string(),
        })
    }).unwrap();

    let crypto = db.with_reader(|conn| {
        structural::get_crypto_findings_by_file(conn, "src/auth.ts")
    }).unwrap();
    assert_eq!(crypto.len(), 1);
    assert_eq!(crypto[0].cwe_id, 328);
}

// ─── 5. ANALYSIS: functions → call_edges → boundaries → detections ──

#[test]
fn stress_analysis_pipeline() {
    let (_dir, db) = setup();

    // Functions — bulk insert via direct SQL (production uses batch writer)
    db.with_writer(|conn| {
        let mut stmt = conn.prepare_cached(
            "INSERT OR REPLACE INTO functions
             (file, name, qualified_name, language, line, end_line,
              parameter_count, return_type, is_exported, is_async,
              body_hash, signature_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
        ).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
        for i in 0..200 {
            stmt.execute(rusqlite::params![
                format!("src/mod_{}.ts", i % 10),
                format!("fn_{i}"),
                format!("src/mod_{}.ts::fn_{i}", i % 10),
                "TypeScript",
                i * 10,
                i * 10 + 9,
                2i32,           // parameter_count
                "void",         // return_type
                (i % 3 != 0) as i32,  // is_exported
                0i32,           // is_async
                vec![i as u8; 32],    // body_hash (BLOB)
                vec![(i + 1) as u8; 32],  // signature_hash (BLOB)
            ]).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
        }
        Ok(())
    }).unwrap();

    let count = db.with_reader(functions::count_functions).unwrap();
    assert_eq!(count, 200);

    let by_file = db.with_reader(|conn| {
        functions::get_functions_by_file(conn, "src/mod_0.ts")
    }).unwrap();
    assert_eq!(by_file.len(), 20);

    // Call edges
    db.with_writer(|conn| {
        let edges: Vec<call_edges::CallEdgeRecord> = (0..100).map(|i| {
            call_edges::CallEdgeRecord {
                caller_id: (i + 1) as i64,
                callee_id: ((i + 2) % 200 + 1) as i64,
                resolution: "import_based".to_string(),
                confidence: 0.9,
                call_site_line: (i * 5) as i64,
            }
        }).collect();
        call_edges::insert_call_edges(conn, &edges)?;
        Ok(())
    }).unwrap();

    let edge_count = db.with_reader(call_edges::count_call_edges).unwrap();
    assert_eq!(edge_count, 100);

    // Boundaries
    db.with_writer(|conn| {
        let bounds: Vec<boundaries::BoundaryRecord> = (0..50).map(|i| {
            boundaries::BoundaryRecord {
                id: 0,
                file: "src/models/user.ts".to_string(),
                framework: "prisma".to_string(),
                model_name: "User".to_string(),
                table_name: Some("users".to_string()),
                field_name: Some(format!("field_{i}")),
                sensitivity: if i % 5 == 0 { Some("pii".to_string()) } else { None },
                confidence: 0.9,
                created_at: 0,
            }
        }).collect();
        boundaries::insert_boundaries(conn, &bounds)?;
        Ok(())
    }).unwrap();

    let sensitive = db.with_reader(boundaries::get_sensitive_boundaries).unwrap();
    assert_eq!(sensitive.len(), 10); // every 5th has sensitivity

    let by_fw = db.with_reader(|conn| {
        boundaries::get_boundaries_by_framework(conn, "prisma")
    }).unwrap();
    assert_eq!(by_fw.len(), 50);

    // Detections
    db.with_writer(|conn| {
        let dets: Vec<detections::DetectionRecord> = (0..100).map(|i| {
            detections::DetectionRecord {
                id: 0,
                file: format!("src/file_{}.ts", i % 10),
                line: i as i64,
                column_num: 0,
                pattern_id: format!("pat-{}", i % 5),
                category: match i % 3 {
                    0 => "security".to_string(),
                    1 => "naming".to_string(),
                    _ => "structure".to_string(),
                },
                confidence: 0.7 + (i as f64 * 0.003),
                detection_method: "ast_match".to_string(),
                cwe_ids: None,
                owasp: None,
                matched_text: Some(format!("matched_text_{i}")),
                created_at: 0,
            }
        }).collect();
        detections::insert_detections(conn, &dets)?;
        Ok(())
    }).unwrap();

    let det_count = db.with_reader(detections::count_detections).unwrap();
    assert_eq!(det_count, 100);

    let by_cat = db.with_reader(|conn| {
        detections::get_detections_by_category(conn, "security")
    }).unwrap();
    assert!(by_cat.len() > 30);
}

// ─── 6. SCAN PIPELINE: file_metadata via BatchWriter → read pool ────

#[test]
fn stress_batch_writer_to_read_pool() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("batch_stress.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    // Create a BatchWriter with a dedicated connection (production path)
    let batch_conn = db.open_batch_connection().unwrap();
    let batch_writer = BatchWriter::new(batch_conn);

    // Send 1000 file metadata rows through the batch writer
    let rows: Vec<BatchFileMetadataRow> = (0..1000).map(|i| {
        BatchFileMetadataRow {
            path: format!("src/components/Component_{i}.tsx"),
            language: Some("TypeScript".to_string()),
            file_size: 1000 + i as i64,
            content_hash: (i as u64).to_le_bytes().to_vec(),
            mtime_secs: 1700000000 + i as i64,
            mtime_nanos: 0,
            last_scanned_at: 1700000000,
            scan_duration_us: Some(100 + i as i64),
        }
    }).collect();

    batch_writer.send(BatchCommand::UpsertFileMetadata(rows)).unwrap();

    // Shutdown waits for the writer thread to finish processing all commands
    let stats = batch_writer.shutdown().unwrap();
    assert_eq!(stats.file_metadata_rows, 1000);

    // Verify data is visible through the read pool
    let all = db.with_reader(files::load_all_file_metadata).unwrap();
    assert_eq!(all.len(), 1000, "all 1000 files should be visible via read pool after batch shutdown");

    // Verify specific file
    let specific = db.with_reader(|conn| {
        files::get_file_metadata(conn, "src/components/Component_42.tsx")
    }).unwrap();
    assert!(specific.is_some());
    let meta = specific.unwrap();
    assert_eq!(meta.file_size, 1042);

    // Create a second batch writer for the delete test
    let batch_conn2 = db.open_batch_connection().unwrap();
    let batch_writer2 = BatchWriter::new(batch_conn2);

    let to_delete: Vec<String> = (0..100).map(|i| {
        format!("src/components/Component_{i}.tsx")
    }).collect();
    batch_writer2.send(BatchCommand::DeleteFileMetadata(to_delete)).unwrap();
    let stats2 = batch_writer2.shutdown().unwrap();
    assert_eq!(stats2.deleted_files, 100);

    let remaining = db.with_reader(files::load_all_file_metadata).unwrap();
    assert_eq!(remaining.len(), 900, "100 files should have been deleted");

    // Scan history round-trip
    let scan_id = db.with_writer(|conn| {
        scan_history::insert_scan_start(conn, 1700000000, "/project")
    }).unwrap();
    assert!(scan_id > 0);

    db.with_writer(|conn| {
        scan_history::update_scan_complete(conn, scan_id, 1700000010, 900, 900, 0, 0, 0, 10000, "completed", None)
    }).unwrap();

    let recent = db.with_reader(|conn| scan_history::query_recent(conn, 5)).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].total_files, Some(900));
}

// ─── 7. CONCURRENT READ/WRITE STRESS ────────────────────────────────

#[test]
fn stress_concurrent_reads_and_writes() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("concurrent.db");
    let db = Arc::new(DatabaseManager::open(&db_path).unwrap());

    // Pre-populate with some data
    db.with_writer(|conn| {
        for i in 0..100 {
            enforcement::insert_violation(conn, &enforcement::ViolationRow {
                id: format!("init-{i}"),
                file: "src/init.ts".to_string(),
                line: i as u32,
                column: None,
                end_line: None,
                end_column: None,
                severity: "medium".to_string(),
                pattern_id: "pat-init".to_string(),
                rule_id: "rule-init".to_string(),
                message: format!("Init violation {i}"),
                quick_fix_strategy: None,
                quick_fix_description: None,
                cwe_id: None,
                owasp_category: None,
                suppressed: false,
                is_new: false,
            })?;
        }
        Ok(())
    }).unwrap();

    let barrier = Arc::new(Barrier::new(9)); // 1 writer + 8 readers

    // Spawn 8 concurrent reader threads
    let mut handles = Vec::new();
    for t in 0..8 {
        let db_clone = db.clone();
        let barrier_clone = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier_clone.wait();
            let mut total_reads = 0;
            for _ in 0..50 {
                let violations = db_clone.with_reader(|conn| {
                    enforcement::query_all_violations(conn)
                }).unwrap();
                assert!(violations.len() >= 100, "reader {t} saw only {} violations", violations.len());
                total_reads += 1;
            }
            total_reads
        }));
    }

    // Writer thread adds more violations concurrently
    let db_writer = db.clone();
    let barrier_writer = barrier.clone();
    let writer_handle = thread::spawn(move || {
        barrier_writer.wait();
        for i in 0..200 {
            db_writer.with_writer(|conn| {
                enforcement::insert_violation(conn, &enforcement::ViolationRow {
                    id: format!("concurrent-{i}"),
                    file: "src/concurrent.ts".to_string(),
                    line: i as u32,
                    column: None,
                    end_line: None,
                    end_column: None,
                    severity: "low".to_string(),
                    pattern_id: "pat-conc".to_string(),
                    rule_id: "rule-conc".to_string(),
                    message: format!("Concurrent violation {i}"),
                    quick_fix_strategy: None,
                    quick_fix_description: None,
                    cwe_id: None,
                    owasp_category: None,
                    suppressed: false,
                    is_new: false,
                })
            }).unwrap();
        }
    });

    writer_handle.join().unwrap();
    for h in handles {
        let reads = h.join().unwrap();
        assert_eq!(reads, 50, "each reader should complete 50 reads");
    }

    // Final count should be 300
    let final_count = db.with_reader(|conn| {
        enforcement::query_all_violations(conn)
    }).unwrap();
    assert_eq!(final_count.len(), 300);
}

// ─── 8. EDGE CASES: Unicode, special chars, empty tables ────────────

#[test]
fn stress_edge_cases() {
    let (_dir, db) = setup();

    // Unicode in all text fields
    db.with_writer(|conn| {
        enforcement::insert_violation(conn, &enforcement::ViolationRow {
            id: "unicode-test-αβγ".to_string(),
            file: "src/日本語/ファイル.ts".to_string(),
            line: 1,
            column: None,
            end_line: None,
            end_column: None,
            severity: "high".to_string(),
            pattern_id: "pat-émojis-🦀".to_string(),
            rule_id: "rule-中文".to_string(),
            message: "违规: использование небезопасного кода — 🚨 alert".to_string(),
            quick_fix_strategy: None,
            quick_fix_description: None,
            cwe_id: Some(79),
            owasp_category: Some("A03:2021-注入".to_string()),
            suppressed: false,
            is_new: false,
        })
    }).unwrap();

    let v = db.with_reader(|conn| {
        enforcement::query_all_violations(conn)
    }).unwrap();
    assert_eq!(v.len(), 1);
    assert!(v[0].id.contains("αβγ"));
    assert!(v[0].message.contains("🚨"));

    // Empty tables return empty vecs, not errors
    let empty_gates = db.with_reader(enforcement::query_gate_results).unwrap();
    assert!(empty_gates.is_empty());

    let empty_conv = db.with_reader(patterns::query_all_conventions).unwrap();
    assert!(empty_conv.is_empty());

    let empty_genes = db.with_reader(structural::get_all_dna_genes).unwrap();
    assert!(empty_genes.is_empty());

    let empty_mutations = db.with_reader(structural::get_unresolved_mutations).unwrap();
    assert!(empty_mutations.is_empty());

    // Zero-count queries
    let fc = db.with_reader(functions::count_functions).unwrap();
    assert_eq!(fc, 0);
    let ec = db.with_reader(call_edges::count_call_edges).unwrap();
    assert_eq!(ec, 0);
    let dc = db.with_reader(detections::count_detections).unwrap();
    assert_eq!(dc, 0);

    // Very long strings (test SQLite handles them)
    let long_msg = "x".repeat(100_000);
    db.with_writer(|conn| {
        enforcement::insert_violation(conn, &enforcement::ViolationRow {
            id: "long-msg".to_string(),
            file: "x".repeat(5000),
            line: 1,
            column: None,
            end_line: None,
            end_column: None,
            severity: "low".to_string(),
            pattern_id: "pat".to_string(),
            rule_id: "rule".to_string(),
            message: long_msg.clone(),
            quick_fix_strategy: None,
            quick_fix_description: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        })
    }).unwrap();

    let v2 = db.with_reader(|conn| {
        enforcement::query_all_violations(conn)
    }).unwrap();
    let long_v = v2.iter().find(|v| v.id == "long-msg").unwrap();
    assert_eq!(long_v.message.len(), 100_000);

    // SQL injection attempt in data (should be stored literally, not executed)
    db.with_writer(|conn| {
        enforcement::insert_violation(conn, &enforcement::ViolationRow {
            id: "sqli-test".to_string(),
            file: "'; DROP TABLE violations; --".to_string(),
            line: 1,
            column: None,
            end_line: None,
            end_column: None,
            severity: "critical".to_string(),
            pattern_id: "pat".to_string(),
            rule_id: "rule".to_string(),
            message: "Robert'); DROP TABLE violations;--".to_string(),
            quick_fix_strategy: None,
            quick_fix_description: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        })
    }).unwrap();

    // Table should still exist and have all 3 rows
    let v3 = db.with_reader(enforcement::query_all_violations).unwrap();
    assert_eq!(v3.len(), 3, "SQL injection should not drop the table");
}

// ─── 9. ORPHAN TABLES: constants, env_variables, data_access ────────

#[test]
fn stress_orphan_tables() {
    let (_dir, db) = setup();

    // Constants
    db.with_writer(|conn| {
        for i in 0..50 {
            constants::insert(conn, &constants::ConstantRow {
                id: 0,
                name: if i % 5 == 0 { format!("{}", i * 42) } else { format!("MAX_RETRIES_{i}") },
                value: format!("{}", i * 42),
                file: format!("src/config_{}.ts", i % 5),
                line: i as i64,
                is_used: i % 3 != 0,
                language: "TypeScript".to_string(),
                is_named: i % 5 != 0,
                created_at: 0,
            })?;
        }
        Ok(())
    }).unwrap();

    let count = db.with_reader(constants::count).unwrap();
    assert_eq!(count, 50);

    let unused = db.with_reader(constants::query_unused).unwrap();
    assert!(!unused.is_empty());

    let magic = db.with_reader(constants::query_magic_numbers).unwrap();
    assert!(!magic.is_empty());

    // Env variables
    db.with_writer(|conn| {
        for i in 0..30 {
            env_variables::insert(conn, &env_variables::EnvVariableRow {
                id: 0,
                name: format!("DB_HOST_{i}"),
                file: format!("src/config_{}.ts", i % 3),
                line: i as i64,
                access_method: "process.env".to_string(),
                has_default: i % 2 == 0,
                defined_in_env: i % 3 == 0,
                framework_prefix: None,
                created_at: 0,
            })?;
        }
        Ok(())
    }).unwrap();

    let missing = db.with_reader(env_variables::query_missing).unwrap();
    // Missing = not defined_in_env AND no default
    assert!(!missing.is_empty());

    let by_name = db.with_reader(|conn| {
        env_variables::query_by_name(conn, "DB_HOST_0")
    }).unwrap();
    assert_eq!(by_name.len(), 1);

    // Data access
    db.with_writer(|conn| {
        for i in 0..20 {
            data_access::insert(conn, &data_access::DataAccessRow {
                function_id: (i + 1) as i64,
                table_name: "users".to_string(),
                operation: match i % 3 { 0 => "SELECT", 1 => "INSERT", _ => "UPDATE" }.to_string(),
                framework: Some("prisma".to_string()),
                line: i as i64,
                confidence: 0.95,
            })?;
        }
        Ok(())
    }).unwrap();

    let da_count = db.with_reader(data_access::count).unwrap();
    assert_eq!(da_count, 20);

    let by_table = db.with_reader(|conn| data_access::query_by_table(conn, "users")).unwrap();
    assert_eq!(by_table.len(), 20);
}

// ─── 10. CHECKPOINT + WAL STRESS ────────────────────────────────────

#[test]
fn stress_wal_checkpoint() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("wal_stress.db");
    let db = DatabaseManager::open(&db_path).unwrap();

    // Write a bunch of data to grow the WAL
    db.with_writer(|conn| {
        for i in 0..500 {
            enforcement::insert_violation(conn, &enforcement::ViolationRow {
                id: format!("wal-{i}"),
                file: format!("src/wal_{i}.ts"),
                line: i as u32,
                column: None,
                end_line: None,
                end_column: None,
                severity: "low".to_string(),
                pattern_id: "pat".to_string(),
                rule_id: "rule".to_string(),
                message: format!("WAL test {i}"),
                quick_fix_strategy: None,
                quick_fix_description: None,
                cwe_id: None,
                owasp_category: None,
                suppressed: false,
                is_new: false,
            })?;
        }
        Ok(())
    }).unwrap();

    // Checkpoint should not error
    db.checkpoint().unwrap();

    // Data should still be accessible after checkpoint
    let count = db.with_reader(enforcement::query_all_violations).unwrap();
    assert_eq!(count.len(), 500);

    // Write more after checkpoint
    db.with_writer(|conn| {
        enforcement::insert_violation(conn, &enforcement::ViolationRow {
            id: "post-checkpoint".to_string(),
            file: "src/post.ts".to_string(),
            line: 1,
            column: None,
            end_line: None,
            end_column: None,
            severity: "high".to_string(),
            pattern_id: "pat".to_string(),
            rule_id: "rule".to_string(),
            message: "After checkpoint".to_string(),
            quick_fix_strategy: None,
            quick_fix_description: None,
            cwe_id: None,
            owasp_category: None,
            suppressed: false,
            is_new: false,
        })
    }).unwrap();

    let count2 = db.with_reader(enforcement::query_all_violations).unwrap();
    assert_eq!(count2.len(), 501);
}

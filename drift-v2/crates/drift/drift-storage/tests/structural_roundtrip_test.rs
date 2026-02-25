//! Roundtrip tests for all 13 entity types in structural.rs (37 pub fns).
//! Every write→read path is verified to catch column-mapping bugs.

use drift_storage::migrations::run_migrations;
use drift_storage::queries::structural::*;
use rusqlite::Connection;

fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    run_migrations(&conn).unwrap();
    conn
}

// ═══════════════════════════════════════════════════════════════════════════
// COUPLING METRICS (4 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn coupling_metrics_upsert_and_get() {
    let conn = setup_db();
    let row = CouplingMetricsRow {
        module: "src/auth".to_string(),
        ce: 5,
        ca: 3,
        instability: 0.625,
        abstractness: 0.2,
        distance: 0.175,
        zone: "main_sequence".to_string(),
    };
    upsert_coupling_metrics(&conn, &row).unwrap();

    let result = get_coupling_metrics(&conn, "src/auth").unwrap().unwrap();
    assert_eq!(result.module, "src/auth");
    assert_eq!(result.ce, 5);
    assert_eq!(result.ca, 3);
    assert!((result.instability - 0.625).abs() < 0.001);
    assert!((result.abstractness - 0.2).abs() < 0.001);
    assert!((result.distance - 0.175).abs() < 0.001);
    assert_eq!(result.zone, "main_sequence");
}

#[test]
fn coupling_metrics_upsert_overwrites() {
    let conn = setup_db();
    let row = CouplingMetricsRow {
        module: "src/db".to_string(),
        ce: 1, ca: 1, instability: 0.5, abstractness: 0.5,
        distance: 0.0, zone: "main_sequence".to_string(),
    };
    upsert_coupling_metrics(&conn, &row).unwrap();

    let row2 = CouplingMetricsRow { ce: 10, zone: "zone_of_pain".to_string(), ..row };
    upsert_coupling_metrics(&conn, &row2).unwrap();

    let result = get_coupling_metrics(&conn, "src/db").unwrap().unwrap();
    assert_eq!(result.ce, 10);
    assert_eq!(result.zone, "zone_of_pain");
}

#[test]
fn coupling_metrics_get_all() {
    let conn = setup_db();
    for i in 0..3 {
        upsert_coupling_metrics(&conn, &CouplingMetricsRow {
            module: format!("mod-{i}"),
            ce: i, ca: i, instability: 0.5, abstractness: 0.5,
            distance: i as f64 * 0.1, zone: "main_sequence".to_string(),
        }).unwrap();
    }
    let all = get_all_coupling_metrics(&conn).unwrap();
    assert_eq!(all.len(), 3);
}

#[test]
fn coupling_metrics_by_zone() {
    let conn = setup_db();
    upsert_coupling_metrics(&conn, &CouplingMetricsRow {
        module: "a".into(), ce: 1, ca: 1, instability: 0.5, abstractness: 0.5,
        distance: 0.0, zone: "main_sequence".into(),
    }).unwrap();
    upsert_coupling_metrics(&conn, &CouplingMetricsRow {
        module: "b".into(), ce: 1, ca: 1, instability: 0.5, abstractness: 0.5,
        distance: 0.7, zone: "zone_of_pain".into(),
    }).unwrap();

    let pain = get_coupling_metrics_by_zone(&conn, "zone_of_pain").unwrap();
    assert_eq!(pain.len(), 1);
    assert_eq!(pain[0].module, "b");
}

#[test]
fn coupling_metrics_nonexistent_returns_none() {
    let conn = setup_db();
    assert!(get_coupling_metrics(&conn, "nope").unwrap().is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTRAINTS (3 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn constraint_upsert_and_get() {
    let conn = setup_db();
    let row = ConstraintRow {
        id: "no-circular-deps".to_string(),
        description: "No circular dependencies allowed".to_string(),
        invariant_type: "dependency".to_string(),
        target: "src/**".to_string(),
        scope: Some("project".to_string()),
        source: "manual".to_string(),
        enabled: true,
    };
    upsert_constraint(&conn, &row).unwrap();

    let result = get_constraint(&conn, "no-circular-deps").unwrap().unwrap();
    assert_eq!(result.description, "No circular dependencies allowed");
    assert_eq!(result.invariant_type, "dependency");
    assert_eq!(result.scope, Some("project".to_string()));
    assert!(result.enabled);
}

#[test]
fn constraint_get_enabled_only() {
    let conn = setup_db();
    upsert_constraint(&conn, &ConstraintRow {
        id: "c1".into(), description: "enabled".into(), invariant_type: "dep".into(),
        target: "*".into(), scope: None, source: "auto".into(), enabled: true,
    }).unwrap();
    upsert_constraint(&conn, &ConstraintRow {
        id: "c2".into(), description: "disabled".into(), invariant_type: "dep".into(),
        target: "*".into(), scope: None, source: "auto".into(), enabled: false,
    }).unwrap();

    let enabled = get_enabled_constraints(&conn).unwrap();
    assert_eq!(enabled.len(), 1);
    assert_eq!(enabled[0].id, "c1");
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTRAINT VERIFICATIONS (2 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn constraint_verification_roundtrip() {
    let conn = setup_db();
    // Need parent constraint first (FK)
    upsert_constraint(&conn, &ConstraintRow {
        id: "cv-parent".into(), description: "parent".into(), invariant_type: "dep".into(),
        target: "*".into(), scope: None, source: "auto".into(), enabled: true,
    }).unwrap();

    insert_constraint_verification(&conn, "cv-parent", true, "[]").unwrap();
    insert_constraint_verification(&conn, "cv-parent", false, r#"["violation1"]"#).unwrap();

    let results = query_constraint_verifications(&conn, "cv-parent").unwrap();
    assert_eq!(results.len(), 2);
    let passed_count = results.iter().filter(|r| r.passed).count();
    let failed_count = results.iter().filter(|r| !r.passed).count();
    assert_eq!(passed_count, 1);
    assert_eq!(failed_count, 1);
    let failed = results.iter().find(|r| !r.passed).unwrap();
    assert!(failed.violations.contains("violation1"));
}

// ═══════════════════════════════════════════════════════════════════════════
// CONTRACTS (3 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn contract_upsert_and_get() {
    let conn = setup_db();
    let row = ContractRow {
        id: "express-auth".to_string(),
        paradigm: "rest".to_string(),
        source_file: "src/routes/auth.ts".to_string(),
        framework: "express".to_string(),
        confidence: 0.92,
        endpoints: r#"[{"method":"POST","path":"/login"}]"#.to_string(),
    };
    upsert_contract(&conn, &row).unwrap();

    let result = get_contract(&conn, "express-auth").unwrap().unwrap();
    assert_eq!(result.paradigm, "rest");
    assert_eq!(result.source_file, "src/routes/auth.ts");
    assert!((result.confidence - 0.92).abs() < 0.001);
    assert!(result.endpoints.contains("/login"));
}

#[test]
fn contracts_by_paradigm() {
    let conn = setup_db();
    upsert_contract(&conn, &ContractRow {
        id: "r1".into(), paradigm: "rest".into(), source_file: "a.ts".into(),
        framework: "express".into(), confidence: 0.9, endpoints: "[]".into(),
    }).unwrap();
    upsert_contract(&conn, &ContractRow {
        id: "g1".into(), paradigm: "graphql".into(), source_file: "b.ts".into(),
        framework: "apollo".into(), confidence: 0.8, endpoints: "[]".into(),
    }).unwrap();

    let rest = get_contracts_by_paradigm(&conn, "rest").unwrap();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].id, "r1");
}

// ═══════════════════════════════════════════════════════════════════════════
// CONTRACT MISMATCHES (3 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn contract_mismatch_roundtrip() {
    let conn = setup_db();
    let row = ContractMismatchRow {
        id: 0, // auto-assigned
        backend_endpoint: "POST /api/users".to_string(),
        frontend_call: "fetch('/api/user')".to_string(),
        mismatch_type: "PathMismatch".to_string(),
        severity: "warning".to_string(),
        message: "Singular vs plural path".to_string(),
        created_at: 0,
    };
    insert_contract_mismatch(&conn, &row).unwrap();

    let all = query_contract_mismatches(&conn).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].backend_endpoint, "POST /api/users");
    assert_eq!(all[0].mismatch_type, "PathMismatch");
}

#[test]
fn contract_mismatches_by_type() {
    let conn = setup_db();
    for (i, mtype) in ["PathMismatch", "MethodMismatch", "PathMismatch"].iter().enumerate() {
        insert_contract_mismatch(&conn, &ContractMismatchRow {
            id: 0, backend_endpoint: format!("ep-{i}"), frontend_call: format!("fc-{i}"),
            mismatch_type: mtype.to_string(), severity: "warning".into(),
            message: "msg".into(), created_at: 0,
        }).unwrap();
    }
    let path = query_contract_mismatches_by_type(&conn, "PathMismatch").unwrap();
    assert_eq!(path.len(), 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// SECRETS (3 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn secret_insert_and_query_by_file() {
    let conn = setup_db();
    let row = SecretRow {
        id: None,
        pattern_name: "aws_key".to_string(),
        redacted_value: "AKIA****".to_string(),
        file: "src/config.ts".to_string(),
        line: 10,
        severity: "critical".to_string(),
        entropy: 4.5,
        confidence: 0.95,
        cwe_ids: "[798]".to_string(),
    };
    let id = insert_secret(&conn, &row).unwrap();
    assert!(id > 0);

    let results = get_secrets_by_file(&conn, "src/config.ts").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].pattern_name, "aws_key");
    assert_eq!(results[0].redacted_value, "AKIA****");
    assert!((results[0].entropy - 4.5).abs() < 0.001);
}

#[test]
fn secrets_by_severity() {
    let conn = setup_db();
    insert_secret(&conn, &SecretRow {
        id: None, pattern_name: "p1".into(), redacted_value: "***".into(),
        file: "a.ts".into(), line: 1, severity: "critical".into(),
        entropy: 3.0, confidence: 0.9, cwe_ids: "[]".into(),
    }).unwrap();
    insert_secret(&conn, &SecretRow {
        id: None, pattern_name: "p2".into(), redacted_value: "***".into(),
        file: "b.ts".into(), line: 1, severity: "warning".into(),
        entropy: 2.0, confidence: 0.7, cwe_ids: "[]".into(),
    }).unwrap();

    let critical = get_secrets_by_severity(&conn, "critical").unwrap();
    assert_eq!(critical.len(), 1);
    assert_eq!(critical[0].pattern_name, "p1");
}

// ═══════════════════════════════════════════════════════════════════════════
// WRAPPERS (3 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn wrapper_insert_and_query_by_file() {
    let conn = setup_db();
    let row = WrapperRow {
        id: None,
        name: "useAuth".to_string(),
        file: "src/hooks/auth.ts".to_string(),
        line: 5,
        category: "hook".to_string(),
        wrapped_primitives: r#"["useState","useEffect"]"#.to_string(),
        framework: "react".to_string(),
        confidence: 0.85,
        is_multi_primitive: true,
        is_exported: true,
        usage_count: 12,
    };
    let id = insert_wrapper(&conn, &row).unwrap();
    assert!(id > 0);

    let results = get_wrappers_by_file(&conn, "src/hooks/auth.ts").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "useAuth");
    assert!(results[0].is_multi_primitive);
    assert!(results[0].is_exported);
    assert_eq!(results[0].usage_count, 12);
}

#[test]
fn wrappers_by_category() {
    let conn = setup_db();
    insert_wrapper(&conn, &WrapperRow {
        id: None, name: "w1".into(), file: "a.ts".into(), line: 1,
        category: "hook".into(), wrapped_primitives: "[]".into(),
        framework: "react".into(), confidence: 0.9,
        is_multi_primitive: false, is_exported: true, usage_count: 1,
    }).unwrap();
    insert_wrapper(&conn, &WrapperRow {
        id: None, name: "w2".into(), file: "b.ts".into(), line: 1,
        category: "utility".into(), wrapped_primitives: "[]".into(),
        framework: "node".into(), confidence: 0.8,
        is_multi_primitive: false, is_exported: false, usage_count: 5,
    }).unwrap();

    let hooks = get_wrappers_by_category(&conn, "hook").unwrap();
    assert_eq!(hooks.len(), 1);
    assert_eq!(hooks[0].name, "w1");
}

// ═══════════════════════════════════════════════════════════════════════════
// DNA GENES (3 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn dna_gene_upsert_and_get() {
    let conn = setup_db();
    let row = DnaGeneRow {
        gene_id: "naming-convention".to_string(),
        name: "Naming Convention".to_string(),
        description: "camelCase for variables".to_string(),
        dominant_allele: Some(r#"{"style":"camelCase"}"#.to_string()),
        alleles: r#"["camelCase","snake_case"]"#.to_string(),
        confidence: 0.95,
        consistency: 0.88,
        exemplars: r#"["src/utils.ts:5"]"#.to_string(),
    };
    upsert_dna_gene(&conn, &row).unwrap();

    let result = get_dna_gene(&conn, "naming-convention").unwrap().unwrap();
    assert_eq!(result.name, "Naming Convention");
    assert!(result.dominant_allele.as_ref().unwrap().contains("camelCase"));
    assert!((result.confidence - 0.95).abs() < 0.001);
    assert!((result.consistency - 0.88).abs() < 0.001);
}

#[test]
fn dna_genes_get_all() {
    let conn = setup_db();
    for i in 0..3 {
        upsert_dna_gene(&conn, &DnaGeneRow {
            gene_id: format!("gene-{i}"), name: format!("Gene {i}"),
            description: "desc".into(), dominant_allele: None,
            alleles: "[]".into(), confidence: 0.5, consistency: 0.5,
            exemplars: "[]".into(),
        }).unwrap();
    }
    assert_eq!(get_all_dna_genes(&conn).unwrap().len(), 3);
}

// ═══════════════════════════════════════════════════════════════════════════
// DNA MUTATIONS (3 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn dna_mutation_upsert_and_query_by_gene() {
    let conn = setup_db();
    let row = DnaMutationRow {
        id: "mut-1".to_string(),
        file: "src/auth.ts".to_string(),
        line: 42,
        gene_id: "naming".to_string(),
        expected: "camelCase".to_string(),
        actual: "snake_case".to_string(),
        impact: "style".to_string(),
        code: "let user_name = ...".to_string(),
        suggestion: "Rename to userName".to_string(),
        detected_at: 1700000000,
        resolved: false,
        resolved_at: None,
    };
    upsert_dna_mutation(&conn, &row).unwrap();

    let results = get_dna_mutations_by_gene(&conn, "naming").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].expected, "camelCase");
    assert_eq!(results[0].actual, "snake_case");
    assert!(!results[0].resolved);
}

#[test]
fn dna_mutations_unresolved() {
    let conn = setup_db();
    upsert_dna_mutation(&conn, &DnaMutationRow {
        id: "m1".into(), file: "a.ts".into(), line: 1, gene_id: "g1".into(),
        expected: "a".into(), actual: "b".into(), impact: "style".into(),
        code: "x".into(), suggestion: "y".into(), detected_at: 1700000000,
        resolved: false, resolved_at: None,
    }).unwrap();
    upsert_dna_mutation(&conn, &DnaMutationRow {
        id: "m2".into(), file: "b.ts".into(), line: 1, gene_id: "g1".into(),
        expected: "a".into(), actual: "b".into(), impact: "style".into(),
        code: "x".into(), suggestion: "y".into(), detected_at: 1700000000,
        resolved: true, resolved_at: Some(1700000100),
    }).unwrap();

    let unresolved = get_unresolved_mutations(&conn).unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].id, "m1");
}

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO FINDINGS (3 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn crypto_finding_insert_and_query_by_file() {
    let conn = setup_db();
    let row = CryptoFindingRow {
        id: None,
        file: "src/crypto.ts".to_string(),
        line: 15,
        category: "weak_cipher".to_string(),
        description: "DES is deprecated".to_string(),
        code: "crypto.createCipher('des', key)".to_string(),
        confidence: 0.98,
        cwe_id: 327,
        owasp: "A02:2021".to_string(),
        remediation: "Use AES-256-GCM".to_string(),
        language: "typescript".to_string(),
    };
    let id = insert_crypto_finding(&conn, &row).unwrap();
    assert!(id > 0);

    let results = get_crypto_findings_by_file(&conn, "src/crypto.ts").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].category, "weak_cipher");
    assert_eq!(results[0].cwe_id, 327);
}

#[test]
fn crypto_findings_by_category() {
    let conn = setup_db();
    insert_crypto_finding(&conn, &CryptoFindingRow {
        id: None, file: "a.ts".into(), line: 1, category: "weak_cipher".into(),
        description: "d".into(), code: "c".into(), confidence: 0.9,
        cwe_id: 327, owasp: "A02".into(), remediation: "fix".into(), language: "ts".into(),
    }).unwrap();
    insert_crypto_finding(&conn, &CryptoFindingRow {
        id: None, file: "b.ts".into(), line: 1, category: "weak_hash".into(),
        description: "d".into(), code: "c".into(), confidence: 0.8,
        cwe_id: 328, owasp: "A02".into(), remediation: "fix".into(), language: "ts".into(),
    }).unwrap();

    let weak = get_crypto_findings_by_category(&conn, "weak_cipher").unwrap();
    assert_eq!(weak.len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// OWASP FINDINGS (3 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn owasp_finding_upsert_and_query_by_file() {
    let conn = setup_db();
    let row = OwaspFindingRow {
        id: "owasp-1".to_string(),
        detector: "xss-detector".to_string(),
        file: "src/render.ts".to_string(),
        line: 25,
        description: "Reflected XSS".to_string(),
        severity: 0.9,
        cwes: "[79]".to_string(),
        owasp_categories: r#"["A03:2021"]"#.to_string(),
        confidence: 0.85,
        remediation: Some("Use DOMPurify".to_string()),
    };
    upsert_owasp_finding(&conn, &row).unwrap();

    let results = get_owasp_findings_by_file(&conn, "src/render.ts").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].detector, "xss-detector");
    assert!((results[0].severity - 0.9).abs() < 0.001);
    assert!(results[0].remediation.as_ref().unwrap().contains("DOMPurify"));
}

#[test]
fn owasp_findings_by_detector() {
    let conn = setup_db();
    upsert_owasp_finding(&conn, &OwaspFindingRow {
        id: "o1".into(), detector: "xss".into(), file: "a.ts".into(), line: 1,
        description: "d".into(), severity: 0.8, cwes: "[]".into(),
        owasp_categories: "[]".into(), confidence: 0.9, remediation: None,
    }).unwrap();
    upsert_owasp_finding(&conn, &OwaspFindingRow {
        id: "o2".into(), detector: "sqli".into(), file: "b.ts".into(), line: 1,
        description: "d".into(), severity: 0.9, cwes: "[]".into(),
        owasp_categories: "[]".into(), confidence: 0.8, remediation: None,
    }).unwrap();

    let xss = get_owasp_findings_by_detector(&conn, "xss").unwrap();
    assert_eq!(xss.len(), 1);
    assert_eq!(xss[0].id, "o1");
}

// ═══════════════════════════════════════════════════════════════════════════
// DECOMPOSITION DECISIONS (2 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn decomposition_decision_roundtrip() {
    let conn = setup_db();
    let row = DecompositionDecisionRow {
        id: None,
        dna_profile_hash: "abc123".to_string(),
        adjustment: r#"{"weight":1.2}"#.to_string(),
        confidence: 0.75,
        dna_similarity: 0.88,
        narrative: "Similar to project X".to_string(),
        source_dna_hash: "def456".to_string(),
        applied_weight: 1.2,
    };
    let id = insert_decomposition_decision(&conn, &row).unwrap();
    assert!(id > 0);

    let results = get_decomposition_decisions(&conn, "abc123").unwrap();
    assert_eq!(results.len(), 1);
    assert!((results[0].confidence - 0.75).abs() < 0.001);
    assert!((results[0].dna_similarity - 0.88).abs() < 0.001);
    assert_eq!(results[0].narrative, "Similar to project X");
}

// ═══════════════════════════════════════════════════════════════════════════
// COUPLING CYCLES (2 fns)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn coupling_cycle_roundtrip() {
    let conn = setup_db();
    insert_coupling_cycle(&conn, r#"["a","b","c"]"#, r#"["remove a->b"]"#).unwrap();
    insert_coupling_cycle(&conn, r#"["x","y"]"#, r#"["remove x->y"]"#).unwrap();

    let cycles = query_coupling_cycles(&conn).unwrap();
    assert_eq!(cycles.len(), 2);
    assert!(cycles[0].members.contains('x') || cycles[1].members.contains('x'));
}

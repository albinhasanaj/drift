//! NAPI bindings for all 9 structural intelligence systems (Phase 5).
//!
//! Exposes coupling, constraints, contracts, constants, wrappers, DNA,
//! OWASP/CWE, crypto, and decomposition analysis to TypeScript/JavaScript.

#[allow(unused_imports)]
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::{Deserialize, Serialize};

use crate::conversions::error_codes;
use crate::runtime;

fn storage_err(e: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR))
}

/// Check if a file path belongs to a test, benchmark, or fixture directory.
fn is_test_or_fixture_file(path: &str) -> bool {
    let p = path.replace('\\', "/");
    // Suffix-based patterns: *_test.ext, *.test.ext, *.spec.ext (all languages)
    let lower = p.to_lowercase();
    if lower.ends_with("_test.rs") || lower.ends_with("_test.ts") || lower.ends_with("_test.js")
        || lower.ends_with("_test.py") || lower.ends_with("_test.go") || lower.ends_with("_test.java")
        || lower.ends_with("_test.rb") || lower.ends_with("_test.kt") || lower.ends_with("_test.cs")
        || lower.ends_with("_test.php")
    {
        return true;
    }
    if lower.ends_with(".test.ts") || lower.ends_with(".test.js") || lower.ends_with(".test.tsx")
        || lower.ends_with(".test.jsx") || lower.ends_with(".spec.ts") || lower.ends_with(".spec.js")
        || lower.ends_with(".spec.tsx") || lower.ends_with(".spec.jsx")
    {
        return true;
    }
    // Test runner config files
    if let Some(filename) = p.rsplit('/').next() {
        let fl = filename.to_lowercase();
        if fl.starts_with("vitest") || fl.starts_with("jest.config")
            || fl.starts_with("karma.conf") || fl.starts_with("cypress.config")
            || fl.starts_with("playwright.config") || fl.starts_with("pytest.ini")
            || fl.starts_with("setup.test") || fl.starts_with("setuptest")
            || fl == "conftest.py"
        {
            return true;
        }
    }
    // Directory-based patterns
    let segments: Vec<&str> = p.split('/').collect();
    segments.iter().any(|s| {
        *s == "tests" || *s == "test" || *s == "benches" || *s == "benchmarks"
            || *s == "test-fixtures" || *s == "__tests__" || *s == "__mocks__"
            || *s == "fixtures" || *s == "testdata" || *s == "e2e"
            || *s == "cypress" || *s == "playwright"
    })
}

// ─── Coupling Analysis ───────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCouplingMetrics {
    pub module: String,
    pub ce: u32,
    pub ca: u32,
    pub instability: f64,
    pub abstractness: f64,
    pub distance: f64,
    pub zone: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCycleInfo {
    pub members: Vec<String>,
    pub break_suggestion_count: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCouplingResult {
    pub metrics: Vec<JsCouplingMetrics>,
    pub cycles: Vec<JsCycleInfo>,
    pub module_count: u32,
}

#[napi]
pub fn drift_coupling_analysis(_root: String) -> napi::Result<JsCouplingResult> {
    let rt = runtime::get()?;

    let rows = rt.storage.with_reader(|conn| {
        drift_storage::queries::structural::get_all_coupling_metrics(conn)
    }).map_err(storage_err)?;

    let cycles = rt.storage.with_reader(|conn| {
        drift_storage::queries::structural::query_coupling_cycles(conn)
    }).map_err(storage_err)?;

    let metrics: Vec<JsCouplingMetrics> = rows.iter().map(|r| JsCouplingMetrics {
        module: r.module.clone(),
        ce: r.ce,
        ca: r.ca,
        instability: r.instability,
        abstractness: r.abstractness,
        distance: r.distance,
        zone: r.zone.clone(),
    }).collect();

    let js_cycles: Vec<JsCycleInfo> = cycles.iter().map(|c| {
        let members: Vec<String> = serde_json::from_str(&c.members).unwrap_or_default();
        let suggestions: Vec<serde_json::Value> = serde_json::from_str(&c.break_suggestions).unwrap_or_default();
        JsCycleInfo {
            members,
            break_suggestion_count: suggestions.len() as u32,
        }
    }).collect();

    let module_count = metrics.len() as u32;

    Ok(JsCouplingResult { metrics, cycles: js_cycles, module_count })
}

// ─── Constraint System ───────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsConstraintViolation {
    pub constraint_id: String,
    pub file: String,
    pub line: Option<u32>,
    pub message: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsConstraintResult {
    pub total_constraints: u32,
    pub passing: u32,
    pub failing: u32,
    pub violations: Vec<JsConstraintViolation>,
}

#[napi]
pub fn drift_constraint_verification(_root: String) -> napi::Result<JsConstraintResult> {
    let rt = runtime::get()?;

    let constraints = rt.storage.with_reader(|conn| {
        drift_storage::queries::structural::get_enabled_constraints(conn)
    }).map_err(storage_err)?;

    // Query verifications for each constraint
    let mut all_violations = Vec::new();
    let mut passing = 0u32;
    for c in &constraints {
        let verifications = rt.storage.with_reader(|conn| {
            drift_storage::queries::structural::query_constraint_verifications(conn, &c.id)
        }).map_err(storage_err)?;
        for v in &verifications {
            if v.passed {
                passing += 1;
            } else {
                all_violations.push(JsConstraintViolation {
                    constraint_id: v.constraint_id.clone(),
                    file: String::new(),
                    line: None,
                    message: v.violations.clone(),
                });
            }
        }
    }
    let failing = all_violations.len() as u32;

    Ok(JsConstraintResult {
        total_constraints: constraints.len() as u32,
        passing,
        failing,
        violations: all_violations,
    })
}

// ─── Contract Tracking ───────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsFieldSpec {
    pub name: String,
    pub field_type: String,
    pub required: bool,
    pub nullable: bool,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsEndpoint {
    pub method: String,
    pub path: String,
    pub file: String,
    pub line: u32,
    pub framework: String,
    pub request_fields: Vec<JsFieldSpec>,
    pub response_fields: Vec<JsFieldSpec>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsContractMismatch {
    pub backend_endpoint: String,
    pub frontend_call: String,
    pub mismatch_type: String,
    pub severity: String,
    pub message: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsContractResult {
    pub endpoints: Vec<JsEndpoint>,
    pub mismatches: Vec<JsContractMismatch>,
    pub paradigm_count: u32,
    pub framework_count: u32,
}

#[napi]
pub fn drift_contract_tracking(root: String) -> napi::Result<JsContractResult> {
    use drift_analysis::structural::contracts::extractors::ExtractorRegistry;
    use drift_analysis::parsers::ParserManager;
    use std::collections::HashSet;

    let registry = ExtractorRegistry::new();
    let parser_manager = ParserManager::new();
    let mut js_endpoints = Vec::new();
    let mut frameworks = HashSet::new();

    // Walk source files in root and extract endpoints.
    let source_extensions = [
        "ts", "tsx", "js", "jsx", "mjs", "cjs",
        "py", "rb", "java", "kt", "cs",
        "go", "rs", "php",
    ];

    use drift_analysis::structural::contracts::matching::match_contracts;
    use drift_analysis::structural::contracts::types::Endpoint;

    let mut all_endpoints: Vec<(String, Endpoint)> = Vec::new();

    if let Ok(walker) = walk_source_files(&root, &source_extensions) {
        for file_path in walker {
            // Skip test/fixture files — they contain embedded code samples
            // that produce false-positive endpoint detections.
            if is_test_or_fixture_file(&file_path) {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&file_path) {
                // CT-FIX-01: Parse file to get ParseResult for field extraction.
                let parse_result = parser_manager
                    .parse(content.as_bytes(), std::path::Path::new(&file_path))
                    .ok();
                // CT-FIX-02: Call extract_all_with_context so extractors can
                // populate request_fields and response_fields from ParseResult.
                let results = registry.extract_all_with_context(
                    &content,
                    &file_path,
                    parse_result.as_ref(),
                );
                for (framework, endpoints) in results {
                    frameworks.insert(framework.clone());
                    for ep in &endpoints {
                        js_endpoints.push(JsEndpoint {
                            method: ep.method.clone(),
                            path: ep.path.clone(),
                            file: ep.file.clone(),
                            line: ep.line,
                            framework: framework.clone(),
                            request_fields: ep.request_fields.iter().map(|f| JsFieldSpec {
                                name: f.name.clone(),
                                field_type: f.field_type.clone(),
                                required: f.required,
                                nullable: f.nullable,
                            }).collect(),
                            response_fields: ep.response_fields.iter().map(|f| JsFieldSpec {
                                name: f.name.clone(),
                                field_type: f.field_type.clone(),
                                required: f.required,
                                nullable: f.nullable,
                            }).collect(),
                        });
                    }
                    for ep in endpoints {
                        all_endpoints.push((framework.clone(), ep));
                    }
                }
            }
        }
    }

    // CE-E-01: Run BE↔FE matching to detect mismatches.
    let backend_frameworks = ["express", "fastify", "nestjs", "spring", "flask", "django", "rails", "laravel", "gin", "actix", "aspnet", "nextjs"];
    let frontend_frameworks = ["frontend"];
    let backend_eps: Vec<Endpoint> = all_endpoints.iter()
        .filter(|(fw, _)| backend_frameworks.contains(&fw.as_str()))
        .map(|(_, ep)| ep.clone())
        .collect();
    let frontend_eps: Vec<Endpoint> = all_endpoints.iter()
        .filter(|(fw, _)| frontend_frameworks.contains(&fw.as_str()))
        .map(|(_, ep)| ep.clone())
        .collect();

    let contract_matches = match_contracts(&backend_eps, &frontend_eps);
    let js_mismatches: Vec<JsContractMismatch> = contract_matches.iter()
        .flat_map(|m| m.mismatches.iter().map(|mm| JsContractMismatch {
            backend_endpoint: mm.backend_endpoint.clone(),
            frontend_call: mm.frontend_call.clone(),
            mismatch_type: format!("{:?}", mm.mismatch_type),
            severity: format!("{:?}", mm.severity),
            message: mm.message.clone(),
        }))
        .collect();

    Ok(JsContractResult {
        endpoints: js_endpoints,
        mismatches: js_mismatches,
        // CT-EDGE-02: Count distinct paradigms (REST, GraphQL, gRPC, etc.)
        paradigm_count: count_paradigms(&frameworks),
        framework_count: frameworks.len() as u32,
    })
}

/// Walk source files under a root directory, returning paths matching given extensions.
fn walk_source_files(root: &str, extensions: &[&str]) -> std::io::Result<Vec<String>> {
    let mut files = Vec::new();
    walk_dir_recursive(std::path::Path::new(root), extensions, &mut files)?;
    Ok(files)
}

fn walk_dir_recursive(
    dir: &std::path::Path,
    extensions: &[&str],
    files: &mut Vec<String>,
) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    // Skip common non-source directories.
    if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
        if matches!(name, "node_modules" | ".git" | "target" | "dist" | "build" | ".next" | "__pycache__") {
            return Ok(());
        }
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir_recursive(&path, extensions, files)?;
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if extensions.contains(&ext) {
                if let Some(p) = path.to_str() {
                    files.push(p.to_string());
                }
            }
        }
    }
    Ok(())
}

/// CT-EDGE-02: Count distinct paradigms from detected frameworks.
fn count_paradigms(frameworks: &std::collections::HashSet<String>) -> u32 {
    if frameworks.is_empty() {
        return 0;
    }
    let mut paradigms = std::collections::HashSet::new();
    for fw in frameworks {
        match fw.as_str() {
            "express" | "fastify" | "nestjs" | "spring" | "flask" | "django"
            | "rails" | "laravel" | "gin" | "actix" | "aspnet" | "nextjs" => {
                paradigms.insert("rest");
            }
            "trpc" => { paradigms.insert("rpc"); }
            "frontend" => { paradigms.insert("frontend"); }
            _ => { paradigms.insert("other"); }
        }
    }
    paradigms.len() as u32
}

// ─── Constants & Secrets ─────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsSecret {
    pub pattern_name: String,
    pub file: String,
    pub line: u32,
    pub severity: String,
    pub confidence: f64,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsMagicNumber {
    pub value: String,
    pub file: String,
    pub line: u32,
    pub suggested_name: Option<String>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsConstantsResult {
    pub constant_count: u32,
    pub secrets: Vec<JsSecret>,
    pub magic_numbers: Vec<JsMagicNumber>,
    pub missing_env_vars: Vec<String>,
    pub dead_constant_count: u32,
}

#[napi]
pub fn drift_constants_analysis(_root: String) -> napi::Result<JsConstantsResult> {
    let rt = runtime::get()?;

    let constant_count = rt.storage.with_reader(|conn| {
        drift_storage::queries::constants::count(conn)
    }).map_err(storage_err)? as u32;

    let secrets = rt.storage.with_reader(|conn| {
        drift_storage::queries::structural::get_secrets_by_severity(conn, "critical")
    }).map_err(storage_err)?;

    let js_secrets: Vec<JsSecret> = secrets.iter().map(|s| JsSecret {
        pattern_name: s.pattern_name.clone(),
        file: s.file.clone(),
        line: s.line,
        severity: s.severity.clone(),
        confidence: s.confidence,
    }).collect();

    let magic_numbers = rt.storage.with_reader(|conn| {
        drift_storage::queries::constants::query_magic_numbers(conn)
    }).map_err(storage_err)?;

    let js_magic: Vec<JsMagicNumber> = magic_numbers.iter().map(|m| JsMagicNumber {
        value: m.name.clone(),
        file: m.file.clone(),
        line: m.line as u32,
        suggested_name: None,
    }).collect();

    let missing_env = rt.storage.with_reader(|conn| {
        drift_storage::queries::env_variables::query_missing(conn)
    }).map_err(storage_err)?;

    let missing_env_vars: Vec<String> = missing_env.iter().map(|e| e.name.clone()).collect();

    let unused = rt.storage.with_reader(|conn| {
        drift_storage::queries::constants::query_unused(conn)
    }).map_err(storage_err)?;

    Ok(JsConstantsResult {
        constant_count,
        secrets: js_secrets,
        magic_numbers: js_magic,
        missing_env_vars,
        dead_constant_count: unused.len() as u32,
    })
}

// ─── Wrapper Detection ───────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsWrapper {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub category: String,
    pub framework: String,
    pub confidence: f64,
    pub is_multi_primitive: bool,
    pub usage_count: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsWrapperHealth {
    pub consistency: f64,
    pub coverage: f64,
    pub abstraction_depth: f64,
    pub overall: f64,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsWrapperResult {
    pub wrappers: Vec<JsWrapper>,
    pub health: JsWrapperHealth,
    pub framework_count: u32,
    pub category_count: u32,
}

#[napi]
pub fn drift_wrapper_detection(_root: String) -> napi::Result<JsWrapperResult> {
    let rt = runtime::get()?;

    let rows = rt.storage.with_reader(|conn| {
        conn.prepare_cached("SELECT id, name, file, line, category, wrapped_primitives, framework, confidence, is_multi_primitive, is_exported, usage_count FROM wrappers")
            .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
            .and_then(|mut stmt| {
                let rows = stmt.query_map([], |row| {
                    Ok(drift_storage::queries::structural::WrapperRow {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        file: row.get(2)?,
                        line: row.get::<_, u32>(3)?,
                        category: row.get(4)?,
                        wrapped_primitives: row.get(5)?,
                        framework: row.get(6)?,
                        confidence: row.get(7)?,
                        is_multi_primitive: row.get::<_, i32>(8)? != 0,
                        is_exported: row.get::<_, i32>(9)? != 0,
                        usage_count: row.get::<_, u32>(10)?,
                    })
                }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
                let mut result = Vec::new();
                for row in rows {
                    result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
                }
                Ok(result)
            })
    }).map_err(storage_err)?;

    let mut frameworks = std::collections::HashSet::new();
    let mut categories = std::collections::HashSet::new();

    let wrappers: Vec<JsWrapper> = rows.iter().map(|w| {
        frameworks.insert(w.framework.clone());
        categories.insert(w.category.clone());
        JsWrapper {
            name: w.name.clone(),
            file: w.file.clone(),
            line: w.line,
            category: w.category.clone(),
            framework: w.framework.clone(),
            confidence: w.confidence,
            is_multi_primitive: w.is_multi_primitive,
            usage_count: w.usage_count,
        }
    }).collect();

    let avg_conf = if wrappers.is_empty() { 0.0 } else {
        wrappers.iter().map(|w| w.confidence).sum::<f64>() / wrappers.len() as f64
    };

    Ok(JsWrapperResult {
        wrappers,
        health: JsWrapperHealth {
            consistency: avg_conf,
            coverage: 0.0,
            abstraction_depth: 0.0,
            overall: avg_conf,
        },
        framework_count: frameworks.len() as u32,
        category_count: categories.len() as u32,
    })
}

// ─── DNA System ──────────────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsGene {
    pub id: String,
    pub name: String,
    pub dominant_allele: Option<String>,
    pub allele_count: u32,
    pub confidence: f64,
    pub consistency: f64,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsMutation {
    pub id: String,
    pub file: String,
    pub line: u32,
    pub gene: String,
    pub expected: String,
    pub actual: String,
    pub impact: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsDnaHealthScore {
    pub overall: f64,
    pub consistency: f64,
    pub confidence: f64,
    pub mutation_score: f64,
    pub coverage: f64,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsDnaResult {
    pub genes: Vec<JsGene>,
    pub mutations: Vec<JsMutation>,
    pub health: JsDnaHealthScore,
    pub genetic_diversity: f64,
}

#[napi]
pub fn drift_dna_analysis(_root: String) -> napi::Result<JsDnaResult> {
    let rt = runtime::get()?;

    let gene_rows = rt.storage.with_reader(|conn| {
        drift_storage::queries::structural::get_all_dna_genes(conn)
    }).map_err(storage_err)?;

    let mutation_rows = rt.storage.with_reader(|conn| {
        drift_storage::queries::structural::get_unresolved_mutations(conn)
    }).map_err(storage_err)?;

    let genes: Vec<JsGene> = gene_rows.iter().map(|g| {
        let alleles: Vec<serde_json::Value> = serde_json::from_str(&g.alleles).unwrap_or_default();
        JsGene {
            id: g.gene_id.clone(),
            name: g.name.clone(),
            dominant_allele: g.dominant_allele.clone(),
            allele_count: alleles.len() as u32,
            confidence: g.confidence,
            consistency: g.consistency,
        }
    }).collect();

    let mutations: Vec<JsMutation> = mutation_rows.iter().map(|m| JsMutation {
        id: m.id.clone(),
        file: m.file.clone(),
        line: m.line,
        gene: m.gene_id.clone(),
        expected: m.expected.clone(),
        actual: m.actual.clone(),
        impact: m.impact.clone(),
    }).collect();

    let avg_consistency = if genes.is_empty() { 0.0 } else {
        genes.iter().map(|g| g.consistency).sum::<f64>() / genes.len() as f64
    };
    let avg_confidence = if genes.is_empty() { 0.0 } else {
        genes.iter().map(|g| g.confidence).sum::<f64>() / genes.len() as f64
    };
    let mutation_score = if gene_rows.is_empty() { 1.0 } else {
        1.0 - (mutations.len() as f64 / gene_rows.len().max(1) as f64).min(1.0)
    };

    Ok(JsDnaResult {
        genes,
        mutations,
        health: JsDnaHealthScore {
            overall: (avg_consistency + avg_confidence + mutation_score) / 3.0,
            consistency: avg_consistency,
            confidence: avg_confidence,
            mutation_score,
            coverage: 0.0,
        },
        genetic_diversity: gene_rows.len() as f64,
    })
}

// ─── OWASP/CWE Mapping ──────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsSecurityFinding {
    pub id: String,
    pub detector: String,
    pub file: String,
    pub line: u32,
    pub description: String,
    pub severity: f64,
    pub cwe_ids: Vec<u32>,
    pub owasp_categories: Vec<String>,
    pub confidence: f64,
    pub remediation: Option<String>,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsComplianceReport {
    pub posture_score: f64,
    pub owasp_coverage: f64,
    pub cwe_top25_coverage: f64,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsOwaspResult {
    pub findings: Vec<JsSecurityFinding>,
    pub compliance: JsComplianceReport,
}

#[napi]
pub fn drift_owasp_analysis(_root: String) -> napi::Result<JsOwaspResult> {
    let rt = runtime::get()?;

    let mut findings: Vec<JsSecurityFinding> = Vec::new();

    // Source 1: Violations with CWE/OWASP mappings
    let violations = rt.storage.with_reader(|conn| {
        drift_storage::queries::enforcement::query_all_violations(conn)
    }).map_err(storage_err)?;

    for v in &violations {
        if v.cwe_id.is_some() || v.owasp_category.is_some() {
            findings.push(JsSecurityFinding {
                id: v.id.clone(),
                detector: v.pattern_id.clone(),
                file: v.file.clone(),
                line: v.line,
                description: v.message.clone(),
                severity: match v.severity.as_str() {
                    "critical" => 1.0, "high" => 0.8, "medium" => 0.5, _ => 0.2,
                },
                cwe_ids: v.cwe_id.into_iter().collect(),
                owasp_categories: v.owasp_category.iter().cloned().collect(),
                confidence: 0.8,
                remediation: None,
            });
        }
    }

    // Source 2: Taint flows — unsanitized data flows are security findings
    let taint_flows = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT id, source_file, source_line, source_type, sink_file, sink_line, sink_type, cwe_id, is_sanitized, path, confidence
             FROM taint_flows WHERE is_sanitized = 0 ORDER BY confidence DESC LIMIT 500"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u32>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, u32>(7)?,
                    row.get::<_, f64>(10)?,
                ))
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    for (id, src_file, src_line, _src_type, sink_file, sink_line, sink_type, cwe_id, confidence) in &taint_flows {
        let severity = match sink_type.as_str() {
            "os_command" => 0.9,
            "sql_query" => 0.9,
            "http_request" => 0.7,
            "deserialization" => 0.7,
            "log_output" => 0.4,
            _ => 0.5,
        };
        let owasp = match sink_type.as_str() {
            "os_command" => "A03:2021",
            "sql_query" => "A03:2021",
            "http_request" => "A10:2021",
            "deserialization" => "A08:2021",
            "log_output" => "A09:2021",
            _ => "A03:2021",
        };
        findings.push(JsSecurityFinding {
            id: format!("taint-{}", id),
            detector: format!("taint-{}", sink_type),
            file: sink_file.clone(),
            line: *sink_line,
            description: format!(
                "Unsanitized data flow from {}:{} to {}:{} (sink: {})",
                src_file.split('/').last().unwrap_or(src_file), src_line,
                sink_file.split('/').last().unwrap_or(sink_file), sink_line,
                sink_type,
            ),
            severity,
            cwe_ids: vec![*cwe_id],
            owasp_categories: vec![owasp.to_string()],
            confidence: *confidence,
            remediation: None,
        });
    }

    // Source 3: Security-category detections with CWE IDs
    let detections = rt.storage.with_reader(|conn| {
        drift_storage::queries::detections::query_all_detections(conn, 5000)
    }).map_err(storage_err)?;

    for d in &detections {
        if d.category != "security" { continue; }
        let cwe_ids: Vec<u32> = d.cwe_ids.as_deref()
            .map(|s| s.split(',').filter_map(|c| c.trim().parse().ok()).collect())
            .unwrap_or_default();
        if cwe_ids.is_empty() && d.owasp.is_none() { continue; }
        findings.push(JsSecurityFinding {
            id: format!("det-{}", d.id),
            detector: d.pattern_id.clone(),
            file: d.file.clone(),
            line: d.line as u32,
            description: d.matched_text.clone().unwrap_or_else(|| d.pattern_id.clone()),
            severity: if d.confidence >= 0.9 { 0.8 } else if d.confidence >= 0.7 { 0.5 } else { 0.3 },
            cwe_ids: cwe_ids.clone(),
            owasp_categories: d.owasp.iter().cloned().collect(),
            confidence: d.confidence,
            remediation: None,
        });
    }

    let mut critical = 0u32; let mut high = 0u32;
    let mut medium = 0u32; let mut low = 0u32;
    for f in &findings {
        if f.severity >= 0.9 { critical += 1; }
        else if f.severity >= 0.7 { high += 1; }
        else if f.severity >= 0.4 { medium += 1; }
        else { low += 1; }
    }

    // Compute OWASP coverage: how many of the 10 OWASP categories are represented
    let mut owasp_cats: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in &findings {
        for cat in &f.owasp_categories {
            if let Some(prefix) = cat.split(':').next() {
                owasp_cats.insert(prefix.to_string());
            }
        }
    }
    let owasp_coverage = owasp_cats.len() as f64 / 10.0;

    // CWE Top 25 coverage
    let cwe_top25: std::collections::HashSet<u32> = [
        787, 79, 89, 416, 78, 20, 125, 22, 352, 434,
        862, 476, 287, 190, 502, 77, 119, 798, 918, 306,
        362, 269, 94, 863, 276,
    ].into_iter().collect();
    let mut found_cwe25: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for f in &findings {
        for cwe in &f.cwe_ids {
            if cwe_top25.contains(cwe) {
                found_cwe25.insert(*cwe);
            }
        }
    }
    let cwe_coverage = found_cwe25.len() as f64 / 25.0;

    let posture = if findings.is_empty() { 100.0 } else {
        (100.0 - (critical as f64 * 20.0 + high as f64 * 10.0 + medium as f64 * 3.0 + low as f64)).max(0.0)
    };

    Ok(JsOwaspResult {
        findings,
        compliance: JsComplianceReport {
            posture_score: posture,
            owasp_coverage,
            cwe_top25_coverage: cwe_coverage,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
        },
    })
}

// ─── Cryptographic Failure Detection ─────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCryptoFinding {
    pub file: String,
    pub line: u32,
    pub category: String,
    pub description: String,
    pub confidence: f64,
    pub cwe_id: u32,
    pub remediation: String,
    pub language: String,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCryptoHealthScore {
    pub overall: f64,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCryptoResult {
    pub findings: Vec<JsCryptoFinding>,
    pub health: JsCryptoHealthScore,
}

#[napi]
pub fn drift_crypto_analysis(_root: String) -> napi::Result<JsCryptoResult> {
    let rt = runtime::get()?;

    let rows = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT id, file, line, category, description, code, confidence, cwe_id, owasp, remediation, language FROM crypto_findings"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| {
                Ok(drift_storage::queries::structural::CryptoFindingRow {
                    id: row.get(0)?,
                    file: row.get(1)?,
                    line: row.get::<_, u32>(2)?,
                    category: row.get(3)?,
                    description: row.get(4)?,
                    code: row.get(5)?,
                    confidence: row.get(6)?,
                    cwe_id: row.get::<_, u32>(7)?,
                    owasp: row.get(8)?,
                    remediation: row.get(9)?,
                    language: row.get(10)?,
                })
            }).map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?);
            }
            Ok(result)
        })
    }).map_err(storage_err)?;

    let mut critical = 0u32; let mut high = 0u32; let mut medium = 0u32;
    let findings: Vec<JsCryptoFinding> = rows.iter().map(|r| {
        if r.confidence >= 0.9 { critical += 1; }
        else if r.confidence >= 0.7 { high += 1; }
        else { medium += 1; }
        JsCryptoFinding {
            file: r.file.clone(),
            line: r.line,
            category: r.category.clone(),
            description: r.description.clone(),
            confidence: r.confidence,
            cwe_id: r.cwe_id,
            remediation: r.remediation.clone(),
            language: r.language.clone(),
        }
    }).collect();

    let overall = if findings.is_empty() { 100.0 } else {
        (100.0 - (critical as f64 * 25.0 + high as f64 * 10.0 + medium as f64 * 3.0)).max(0.0)
    };

    Ok(JsCryptoResult {
        findings,
        health: JsCryptoHealthScore { overall, critical_count: critical, high_count: high, medium_count: medium },
    })
}

// ─── Module Decomposition ────────────────────────────────────────────

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsLogicalModule {
    pub name: String,
    pub file_count: u32,
    pub public_interface_count: u32,
    pub internal_function_count: u32,
    pub cohesion: f64,
    pub coupling: f64,
    pub estimated_complexity: u32,
    pub applied_prior_count: u32,
}

#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsDecompositionResult {
    pub modules: Vec<JsLogicalModule>,
    pub module_count: u32,
    pub total_files: u32,
    pub avg_cohesion: f64,
    pub avg_coupling: f64,
}

#[napi]
pub fn drift_decomposition(_root: String) -> napi::Result<JsDecompositionResult> {
    let rt = runtime::get()?;

    // Use coupling_metrics as a proxy for module decomposition
    let metrics = rt.storage.with_reader(|conn| {
        drift_storage::queries::structural::get_all_coupling_metrics(conn)
    }).map_err(storage_err)?;

    let file_count = rt.storage.with_reader(|conn| {
        drift_storage::queries::files::count_files(conn)
    }).map_err(storage_err)? as u32;

    let modules: Vec<JsLogicalModule> = metrics.iter().map(|m| JsLogicalModule {
        name: m.module.clone(),
        file_count: 0,
        public_interface_count: m.ca,
        internal_function_count: m.ce,
        cohesion: 1.0 - m.distance,
        coupling: m.instability,
        estimated_complexity: m.ce + m.ca,
        applied_prior_count: 0,
    }).collect();

    let module_count = modules.len() as u32;
    let avg_cohesion = if modules.is_empty() { 0.0 } else {
        modules.iter().map(|m| m.cohesion).sum::<f64>() / modules.len() as f64
    };
    let avg_coupling = if modules.is_empty() { 0.0 } else {
        modules.iter().map(|m| m.coupling).sum::<f64>() / modules.len() as f64
    };

    Ok(JsDecompositionResult { modules, module_count, total_files: file_count, avg_cohesion, avg_coupling })
}

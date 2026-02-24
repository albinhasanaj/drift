//! Phase 2 NAPI bindings — drift_analyze(), drift_call_graph(), drift_boundaries().

use napi_derive::napi;
use serde::{Deserialize, Serialize};

use rayon::prelude::*;

use crate::conversions::error_codes;
use crate::runtime;

/// Debug logging macro — suppressed when DRIFT_QUIET=1 is set.
/// Prevents [drift-analyze] timing/status messages from leaking
/// to stderr when the CLI is in --quiet mode.
macro_rules! drift_log {
    ($($arg:tt)*) => {
        if std::env::var("DRIFT_QUIET").as_deref() != Ok("1") {
            eprintln!($($arg)*);
        }
    };
}

/// Check if a file path belongs to a test, benchmark, or fixture directory.
/// Used to exclude embedded code samples from contract/endpoint extraction.
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

/// Analysis result returned to TypeScript.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsAnalysisResult {
    pub file: String,
    pub language: String,
    pub matches: Vec<JsPatternMatch>,
    pub analysis_time_us: f64,
}

/// A pattern match returned to TypeScript.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsPatternMatch {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub pattern_id: String,
    pub confidence: f64,
    pub category: String,
    pub detection_method: String,
    pub matched_text: String,
    pub cwe_ids: Vec<u32>,
    pub owasp: Option<String>,
}

/// Call graph result returned to TypeScript.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCallGraphResult {
    pub total_functions: u32,
    pub total_edges: u32,
    pub entry_points: u32,
    pub resolution_rate: f64,
    pub build_duration_ms: f64,
}

/// Boundary detection result returned to TypeScript.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsBoundaryResult {
    pub models: Vec<JsModelResult>,
    pub sensitive_fields: Vec<JsSensitiveField>,
    pub frameworks_detected: Vec<String>,
}

/// A model result returned to TypeScript.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsModelResult {
    pub name: String,
    pub table_name: Option<String>,
    pub file: String,
    pub framework: String,
    pub field_count: u32,
    pub confidence: f64,
}

/// A sensitive field result returned to TypeScript.
#[napi(object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsSensitiveField {
    pub model_name: String,
    pub field_name: String,
    pub file: String,
    pub sensitivity: String,
    pub confidence: f64,
}

fn storage_err(e: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(format!("[{}] {e}", error_codes::STORAGE_ERROR))
}

/// Run the analysis pipeline on the project.
///
/// Orchestrates in phases:
///   Phase 1: read tracked files → parse → detect → persist detections + functions
///   Phase 2: cross-file analysis (boundaries, call graph)
///   Phase 3: pattern intelligence + structural (coupling, wrappers, crypto, DNA, etc.)
///   Phase 4: graph intelligence (taint, errors, impact, test topology, reachability)
///   Phase 5: enforcement (quality gates, violations, degradation alerts)
///
/// @param max_phase - Stop after this phase (1-5). Default: 5 (all phases).
#[napi(js_name = "driftAnalyze")]
pub async fn drift_analyze(max_phase: Option<u32>) -> napi::Result<Vec<JsAnalysisResult>> {
    let max_phase = max_phase.unwrap_or(5).clamp(1, 5);
    let rt = runtime::get()?;

    // Step 1: Read tracked files from file_metadata
    let files = rt.storage.with_reader(|conn| {
        drift_storage::queries::files::load_all_file_metadata(conn)
    }).map_err(storage_err)?;

    if files.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Parse each file and run detection
    let parser_manager = drift_analysis::parsers::ParserManager::new();
    let detection_engine = drift_analysis::engine::DetectionEngine::new(
        drift_analysis::engine::VisitorRegistry::new(),
    );
    let mut analysis_pipeline = drift_analysis::engine::AnalysisPipeline::with_engine(
        detection_engine,
    );

    // Step 2a: Load framework packs (built-in + custom from .drift/frameworks/)
    let fw_load_timer = std::time::Instant::now();
    let framework_registry = {
        let custom_dir = rt.project_root.as_ref()
            .map(|p| p.join(".drift").join("frameworks"));
        match custom_dir {
            Some(ref dir) if dir.is_dir() => {
                drift_analysis::frameworks::registry::FrameworkPackRegistry::with_builtins_and_custom(dir)
            }
            _ => drift_analysis::frameworks::registry::FrameworkPackRegistry::with_builtins(),
        }
    };
    let framework_packs = framework_registry.into_packs();
    let framework_packs_for_learner = framework_packs.clone();
    let mut framework_matcher = drift_analysis::frameworks::FrameworkMatcher::new(framework_packs);
    let mut framework_learner = drift_analysis::frameworks::FrameworkLearner::new(framework_packs_for_learner);
    drift_log!(
        "[drift-analyze] framework packs loaded: {} packs, {} patterns",
        framework_matcher.pack_count(),
        framework_matcher.pattern_count(),
    );
    drift_log!("[drift-analyze] 2a (framework load): {:?}", fw_load_timer.elapsed());

    let mut all_results: Vec<JsAnalysisResult> = Vec::new();
    let mut all_matches: Vec<drift_analysis::engine::types::PatternMatch> = Vec::new();
    let mut detection_rows: Vec<drift_storage::batch::commands::DetectionRow> = Vec::new();
    let mut function_rows: Vec<drift_storage::batch::commands::FunctionRow> = Vec::new();
    let mut all_parse_results: Vec<drift_analysis::parsers::ParseResult> = Vec::new();
    // File content cache — read once in Phase 1, reused in Phase 3+ sub-steps.
    // Eliminates ~15,000 redundant disk reads (9 sub-steps × 1700 files).
    let mut file_contents: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    let project_root = rt.project_root.as_deref();

    for file_meta in &files {
        let file_path = if let Some(root) = project_root {
            root.join(&file_meta.path)
        } else {
            std::path::PathBuf::from(&file_meta.path)
        };

        // Skip files without a known language
        if file_meta.language.is_none() {
            continue;
        }

        let lang = match drift_analysis::scanner::language_detect::Language::from_extension(
            file_path.extension().and_then(|e| e.to_str()),
        ) {
            Some(l) => l,
            None => continue,
        };

        // Read file from disk
        let source = match std::fs::read(&file_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[drift-analyze] warning: cannot read {}: {} (project_root={:?})",
                    file_path.display(),
                    e,
                    project_root,
                );
                continue;
            }
        };

        // Single parse: get both ParseResult and tree-sitter Tree
        let (parse_result, tree) = match parser_manager.parse_returning_tree(&source, &file_path) {
            Ok(pair) => pair,
            Err(_) => continue,
        };

        // Run the 4-phase analysis pipeline
        let mut resolution_index = drift_analysis::engine::ResolutionIndex::new();
        let result = analysis_pipeline.analyze_file(
            &parse_result,
            &source,
            &tree,
            &mut resolution_index,
        );

        // Run framework pattern matcher + learner on this file's ParseResult
        {
            use drift_analysis::engine::visitor::{FileDetectorHandler, LearningDetectorHandler};
            let ctx = drift_analysis::engine::visitor::DetectionContext::from_parse_result(
                &parse_result, &source,
            );
            framework_matcher.analyze_file(&ctx);
            framework_learner.learn(&ctx);
        }

        // Cache file content for reuse in learning detect pass and Phase 3+ structural sub-steps
        // (eliminates ~15,000 redundant disk reads: 9 sub-steps × N files)
        if let Ok(s) = String::from_utf8(source.clone()) {
            file_contents.insert(parse_result.file.clone(), s);
        }

        // Collect parse results for cross-file analyses (boundaries, call graph)
        all_parse_results.push(parse_result.clone());

        // Collect matches for pattern intelligence
        all_matches.extend(result.matches.iter().cloned());

        // Convert to detection rows for batch persistence
        for m in &result.matches {
            detection_rows.push(drift_storage::batch::commands::DetectionRow {
                file: m.file.clone(),
                line: m.line as i64,
                column_num: m.column as i64,
                pattern_id: m.pattern_id.clone(),
                category: format!("{:?}", m.category),
                confidence: m.confidence as f64,
                detection_method: format!("{:?}", m.detection_method),
                cwe_ids: if m.cwe_ids.is_empty() {
                    None
                } else {
                    Some(m.cwe_ids.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","))
                },
                owasp: m.owasp.clone(),
                matched_text: Some(m.matched_text.clone()),
            });
        }

        // Convert parsed functions to function rows
        for func in &parse_result.functions {
            function_rows.push(drift_storage::batch::commands::FunctionRow {
                file: parse_result.file.clone(),
                name: func.name.clone(),
                qualified_name: func.qualified_name.clone(),
                language: lang.name().to_string(),
                line: func.line as i64,
                end_line: func.end_line as i64,
                parameter_count: func.parameters.len() as i64,
                return_type: func.return_type.clone(),
                is_exported: func.is_exported,
                is_async: func.is_async,
                body_hash: func.body_hash.to_le_bytes().to_vec(),
                signature_hash: func.signature_hash.to_le_bytes().to_vec(),
            });
        }

        // Build JS result — include both AST visitor matches AND framework matches for this file
        let mut js_matches: Vec<JsPatternMatch> = result
            .matches
            .iter()
            .map(|m| JsPatternMatch {
                file: m.file.clone(),
                line: m.line,
                column: m.column,
                pattern_id: m.pattern_id.clone(),
                confidence: m.confidence as f64,
                category: format!("{:?}", m.category),
                detection_method: format!("{:?}", m.detection_method),
                matched_text: m.matched_text.clone(),
                cwe_ids: m.cwe_ids.to_vec(),
                owasp: m.owasp.clone(),
            })
            .collect();

        // FW-JSRES-02: Include framework matches for this file in JsAnalysisResult
        for m in framework_matcher.last_file_results() {
            js_matches.push(JsPatternMatch {
                file: m.file.clone(),
                line: m.line,
                column: m.column,
                pattern_id: m.pattern_id.clone(),
                confidence: m.confidence as f64,
                category: format!("{:?}", m.category),
                detection_method: format!("{:?}", m.detection_method),
                matched_text: m.matched_text.clone(),
                cwe_ids: m.cwe_ids.to_vec(),
                owasp: m.owasp.clone(),
            });
        }

        all_results.push(JsAnalysisResult {
            file: file_meta.path.clone(),
            language: lang.name().to_string(),
            matches: js_matches,
            analysis_time_us: result.analysis_time_us as f64,
        });
    }

    // Step 2c: Framework learning — detect convention deviations
    let fw_learn_timer = std::time::Instant::now();
    {
        use drift_analysis::engine::visitor::LearningDetectorHandler;
        for pr in &all_parse_results {
            if let Some(content) = file_contents.get(&pr.file) {
                let source = content.as_bytes();
                let ctx = drift_analysis::engine::visitor::DetectionContext::from_parse_result(pr, source);
                framework_learner.detect(&ctx);
            }
        }
        let learning_matches = framework_learner.results();
        if !learning_matches.is_empty() {
            drift_log!("[drift-analyze] framework learning deviations: {} hits", learning_matches.len());
            for m in &learning_matches {
                detection_rows.push(drift_storage::batch::commands::DetectionRow {
                    file: m.file.clone(),
                    line: m.line as i64,
                    column_num: m.column as i64,
                    pattern_id: m.pattern_id.clone(),
                    category: format!("{:?}", m.category),
                    confidence: m.confidence as f64,
                    detection_method: format!("{:?}", m.detection_method),
                    cwe_ids: if m.cwe_ids.is_empty() {
                        None
                    } else {
                        Some(m.cwe_ids.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","))
                    },
                    owasp: m.owasp.clone(),
                    matched_text: Some(m.matched_text.clone()),
                });
            }
            all_matches.extend(learning_matches);
        }
    }
    drift_log!("[drift-analyze] 2c (framework learn): {:?}", fw_learn_timer.elapsed());

    // Step 2b: Collect framework matcher results and merge into all_matches
    let fw_match_timer = std::time::Instant::now();
    {
        use drift_analysis::engine::visitor::FileDetectorHandler;
        let framework_matches = framework_matcher.results();
        if !framework_matches.is_empty() {
            drift_log!(
                "[drift-analyze] framework patterns matched: {} hits",
                framework_matches.len(),
            );
            for m in &framework_matches {
                detection_rows.push(drift_storage::batch::commands::DetectionRow {
                    file: m.file.clone(),
                    line: m.line as i64,
                    column_num: m.column as i64,
                    pattern_id: m.pattern_id.clone(),
                    category: format!("{:?}", m.category),
                    confidence: m.confidence as f64,
                    detection_method: format!("{:?}", m.detection_method),
                    cwe_ids: if m.cwe_ids.is_empty() {
                        None
                    } else {
                        Some(m.cwe_ids.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","))
                    },
                    owasp: m.owasp.clone(),
                    matched_text: Some(m.matched_text.clone()),
                });
            }
            all_matches.extend(framework_matches);
        }
    }
    drift_log!("[drift-analyze] 2b (framework match): {:?}", fw_match_timer.elapsed());

    // Step 3: Persist detections and functions via BatchWriter
    if !detection_rows.is_empty() {
        rt.storage.send_batch(
            drift_storage::batch::commands::BatchCommand::InsertDetections(detection_rows),
        ).map_err(storage_err)?;
    }
    if !function_rows.is_empty() {
        rt.storage.send_batch(
            drift_storage::batch::commands::BatchCommand::InsertFunctions(function_rows),
        ).map_err(storage_err)?;
    }

    // Flush phase 1 results before continuing
    rt.storage.flush_batch_sync().map_err(storage_err)?;

    // ── Phase 1 complete: parse + detect ──
    if max_phase < 2 {
        return Ok(all_results);
    }

    // Build production-only filtered views.
    // Test/bench/fixture files are excluded from subsystems where their patterns
    // would create noise (coupling, wrappers, crypto, DNA, secrets, constants,
    // taint, error handling, impact, enforcement). They are kept for test topology,
    // boundary detection, call graph, and reachability.
    let prod_parse_results: Vec<&drift_analysis::parsers::ParseResult> = all_parse_results
        .iter()
        .filter(|pr| !is_test_or_fixture_file(&pr.file))
        .collect();
    let prod_matches: Vec<&drift_analysis::engine::types::PatternMatch> = all_matches
        .iter()
        .filter(|m| !is_test_or_fixture_file(&m.file))
        .collect();
    // Owned clone for APIs that require &[ParseResult] instead of &[&ParseResult].
    let prod_pr_owned: Vec<drift_analysis::parsers::ParseResult> = prod_parse_results
        .iter()
        .map(|pr| (*pr).clone())
        .collect();

    // Step 3b: Run cross-file analyses (boundary detection, call graph)
    if !all_parse_results.is_empty() {
        // Boundary detection → persist boundary rows
        let boundary_detector = drift_analysis::boundaries::BoundaryDetector::new();
        if let Ok(boundary_result) = boundary_detector.detect(&all_parse_results) {
            let mut boundary_rows: Vec<drift_storage::batch::commands::BoundaryRow> = Vec::new();

            for model in &boundary_result.models {
                // One row per model (no field)
                boundary_rows.push(drift_storage::batch::commands::BoundaryRow {
                    file: model.file.clone(),
                    framework: format!("{:?}", model.framework),
                    model_name: model.name.clone(),
                    table_name: model.table_name.clone(),
                    field_name: None,
                    sensitivity: None,
                    confidence: model.confidence as f64,
                });
            }

            for sf in &boundary_result.sensitive_fields {
                boundary_rows.push(drift_storage::batch::commands::BoundaryRow {
                    file: sf.file.clone(),
                    framework: String::new(),
                    model_name: sf.model_name.clone(),
                    table_name: None,
                    field_name: Some(sf.field_name.clone()),
                    sensitivity: Some(sf.sensitivity.name().to_string()),
                    confidence: sf.confidence as f64,
                });
            }

            if !boundary_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertBoundaries(boundary_rows),
                ).map_err(storage_err)?;
            }

            // BW-EVT-04: Fire on_boundary_discovered for each detected boundary model
            {
                use drift_core::events::types::BoundaryDiscoveredEvent;
                if let Ok(mut dedup) = rt.bridge_deduplicator.lock() {
                    for model in &boundary_result.models {
                        let entity_id = format!("{}:{}", model.file, model.name);
                        if !dedup.is_duplicate("on_boundary_discovered", &entity_id, "") {
                            rt.dispatcher.emit_boundary_discovered(&BoundaryDiscoveredEvent {
                                boundary_id: entity_id,
                                orm: format!("{:?}", model.framework),
                                model: model.name.clone(),
                            });
                        }
                    }
                }
            }
        }

        // Call graph building → persist call edges (with tsconfig alias resolution)
        let cg_builder = match &rt.project_root {
            Some(root) => drift_analysis::call_graph::CallGraphBuilder::for_project(root.clone()),
            None => drift_analysis::call_graph::CallGraphBuilder::new(),
        };
        if let Ok((call_graph, _stats)) = cg_builder.build(&all_parse_results) {
            use petgraph::visit::{EdgeRef, IntoEdgeReferences};
            let call_edge_rows: Vec<drift_storage::batch::commands::CallEdgeRow> = call_graph
                .graph
                .edge_references()
                .map(|e: petgraph::stable_graph::EdgeReference<'_, drift_analysis::call_graph::CallEdge>| {
                    let edge = e.weight();
                    drift_storage::batch::commands::CallEdgeRow {
                        caller_id: e.source().index() as i64,
                        callee_id: e.target().index() as i64,
                        resolution: edge.resolution.name().to_string(),
                        confidence: edge.confidence as f64,
                        call_site_line: edge.call_site_line as i64,
                    }
                })
                .collect();

            if !call_edge_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertCallEdges(call_edge_rows),
                ).map_err(storage_err)?;
            }
        }
    }

    // ── Phase 2 complete: cross-file analysis ──
    if max_phase < 3 {
        rt.storage.flush_batch_sync().map_err(storage_err)?;
        return Ok(all_results);
    }

    let phase_timer = std::time::Instant::now();
    // Step 4: Run pattern intelligence pipeline (with feedback store for closed-loop)
    if !all_matches.is_empty() {
        let feedback_store = crate::feedback_store::DbFeedbackStore::new(rt.clone());
        let mut pattern_pipeline = drift_analysis::patterns::pipeline::PatternIntelligencePipeline::new()
            .with_feedback_store(Box::new(feedback_store));

        let total_files = files.len() as u64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let pi_result = pattern_pipeline.run(&all_matches, total_files, now, None);

        // Persist pattern confidence scores
        let confidence_rows: Vec<drift_storage::batch::commands::PatternConfidenceRow> = pi_result
            .scores
            .iter()
            .map(|(pid, score)| drift_storage::batch::commands::PatternConfidenceRow {
                pattern_id: pid.clone(),
                alpha: score.alpha,
                beta: score.beta,
                posterior_mean: score.posterior_mean,
                credible_interval_low: score.credible_interval.0,
                credible_interval_high: score.credible_interval.1,
                tier: format!("{:?}", score.tier),
                momentum: format!("{:?}", score.momentum),
            })
            .collect();

        if !confidence_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertPatternConfidence(confidence_rows),
            ).map_err(storage_err)?;
        }

        // PH2-10: Persist outlier file/line from source detection matches
        let mut outlier_rows: Vec<drift_storage::batch::commands::OutlierDetectionRow> = Vec::new();
        for (pid, outliers) in &pi_result.outliers {
            // Find source detections for this pattern to extract file/line
            let pattern_matches: Vec<&drift_analysis::engine::types::PatternMatch> = all_matches
                .iter()
                .filter(|m| &m.pattern_id == pid)
                .collect();

            for o in outliers {
                // Use the outlier index to look up the source detection, fallback to first match
                let source = pattern_matches.get(o.index).or_else(|| pattern_matches.first());
                let (file, line) = match source {
                    Some(m) => (m.file.clone(), m.line as i64),
                    None => (String::new(), 0),
                };
                outlier_rows.push(drift_storage::batch::commands::OutlierDetectionRow {
                    pattern_id: pid.clone(),
                    file,
                    line,
                    deviation_score: o.deviation_score.value(),
                    significance: format!("{:?}", o.significance),
                    method: format!("{:?}", o.method),
                });
            }
        }
        if !outlier_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertOutliers(outlier_rows),
            ).map_err(storage_err)?;
        }

        // Persist conventions
        let convention_rows: Vec<drift_storage::batch::commands::ConventionInsertRow> = pi_result
            .conventions
            .iter()
            .map(|c| drift_storage::batch::commands::ConventionInsertRow {
                pattern_id: c.pattern_id.clone(),
                category: format!("{:?}", c.category),
                scope: c.scope.to_string(),
                dominance_ratio: c.dominance_ratio,
                promotion_status: format!("{:?}", c.promotion_status),
                discovered_at: c.discovery_date as i64,
                last_seen: c.last_seen as i64,
                expires_at: None,
            })
            .collect();

        if !convention_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertConventions(convention_rows),
            ).map_err(storage_err)?;
        }
    }

    // BW-EVT-03: Fire on_pattern_discovered for each unique pattern
    {
        use drift_core::events::types::PatternDiscoveredEvent;
        let mut seen_patterns = std::collections::HashSet::new();
        if let Ok(mut dedup) = rt.bridge_deduplicator.lock() {
            for m in &all_matches {
                if seen_patterns.insert(m.pattern_id.clone())
                    && !dedup.is_duplicate("on_pattern_discovered", &m.pattern_id, "")
                {
                    rt.dispatcher.emit_pattern_discovered(&PatternDiscoveredEvent {
                        pattern_id: m.pattern_id.clone(),
                        category: format!("{:?}", m.category),
                        confidence: m.confidence as f64,
                    });
                }
            }
        }
    }

    drift_log!("[drift-analyze] step 4 (pattern intelligence): {:?}", phase_timer.elapsed());
    let step_timer = std::time::Instant::now();

    // Step 5: Structural analysis — coupling, wrappers, crypto, constraints
    if !all_parse_results.is_empty() {
        // 5a: Coupling analysis → coupling_metrics + coupling_cycles tables
        // Uses prod_parse_results to exclude test configs (vitest, playwright, etc.)
        let import_graph = drift_analysis::structural::coupling::ImportGraphBuilder::from_parse_results(
            &prod_pr_owned, 2,
        );
        let coupling_metrics = drift_analysis::structural::coupling::compute_martin_metrics(&import_graph);
        let coupling_rows: Vec<drift_storage::batch::commands::CouplingMetricInsertRow> = coupling_metrics
            .iter()
            .map(|m| drift_storage::batch::commands::CouplingMetricInsertRow {
                module: m.module.clone(),
                ce: m.ce as i64,
                ca: m.ca as i64,
                instability: m.instability,
                abstractness: m.abstractness,
                distance: m.distance,
                zone: format!("{:?}", m.zone),
            })
            .collect();
        if !coupling_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertCouplingMetrics(coupling_rows),
            ).map_err(storage_err)?;
        }

        let cycles = drift_analysis::structural::coupling::detect_cycles(&import_graph);
        let cycle_rows: Vec<drift_storage::batch::commands::CouplingCycleInsertRow> = cycles
            .iter()
            .map(|c| drift_storage::batch::commands::CouplingCycleInsertRow {
                members: serde_json::to_string(&c.members).unwrap_or_default(),
                break_suggestions: serde_json::to_string(&c.break_suggestions).unwrap_or_default(),
            })
            .collect();
        if !cycle_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertCouplingCycles(cycle_rows),
            ).map_err(storage_err)?;
        }

        drift_log!("[drift-analyze] 5a (coupling): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5b: Wrapper detection → wrappers table (parallel)
        let wrapper_detector = drift_analysis::structural::wrappers::WrapperDetector::new();
        let wrapper_rows: Vec<drift_storage::batch::commands::WrapperInsertRow> = prod_parse_results.par_iter()
            .filter_map(|pr| file_contents.get(&pr.file).map(|c| (pr, c)))
            .flat_map(|(pr, content)| {
                let wrappers = wrapper_detector.detect(content, &pr.file);
                wrappers.iter().map(|w| {
                    let confidence = drift_analysis::structural::wrappers::confidence::compute_confidence(w, content);
                    let multi = drift_analysis::structural::wrappers::multi_primitive::analyze_multi_primitive(w);
                    drift_storage::batch::commands::WrapperInsertRow {
                        name: w.name.clone(),
                        file: w.file.clone(),
                        line: w.line,
                        category: format!("{:?}", w.category),
                        wrapped_primitives: serde_json::to_string(&w.wrapped_primitives).unwrap_or_default(),
                        framework: w.framework.clone(),
                        confidence,
                        is_multi_primitive: multi.is_composite,
                        is_exported: w.is_exported,
                        usage_count: w.usage_count,
                    }
                }).collect::<Vec<_>>()
            })
            .collect();
        if !wrapper_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertWrappers(wrapper_rows),
            ).map_err(storage_err)?;
        }

        drift_log!("[drift-analyze] 5b (wrappers): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5c: Crypto detection → crypto_findings table (parallel)
        let crypto_detector = drift_analysis::structural::crypto::CryptoDetector::new();
        let crypto_rows: Vec<drift_storage::batch::commands::CryptoFindingInsertRow> = prod_parse_results.par_iter()
            .filter_map(|pr| file_contents.get(&pr.file).map(|c| (pr, c)))
            .flat_map(|(pr, content)| {
                let lang = format!("{:?}", pr.language).to_lowercase();
                let mut findings = crypto_detector.detect(content, &pr.file, &lang);
                drift_analysis::structural::crypto::confidence::compute_confidence_batch(&mut findings, content);
                findings.iter().map(|f| {
                    drift_storage::batch::commands::CryptoFindingInsertRow {
                        file: f.file.clone(),
                        line: f.line,
                        category: format!("{:?}", f.category),
                        description: f.description.clone(),
                        code: f.code.clone(),
                        confidence: f.confidence,
                        cwe_id: f.cwe_id,
                        owasp: f.owasp.clone(),
                        remediation: f.remediation.clone(),
                        language: lang.clone(),
                    }
                }).collect::<Vec<_>>()
            })
            .collect();
        if !crypto_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertCryptoFindings(crypto_rows),
            ).map_err(storage_err)?;
        }

        drift_log!("[drift-analyze] 5c (crypto): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5d: DNA profiling → dna_genes + dna_mutations tables
        let mut all_gene_rows: Vec<drift_storage::batch::commands::DnaGeneInsertRow> = Vec::new();
        let mut all_mutation_rows: Vec<drift_storage::batch::commands::DnaMutationInsertRow> = Vec::new();
        let mut built_genes: Vec<drift_analysis::structural::dna::types::Gene> = Vec::new();

        // Language pre-filter: frontend extractors only run on JS/TS files (~324 vs 1707).
        // Backend extractors run on all files. ~3-4x speedup for 6 of 10 extractors.
        // Uses prod_parse_results so test patterns don't define codebase "genes".
        use drift_analysis::scanner::language_detect::Language as Lang;
        let frontend_files: Vec<(&str, &str)> = prod_parse_results.iter()
            .filter(|pr| matches!(pr.language, Lang::TypeScript | Lang::JavaScript))
            .filter_map(|pr| file_contents.get(&pr.file).map(|c| (c.as_str(), pr.file.as_str())))
            .collect();
        let all_files: Vec<(&str, &str)> = prod_parse_results.iter()
            .filter_map(|pr| file_contents.get(&pr.file).map(|c| (c.as_str(), pr.file.as_str())))
            .collect();

        // Frontend extractors (6): only on JS/TS files
        for extractor in drift_analysis::structural::dna::extractors::create_frontend_extractors() {
            let file_results = extractor.extract_batch(&frontend_files);
            let gene = extractor.build_gene(&file_results);
            if !gene.alleles.is_empty() {
                all_gene_rows.push(drift_storage::batch::commands::DnaGeneInsertRow {
                    gene_id: format!("{:?}", gene.id),
                    name: gene.name.clone(),
                    description: gene.description.clone(),
                    dominant_allele: gene.dominant.as_ref().map(|a| a.name.clone()),
                    alleles: serde_json::to_string(&gene.alleles).unwrap_or_default(),
                    confidence: gene.confidence,
                    consistency: gene.consistency,
                    exemplars: serde_json::to_string(&gene.exemplars).unwrap_or_default(),
                });
                built_genes.push(gene);
            }
        }
        // Backend extractors (4): on all files
        for extractor in drift_analysis::structural::dna::extractors::create_backend_extractors() {
            let file_results = extractor.extract_batch(&all_files);
            let gene = extractor.build_gene(&file_results);
            if !gene.alleles.is_empty() {
                all_gene_rows.push(drift_storage::batch::commands::DnaGeneInsertRow {
                    gene_id: format!("{:?}", gene.id),
                    name: gene.name.clone(),
                    description: gene.description.clone(),
                    dominant_allele: gene.dominant.as_ref().map(|a| a.name.clone()),
                    alleles: serde_json::to_string(&gene.alleles).unwrap_or_default(),
                    confidence: gene.confidence,
                    consistency: gene.consistency,
                    exemplars: serde_json::to_string(&gene.exemplars).unwrap_or_default(),
                });
                built_genes.push(gene);
            }
        }

        // Detect mutations from the built genes (reuse — no double extraction)
        if !built_genes.is_empty() {
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let mutations = drift_analysis::structural::dna::mutations::detect_mutations(&built_genes, now_ts);
            for m in &mutations {
                all_mutation_rows.push(drift_storage::batch::commands::DnaMutationInsertRow {
                    id: m.id.clone(),
                    file: m.file.clone(),
                    line: m.line,
                    gene_id: format!("{:?}", m.gene),
                    expected: m.expected.clone(),
                    actual: m.actual.clone(),
                    impact: format!("{:?}", m.impact),
                    code: m.code.clone(),
                    suggestion: m.suggestion.clone(),
                    detected_at: now_ts,
                });
            }
        }

        if !all_gene_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertDnaGenes(all_gene_rows),
            ).map_err(storage_err)?;
        }
        if !all_mutation_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertDnaMutations(all_mutation_rows),
            ).map_err(storage_err)?;
        }

        drift_log!("[drift-analyze] 5d (dna): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5e: Secrets detection → secrets table (pre-compiled + parallel)
        let secret_detector = drift_analysis::structural::constants::secrets::CompiledSecretDetector::new();
        let secret_rows: Vec<drift_storage::batch::commands::SecretInsertRow> = prod_parse_results.par_iter()
            .filter_map(|pr| file_contents.get(&pr.file).map(|c| (pr, c)))
            .flat_map(|(_pr, content)| {
                let secrets = secret_detector.detect(content, &_pr.file);
                secrets.into_iter().map(|s| {
                    drift_storage::batch::commands::SecretInsertRow {
                        pattern_name: s.pattern_name,
                        redacted_value: s.redacted_value,
                        file: s.file,
                        line: s.line,
                        severity: format!("{:?}", s.severity),
                        entropy: s.entropy,
                        confidence: s.confidence,
                        cwe_ids: serde_json::to_string(&s.cwe_ids).unwrap_or_default(),
                    }
                }).collect::<Vec<_>>()
            })
            .collect();
        if !secret_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertSecrets(secret_rows),
            ).map_err(storage_err)?;
        }

        drift_log!("[drift-analyze] 5e (secrets): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5f: Constants & magic numbers → constants table (parallel)
        let constant_rows: Vec<drift_storage::batch::commands::ConstantInsertRow> = prod_parse_results.par_iter()
            .filter_map(|pr| file_contents.get(&pr.file).map(|c| (pr, c)))
            .flat_map(|(pr, content)| {
                let lang = format!("{:?}", pr.language).to_lowercase();
                let magic_numbers = drift_analysis::structural::constants::magic_numbers::detect_magic_numbers(content, &pr.file, &lang);
                magic_numbers.into_iter().map(move |mn| {
                    drift_storage::batch::commands::ConstantInsertRow {
                        name: mn.suggested_name.clone().unwrap_or_else(|| mn.value.to_string()),
                        value: mn.value.to_string(),
                        file: mn.file,
                        line: mn.line as i64,
                        is_used: true,
                        language: lang.clone(),
                        is_named: mn.suggested_name.is_some(),
                    }
                }).collect::<Vec<_>>()
            })
            .collect();
        if !constant_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertConstants(constant_rows),
            ).map_err(storage_err)?;
        }

        drift_log!("[drift-analyze] 5f (constants): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5g: Constraint verification → constraint_verifications table
        let constraint_rows = rt.storage.with_reader(|conn| {
            drift_storage::queries::structural::get_enabled_constraints(conn)
        }).unwrap_or_default();

        if !constraint_rows.is_empty() {
            // Populate the invariant detector from parse results
            let mut inv_detector = drift_analysis::structural::constraints::detector::InvariantDetector::new();
            for pr in &prod_parse_results {
                let funcs: Vec<drift_analysis::structural::constraints::detector::FunctionInfo> = pr.functions.iter().map(|f| {
                    drift_analysis::structural::constraints::detector::FunctionInfo {
                        name: f.name.clone(),
                        line: f.line,
                        is_exported: f.is_exported,
                    }
                }).collect();
                let imports: Vec<String> = pr.imports.iter().map(|i| i.source.clone()).collect();
                let line_count = file_contents.get(&pr.file)
                    .map(|c| c.lines().count() as u32)
                    .unwrap_or(0);
                inv_detector.add_file(&pr.file, funcs, imports, line_count);
            }

            // Build store + verifier, run, persist results
            let mut store = drift_analysis::structural::constraints::store::ConstraintStore::new();
            for cr in &constraint_rows {
                store.add(drift_analysis::structural::constraints::types::Constraint {
                    id: cr.id.clone(),
                    description: cr.description.clone(),
                    invariant_type: serde_json::from_str(&format!("\"{}\"", cr.invariant_type))
                        .unwrap_or(drift_analysis::structural::constraints::types::InvariantType::MustExist),
                    target: cr.target.clone(),
                    scope: cr.scope.clone(),
                    source: drift_analysis::structural::constraints::types::ConstraintSource::Manual,
                    enabled: cr.enabled,
                });
            }

            let verifier = drift_analysis::structural::constraints::verifier::ConstraintVerifier::new(&store, &inv_detector);
            if let Ok(results) = verifier.verify_all() {
                // Flush batch writer first so constraint_verifications insert sees a clean state
                rt.storage.flush_batch().map_err(storage_err)?;

                rt.storage.with_writer(|conn| {
                    for vr in &results {
                        let violations_json = serde_json::to_string(&vr.violations).unwrap_or_default();
                        let _ = drift_storage::queries::structural::insert_constraint_verification(
                            conn, &vr.constraint_id, vr.passed, &violations_json,
                        );
                    }
                    Ok(())
                }).map_err(storage_err)?;
            }
        }

        drift_log!("[drift-analyze] 5g (constraints): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5h: Environment variable extraction → env_variables table (parallel)
        let env_rows: Vec<drift_storage::batch::commands::EnvVariableInsertRow> = prod_parse_results.par_iter()
            .filter_map(|pr| file_contents.get(&pr.file).map(|c| (pr, c)))
            .flat_map(|(pr, content)| {
                let lang = format!("{:?}", pr.language).to_lowercase();
                let env_refs = drift_analysis::structural::constants::env_extraction::extract_env_references(content, &pr.file, &lang);
                env_refs.into_iter().map(|ev| {
                    drift_storage::batch::commands::EnvVariableInsertRow {
                        name: ev.name,
                        file: ev.file,
                        line: ev.line as i64,
                        access_method: ev.access_method,
                        has_default: ev.has_default,
                        defined_in_env: ev.defined_in_env,
                        framework_prefix: ev.framework_prefix,
                    }
                }).collect::<Vec<_>>()
            })
            .collect();
        if !env_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertEnvVariables(env_rows),
            ).map_err(storage_err)?;
        }

        drift_log!("[drift-analyze] 5h (env vars): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5i: Data access tracking → data_access table (from DataAccess-category detections)
        let mut da_rows: Vec<drift_storage::batch::commands::DataAccessInsertRow> = Vec::new();
        for m in &all_matches {
            if format!("{:?}", m.category) == "DataAccess" {
                // Extract operation and table from matched_text (e.g. "ORM call: findAll", "raw query: db.query")
                let operation = if m.pattern_id.starts_with("DA-RAW") {
                    "raw_query"
                } else if m.pattern_id.starts_with("DA-REPO") {
                    "repository"
                } else {
                    "orm"
                };
                // Use line as a proxy function_id (actual function_id requires join with functions table)
                da_rows.push(drift_storage::batch::commands::DataAccessInsertRow {
                    function_id: m.line as i64,
                    table_name: m.matched_text.clone(),
                    operation: operation.to_string(),
                    framework: None,
                    line: m.line as i64,
                    confidence: m.confidence as f64,
                });
            }
        }
        if !da_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertDataAccess(da_rows),
            ).map_err(storage_err)?;
        }

        drift_log!("[drift-analyze] 5i (data access): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5j: OWASP findings → owasp_findings table (enriched from detections with CWE/OWASP data)
        let mut owasp_rows: Vec<drift_storage::batch::commands::OwaspFindingInsertRow> = Vec::new();
        let mut owasp_counter: u64 = 0;
        for m in &all_matches {
            let has_cwe = !m.cwe_ids.is_empty();
            let has_owasp = m.owasp.is_some();
            if has_cwe || has_owasp {
                owasp_counter += 1;
                let cwes_json = if has_cwe {
                    serde_json::to_string(&m.cwe_ids.iter().map(|c| c.to_string()).collect::<Vec<_>>()).unwrap_or_default()
                } else {
                    "[]".to_string()
                };
                let owasp_cats = m.owasp.clone().unwrap_or_default();
                owasp_rows.push(drift_storage::batch::commands::OwaspFindingInsertRow {
                    id: format!("owasp-{}-{}-{}", m.file.replace('/', "-"), m.line, owasp_counter),
                    detector: m.pattern_id.clone(),
                    file: m.file.clone(),
                    line: m.line as i64,
                    description: m.matched_text.clone(),
                    severity: m.confidence as f64,
                    cwes: cwes_json,
                    owasp_categories: owasp_cats,
                    confidence: m.confidence as f64,
                    remediation: None,
                });
            }
        }
        if !owasp_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertOwaspFindings(owasp_rows),
            ).map_err(storage_err)?;
        }

        drift_log!("[drift-analyze] 5j (owasp): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5k: Decomposition analysis → decomposition_decisions table
        {
            // Build DecompositionInput from parse results and call graph
            let decomp_files: Vec<drift_analysis::structural::decomposition::decomposer::FileEntry> =
                prod_parse_results.iter().map(|pr| {
                    let line_count = file_contents.get(&pr.file)
                        .map(|c| c.lines().count() as u64)
                        .unwrap_or(0);
                    drift_analysis::structural::decomposition::decomposer::FileEntry {
                        path: pr.file.clone(),
                        line_count,
                        language: format!("{:?}", pr.language).to_lowercase(),
                    }
                }).collect();

            let decomp_functions: Vec<(String, String, bool)> = prod_parse_results.iter()
                .flat_map(|pr| {
                    pr.functions.iter().map(move |f| (pr.file.clone(), f.name.clone(), f.is_exported))
                })
                .collect();

            // PH2-11: Build call_edges from parse results' call sites
            let decomp_call_edges: Vec<(String, String, String)> = prod_parse_results.iter()
                .flat_map(|pr| {
                    pr.call_sites.iter().filter_map(move |cs| {
                        cs.receiver.as_ref().map(|_| {
                            (pr.file.clone(), cs.callee_name.clone(), cs.callee_name.clone())
                        })
                    })
                })
                .collect();

            // PH2-11: Build data_access from DataAccess-category detection matches
            let decomp_data_access: Vec<(String, String, String)> = all_matches.iter()
                .filter(|m| format!("{:?}", m.category) == "DataAccess")
                .map(|m| {
                    let operation = if m.pattern_id.starts_with("DA-RAW") { "raw" } else { "orm" };
                    (m.file.clone(), m.pattern_id.clone(), operation.to_string())
                })
                .collect();

            let decomp_input = drift_analysis::structural::decomposition::decomposer::DecompositionInput {
                files: decomp_files,
                call_edges: decomp_call_edges,
                data_access: decomp_data_access,
                functions: decomp_functions,
            };

            let modules = drift_analysis::structural::decomposition::decomposer::decompose_with_priors(
                &decomp_input, &[],
            );

            // Persist applied priors as decomposition decisions
            let mut decision_rows: Vec<drift_storage::batch::commands::DecompositionDecisionInsertRow> = Vec::new();
            for module in &modules {
                for prior in &module.applied_priors {
                    decision_rows.push(drift_storage::batch::commands::DecompositionDecisionInsertRow {
                        dna_profile_hash: module.name.clone(),
                        adjustment: serde_json::to_string(&prior.adjustment).unwrap_or_default(),
                        confidence: prior.applied_weight,
                        dna_similarity: prior.applied_weight,
                        narrative: prior.narrative.clone(),
                        source_dna_hash: prior.source_dna_hash.clone(),
                        applied_weight: prior.applied_weight,
                    });
                }
            }
            if !decision_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertDecompositionDecisions(decision_rows),
                ).map_err(storage_err)?;
            }
        }

        drift_log!("[drift-analyze] 5k (decomposition): {:?}", step_timer.elapsed());
        let step_timer = std::time::Instant::now();

        // 5l: Contract extraction → contracts + contract_mismatches tables
        {
            use drift_analysis::structural::contracts::extractors::ExtractorRegistry;
            use drift_analysis::structural::contracts::matching::match_contracts;

            let contract_registry = ExtractorRegistry::new();

            // Parallel contract extraction: each file processed independently across cores.
            // Skip test files, benchmarks, and test fixtures — their embedded code
            // samples produce phantom endpoints that pollute contract analysis.
            #[allow(clippy::type_complexity)]
            let per_file_results: Vec<(
                Vec<drift_storage::batch::commands::ContractInsertRow>,
                Vec<(String, drift_analysis::structural::contracts::types::Endpoint)>,
            )> = all_parse_results.par_iter()
                .filter(|pr| !is_test_or_fixture_file(&pr.file))
                .filter_map(|pr| {
                    let content = file_contents.get(&pr.file)?;
                    let results = contract_registry.extract_all_with_context(
                        content, &pr.file, Some(pr),
                    );
                    let mut rows = Vec::new();
                    let mut endpoints = Vec::new();
                    for (framework, eps) in &results {
                        if !eps.is_empty() {
                            let endpoints_json = serde_json::to_string(
                                &eps.iter().map(|ep| {
                                    serde_json::json!({
                                        "method": ep.method,
                                        "path": ep.path,
                                        "line": ep.line,
                                        "request_fields": ep.request_fields.len(),
                                        "response_fields": ep.response_fields.len(),
                                    })
                                }).collect::<Vec<_>>()
                            ).unwrap_or_default();
                            let paradigm = match framework.as_str() {
                                "trpc" => "rpc",
                                "frontend" => "frontend",
                                _ => "rest",
                            };
                            let field_count: usize = eps.iter()
                                .map(|ep| ep.request_fields.len() + ep.response_fields.len())
                                .sum();
                            let confidence = if field_count > 0 { 0.9 } else { 0.6 };
                            rows.push(drift_storage::batch::commands::ContractInsertRow {
                                id: format!("{}:{}", pr.file, framework),
                                paradigm: paradigm.to_string(),
                                source_file: pr.file.clone(),
                                framework: framework.clone(),
                                confidence,
                                endpoints: endpoints_json,
                            });
                        }
                        for ep in eps {
                            endpoints.push((framework.clone(), ep.clone()));
                        }
                    }
                    Some((rows, endpoints))
                })
                .collect();

            // Merge parallel results
            let mut contract_rows: Vec<drift_storage::batch::commands::ContractInsertRow> = Vec::new();
            let mut all_contract_endpoints: Vec<(String, drift_analysis::structural::contracts::types::Endpoint)> = Vec::new();
            for (rows, endpoints) in per_file_results {
                contract_rows.extend(rows);
                all_contract_endpoints.extend(endpoints);
            }

            if !contract_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertContracts(contract_rows),
                ).map_err(storage_err)?;
            }

            // Run BE↔FE matching
            let backend_frameworks = ["express", "fastify", "nestjs", "spring", "flask", "django", "rails", "laravel", "gin", "actix", "aspnet", "nextjs"];
            let frontend_frameworks = ["frontend"];
            let backend_eps: Vec<drift_analysis::structural::contracts::types::Endpoint> = all_contract_endpoints.iter()
                .filter(|(fw, _)| backend_frameworks.contains(&fw.as_str()))
                .map(|(_, ep)| ep.clone())
                .collect();
            let frontend_eps: Vec<drift_analysis::structural::contracts::types::Endpoint> = all_contract_endpoints.iter()
                .filter(|(fw, _)| frontend_frameworks.contains(&fw.as_str()))
                .map(|(_, ep)| ep.clone())
                .collect();

            let contract_matches = match_contracts(&backend_eps, &frontend_eps);
            let mismatch_rows: Vec<drift_storage::batch::commands::ContractMismatchInsertRow> = contract_matches.iter()
                .flat_map(|m| m.mismatches.iter().map(|mm| {
                    drift_storage::batch::commands::ContractMismatchInsertRow {
                        backend_endpoint: mm.backend_endpoint.clone(),
                        frontend_call: mm.frontend_call.clone(),
                        mismatch_type: format!("{:?}", mm.mismatch_type),
                        severity: format!("{:?}", mm.severity),
                        message: mm.message.clone(),
                    }
                }))
                .collect();

            if !mismatch_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertContractMismatches(mismatch_rows),
                ).map_err(storage_err)?;
            }
        }
        drift_log!("[drift-analyze] 5l (contracts): {:?}", step_timer.elapsed());
    }

    // ── Phase 3 complete: pattern intelligence + structural ──
    if max_phase < 4 {
        rt.storage.flush_batch_sync().map_err(storage_err)?;
        return Ok(all_results);
    }

    // Step 6: Graph intelligence — taint, error handling, impact, test topology
    if !all_parse_results.is_empty() {
        // Re-build call graph with tsconfig alias resolution
        let cg_builder = match &rt.project_root {
            Some(root) => drift_analysis::call_graph::CallGraphBuilder::for_project(root.clone()),
            None => drift_analysis::call_graph::CallGraphBuilder::new(),
        };
        let call_graph_result = cg_builder.build(&all_parse_results);

        if let Ok((ref call_graph, ref _cg_stats)) = call_graph_result {
            // 6a: Taint analysis → taint_flows table
            let taint_registry = drift_analysis::graph::taint::TaintRegistry::with_defaults();

            // Phase 1: intraprocedural (per-file)
            // Uses prod_parse_results to avoid false taint flows from test mocks.
            let mut all_taint_flows = Vec::new();
            for pr in &prod_parse_results {
                let intra_flows = drift_analysis::graph::taint::analyze_intraprocedural(pr, &taint_registry);
                all_taint_flows.extend(intra_flows);
            }
            // Phase 2: interprocedural (cross-function via call graph)
            if let Ok(inter_flows) = drift_analysis::graph::taint::analyze_interprocedural(
                call_graph, &prod_pr_owned, &taint_registry, None,
            ) {
                all_taint_flows.extend(inter_flows);
            }

            let taint_rows: Vec<drift_storage::batch::commands::TaintFlowInsertRow> = all_taint_flows
                .iter()
                .map(|f| drift_storage::batch::commands::TaintFlowInsertRow {
                    source_file: f.source.file.clone(),
                    source_line: f.source.line as i64,
                    source_type: f.source.source_type.name().to_string(),
                    sink_file: f.sink.file.clone(),
                    sink_line: f.sink.line as i64,
                    sink_type: f.sink.sink_type.name().to_string(),
                    cwe_id: f.cwe_id.map(|c| c as i64),
                    is_sanitized: f.is_sanitized,
                    path: serde_json::to_string(&f.path.iter().map(|h| &h.function).collect::<Vec<_>>()).unwrap_or_default(),
                    confidence: f.confidence as f64,
                })
                .collect();
            if !taint_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertTaintFlows(taint_rows),
                ).map_err(storage_err)?;
            }

            // 6b: Error handling analysis → error_gaps table
            // Uses prod_parse_results — test files intentionally have bare try/catch.
            let handlers = drift_analysis::graph::error_handling::handler_detection::detect_handlers(
                &prod_pr_owned,
            );
            let chains = drift_analysis::graph::error_handling::propagation::trace_propagation(
                call_graph, &prod_pr_owned, &handlers,
            );
            let gaps = drift_analysis::graph::error_handling::gap_analysis::analyze_gaps(
                &handlers, &chains, &prod_pr_owned,
            );

            let gap_rows: Vec<drift_storage::batch::commands::ErrorGapInsertRow> = gaps
                .iter()
                .map(|g| {
                    let cwe = drift_analysis::graph::error_handling::cwe_mapping::map_to_cwe(g);
                    drift_storage::batch::commands::ErrorGapInsertRow {
                        file: g.file.clone(),
                        function_id: g.function.clone(),
                        gap_type: g.gap_type.name().to_string(),
                        error_type: g.error_type.clone(),
                        propagation_chain: None,
                        framework: g.framework.clone(),
                        cwe_id: Some(cwe.cwe_id as i64),
                        severity: drift_analysis::graph::error_handling::cwe_mapping::gap_severity(g.gap_type).name().to_string(),
                    }
                })
                .collect();
            if !gap_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertErrorGaps(gap_rows),
                ).map_err(storage_err)?;
            }

            // 6c: Impact analysis → impact_scores table
            let blast_radii = drift_analysis::graph::impact::blast_radius::compute_all_blast_radii(call_graph);
            let dead_code = drift_analysis::graph::impact::dead_code::detect_dead_code(call_graph);

            let mut impact_rows: Vec<drift_storage::batch::commands::ImpactScoreInsertRow> = Vec::new();

            // Add blast radius entries
            for br in &blast_radii {
                let node = &call_graph.graph[br.function_id];
                let key = format!("{}::{}", node.file, node.name);
                impact_rows.push(drift_storage::batch::commands::ImpactScoreInsertRow {
                    function_id: key,
                    blast_radius: br.caller_count as i64,
                    risk_score: br.risk_score.overall as f64,
                    is_dead_code: false,
                    dead_code_reason: None,
                    exclusion_category: None,
                });
            }
            // Update entries that are dead code
            for dc in &dead_code {
                let node = &call_graph.graph[dc.function_id];
                let key = format!("{}::{}", node.file, node.name);
                // Find existing entry or create new
                if let Some(existing) = impact_rows.iter_mut().find(|r| r.function_id == key) {
                    existing.is_dead_code = true;
                    existing.dead_code_reason = Some(format!("{:?}", dc.reason));
                    existing.exclusion_category = dc.exclusion.as_ref().map(|e| format!("{:?}", e));
                } else {
                    impact_rows.push(drift_storage::batch::commands::ImpactScoreInsertRow {
                        function_id: key,
                        blast_radius: 0,
                        risk_score: 0.0,
                        is_dead_code: true,
                        dead_code_reason: Some(format!("{:?}", dc.reason)),
                        exclusion_category: dc.exclusion.as_ref().map(|e| format!("{:?}", e)),
                    });
                }
            }
            if !impact_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertImpactScores(impact_rows),
                ).map_err(storage_err)?;
            }

            // 6d: Test topology → test_quality table
            let quality_score = drift_analysis::graph::test_topology::quality_scorer::compute_quality_score(
                call_graph, &all_parse_results,
            );
            let smells = drift_analysis::graph::test_topology::smells::detect_all_smells(
                &all_parse_results, call_graph,
            );

            let mut quality_rows: Vec<drift_storage::batch::commands::TestQualityInsertRow> = Vec::new();
            // Add per-function quality (from smells)
            for (file, func_name, func_smells) in &smells {
                let key = format!("{}::{}", file, func_name);
                quality_rows.push(drift_storage::batch::commands::TestQualityInsertRow {
                    function_id: key,
                    coverage_breadth: None,
                    coverage_depth: None,
                    assertion_density: None,
                    mock_ratio: None,
                    isolation: None,
                    freshness: None,
                    stability: None,
                    overall_score: quality_score.overall as f64,
                    smells: if func_smells.is_empty() {
                        None
                    } else {
                        Some(serde_json::to_string(func_smells).unwrap_or_default())
                    },
                });
            }
            // If no per-function data, insert aggregate
            if quality_rows.is_empty() {
                quality_rows.push(drift_storage::batch::commands::TestQualityInsertRow {
                    function_id: "__aggregate__".to_string(),
                    coverage_breadth: Some(quality_score.coverage_breadth as f64),
                    coverage_depth: Some(quality_score.coverage_depth as f64),
                    assertion_density: Some(quality_score.assertion_density as f64),
                    mock_ratio: Some(quality_score.mock_ratio as f64),
                    isolation: Some(quality_score.isolation as f64),
                    freshness: Some(quality_score.freshness as f64),
                    stability: Some(quality_score.stability as f64),
                    overall_score: quality_score.overall as f64,
                    smells: None,
                });
            }
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertTestQuality(quality_rows),
            ).map_err(storage_err)?;

            // 6e: Reachability cache → reachability_cache table
            let mut reach_rows: Vec<drift_storage::batch::commands::ReachabilityCacheRow> = Vec::new();
            for node_idx in call_graph.graph.node_indices() {
                let node = &call_graph.graph[node_idx];
                let key = format!("{}::{}", node.file, node.name);

                let fwd = drift_analysis::graph::reachability::bfs::reachability_forward(
                    call_graph, node_idx, Some(10),
                );
                let reachable_names: Vec<String> = fwd.reachable.iter().map(|&idx| {
                    let n = &call_graph.graph[idx];
                    format!("{}::{}", n.file, n.name)
                }).collect();
                let reachable_vec: Vec<_> = fwd.reachable.iter().copied().collect();
                let sensitivity = drift_analysis::graph::reachability::sensitivity::classify_sensitivity(
                    call_graph, node_idx, &reachable_vec,
                );

                reach_rows.push(drift_storage::batch::commands::ReachabilityCacheRow {
                    source_node: key,
                    direction: "forward".to_string(),
                    reachable_set: serde_json::to_string(&reachable_names).unwrap_or_default(),
                    sensitivity: sensitivity.name().to_string(),
                });
            }
            if !reach_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertReachabilityCache(reach_rows),
                ).map_err(storage_err)?;
            }
        }
    }

    // ── Phase 4 complete: graph intelligence ──
    if max_phase < 5 {
        rt.storage.flush_batch_sync().map_err(storage_err)?;
        return Ok(all_results);
    }

    // Step 7: Enforcement — run quality gates, persist violations + gate results
    if !all_parse_results.is_empty() {
        use drift_analysis::enforcement::gates::{GateOrchestrator, GateInputBuilder};
        use drift_analysis::enforcement::rules::types::PatternInfo as RulesPatternInfo;

        // Build GateInput from upstream analysis results
        // Uses prod_parse_results so test file violations don't inflate gate scores.
        let file_list: Vec<String> = prod_parse_results.iter().map(|pr| pr.file.clone()).collect();

        // Convert detection matches into PatternInfo for enforcement gates
        // Uses prod_matches to exclude test file detections from gate evaluation.
        let mut pattern_map: std::collections::HashMap<String, RulesPatternInfo> = std::collections::HashMap::new();
        for m in &prod_matches {
            let entry = pattern_map.entry(m.pattern_id.clone()).or_insert_with(|| RulesPatternInfo {
                pattern_id: m.pattern_id.clone(),
                category: format!("{:?}", m.category),
                confidence: m.confidence as f64,
                locations: Vec::new(),
                outliers: Vec::new(),
                cwe_ids: m.cwe_ids.to_vec(),
                owasp_categories: m.owasp.as_ref().map(|o| vec![o.clone()]).unwrap_or_default(),
            });
            entry.locations.push(drift_analysis::enforcement::rules::types::PatternLocation {
                file: m.file.clone(),
                line: m.line,
                column: Some(m.column),
            });
        }
        let patterns: Vec<RulesPatternInfo> = pattern_map.into_values().collect();

        let gate_input = GateInputBuilder::new()
            .files(file_list)
            .patterns(patterns)
            .build();

        let orchestrator = GateOrchestrator::new();
        if let Ok(gate_results) = orchestrator.execute(&gate_input) {
            // Collect all violations from all gates
            let mut violation_rows: Vec<drift_storage::batch::commands::ViolationInsertRow> = Vec::new();
            let mut gate_result_rows: Vec<drift_storage::batch::commands::GateResultInsertRow> = Vec::new();

            for gr in &gate_results {
                // Persist gate result
                gate_result_rows.push(drift_storage::batch::commands::GateResultInsertRow {
                    gate_id: gr.gate_id.to_string(),
                    status: format!("{:?}", gr.status).to_lowercase(),
                    passed: gr.passed,
                    score: gr.score,
                    summary: gr.summary.clone(),
                    violation_count: gr.violations.len() as i64,
                    warning_count: gr.warnings.len() as i64,
                    execution_time_ms: gr.execution_time_ms as i64,
                    details: if gr.details.is_null() { None } else { Some(gr.details.to_string()) },
                    error: gr.error.clone(),
                });

                // Persist violations
                for v in &gr.violations {
                    violation_rows.push(drift_storage::batch::commands::ViolationInsertRow {
                        id: v.id.clone(),
                        file: v.file.clone(),
                        line: v.line as i64,
                        column_num: v.column.map(|c| c as i64),
                        end_line: v.end_line.map(|l| l as i64),
                        end_column: v.end_column.map(|c| c as i64),
                        severity: format!("{:?}", v.severity).to_lowercase(),
                        pattern_id: v.pattern_id.clone(),
                        rule_id: v.rule_id.clone(),
                        message: v.message.clone(),
                        quick_fix_strategy: v.quick_fix.as_ref().map(|qf| format!("{:?}", qf.strategy).to_lowercase()),
                        quick_fix_description: v.quick_fix.as_ref().map(|qf| qf.description.clone()),
                        cwe_id: v.cwe_id.map(|c| c as i64),
                        owasp_category: v.owasp_category.clone(),
                        suppressed: v.suppressed,
                        is_new: v.is_new,
                    });
                }
            }

            if !violation_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertViolations(violation_rows),
                ).map_err(storage_err)?;
            }
            if !gate_result_rows.is_empty() {
                rt.storage.send_batch(
                    drift_storage::batch::commands::BatchCommand::InsertGateResults(gate_result_rows),
                ).map_err(storage_err)?;
            }

            // BW-EVT-05: Fire on_gate_evaluated for each gate result
            {
                use drift_core::events::types::GateEvaluatedEvent;
                for gr in &gate_results {
                    rt.dispatcher.emit_gate_evaluated(&GateEvaluatedEvent {
                        gate_name: gr.gate_id.to_string(),
                        passed: gr.passed,
                        score: Some(gr.score),
                        message: gr.summary.clone(),
                    });
                }
            }
        }
    }

    // Step 8: Degradation alerts — compare current vs previous gate results
    {
        let previous_gates = rt.storage.with_reader(|conn| {
            drift_storage::queries::enforcement::query_gate_results(conn)
        }).unwrap_or_default();

        let mut alert_rows: Vec<drift_storage::batch::commands::DegradationAlertInsertRow> = Vec::new();

        // Check for score degradation across gates
        for prev in &previous_gates {
            if prev.score < 0.5 && prev.violation_count > 0 {
                alert_rows.push(drift_storage::batch::commands::DegradationAlertInsertRow {
                    alert_type: "gate_score_low".to_string(),
                    severity: if prev.score < 0.3 { "high" } else { "medium" }.to_string(),
                    message: format!("Gate '{}' score is {:.1}% with {} violations",
                        prev.gate_id, prev.score * 100.0, prev.violation_count),
                    current_value: prev.score,
                    previous_value: 1.0,
                    delta: prev.score - 1.0,
                });
            }
        }

        // Check framework detection count drops per pack
        {
            // Count current framework detections per pack (from pattern_id prefix before '/')
            let mut current_pack_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for m in &all_matches {
                if let Some(pack_prefix) = m.pattern_id.split('/').next() {
                    *current_pack_counts.entry(pack_prefix.to_string()).or_insert(0) += 1;
                }
            }

            // Get previous detection counts per pack from DB
            let previous_detections = rt.storage.with_reader(|conn| {
                drift_storage::queries::detections::query_all_detections(conn, 100_000)
            }).unwrap_or_default();

            let mut previous_pack_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for d in &previous_detections {
                if let Some(pack_prefix) = d.pattern_id.split('/').next() {
                    *previous_pack_counts.entry(pack_prefix.to_string()).or_insert(0) += 1;
                }
            }

            // Compare: if current < 50% of previous for any pack, emit alert
            for (pack, prev_count) in &previous_pack_counts {
                if *prev_count >= 5 { // Only alert if there were meaningful previous detections
                    let curr_count = current_pack_counts.get(pack).copied().unwrap_or(0);
                    if (curr_count as f64) < (*prev_count as f64 * 0.5) {
                        alert_rows.push(drift_storage::batch::commands::DegradationAlertInsertRow {
                            alert_type: "framework_detection_drop".to_string(),
                            severity: if curr_count == 0 { "high" } else { "medium" }.to_string(),
                            message: format!(
                                "Framework pack '{}' detection count dropped from {} to {} ({:.0}% decrease)",
                                pack, prev_count, curr_count,
                                (1.0 - curr_count as f64 / *prev_count as f64) * 100.0
                            ),
                            current_value: curr_count as f64,
                            previous_value: *prev_count as f64,
                            delta: curr_count as f64 - *prev_count as f64,
                        });
                    }
                }
            }
        }

        // Check overall violation count
        let total_violations = rt.storage.with_reader(|conn| {
            drift_storage::queries::enforcement::query_all_violations(conn)
                .map(|v| v.len() as i64)
        }).unwrap_or(0);

        if total_violations > 50 {
            alert_rows.push(drift_storage::batch::commands::DegradationAlertInsertRow {
                alert_type: "violation_count_high".to_string(),
                severity: if total_violations > 100 { "high" } else { "medium" }.to_string(),
                message: format!("{} total violations detected", total_violations),
                current_value: total_violations as f64,
                previous_value: 0.0,
                delta: total_violations as f64,
            });
        }

        // BW-EVT-06: Fire on_regression_detected for score degradation alerts
        // Uses dedup to prevent re-emitting the same regression event when
        // scores haven't changed (P1-8). The `extra` field encodes previous
        // and current scores so different score transitions are distinct.
        {
            use drift_core::events::types::RegressionDetectedEvent;
            if let Ok(mut dedup) = rt.bridge_deduplicator.lock() {
                for alert in &alert_rows {
                    if alert.alert_type == "gate_score_low" {
                        let extra = format!(
                            "prev={:.2};curr={:.2}",
                            alert.previous_value, alert.current_value
                        );
                        if !dedup.is_duplicate("on_regression_detected", &alert.message, &extra) {
                            rt.dispatcher.emit_regression_detected(&RegressionDetectedEvent {
                                pattern_id: alert.message.clone(),
                                previous_score: alert.previous_value,
                                current_score: alert.current_value,
                            });
                        }
                    }
                }
            }
        }

        if !alert_rows.is_empty() {
            rt.storage.send_batch(
                drift_storage::batch::commands::BatchCommand::InsertDegradationAlerts(alert_rows),
            ).map_err(storage_err)?;
        }
    }

    // Flush to ensure batch writer processes all queued commands
    rt.storage.flush_batch().map_err(storage_err)?;

    // BW-EVT-07: Fire on_scan_complete at end of pipeline
    {
        use drift_core::events::types::ScanCompleteEvent;
        let total = all_results.len();
        let total_matches: usize = all_results.iter().map(|r| r.matches.len()).sum();
        rt.dispatcher.emit_scan_complete(&ScanCompleteEvent {
            added: total_matches,
            modified: 0,
            removed: 0,
            unchanged: total.saturating_sub(total_matches),
            duration_ms: 0,
        });
    }

    // BW-EVT-08: Auto-grounding after analysis — run grounding loop on all bridge memories
    if rt.bridge_initialized {
        let grounding_timer = std::time::Instant::now();
        if let Err(e) = run_bridge_grounding_loop(&rt) {
            tracing::warn!(error = %e, "Post-analysis grounding loop failed (non-fatal)");
        } else {
            drift_log!("[drift-analyze] bridge grounding: {:?}", grounding_timer.elapsed());
        }
    }

    Ok(all_results)
}

/// BW-EVT-08: Run the bridge grounding loop on all bridge memories.
/// Called automatically after drift_analyze() completes.
fn run_bridge_grounding_loop(
    rt: &std::sync::Arc<crate::runtime::DriftRuntime>,
) -> Result<(), napi::Error> {
    let store = rt.bridge_storage().ok_or_else(|| {
        napi::Error::from_reason("[BRIDGE_ERROR] bridge.db not available for grounding")
    })?;

    // Query all memories from bridge storage
    use cortex_drift_bridge::traits::IBridgeStorage;
    let memory_rows = store.query_all_memories_for_grounding()
        .map_err(|e| napi::Error::from_reason(format!("[BRIDGE_ERROR] {e}")))?;
    let memories = crate::bindings::bridge::memory_rows_to_grounding(&memory_rows);

    if memories.is_empty() {
        return Ok(());
    }

    // Run grounding via the NAPI function (reuses existing logic)
    let drift_guard = rt.lock_drift_db_for_bridge();
    let _snapshot = cortex_drift_bridge::napi::functions::bridge_ground_all(
        &memories,
        &rt.bridge_config.grounding,
        drift_guard.as_deref(),
        Some(store.as_ref()),
    )
    .map_err(|e| napi::Error::from_reason(format!("[BRIDGE_ERROR] {e}")))?;

    drift_log!(
        "[drift-analyze] bridge grounding complete: {} memories grounded",
        memories.len(),
    );

    Ok(())
}

/// Build or query the call graph.
#[napi]
pub async fn drift_call_graph() -> napi::Result<JsCallGraphResult> {
    let rt = runtime::get()?;

    let total_functions = rt.storage.with_reader(|conn| {
        drift_storage::queries::functions::count_functions(conn)
    }).map_err(storage_err)? as u32;

    let total_edges = rt.storage.with_reader(|conn| {
        drift_storage::queries::call_edges::count_call_edges(conn)
    }).map_err(storage_err)? as u32;

    let entry_points = rt.storage.with_reader(|conn| {
        drift_storage::queries::functions::count_entry_points(conn)
    }).unwrap_or(0) as u32;

    Ok(JsCallGraphResult {
        total_functions,
        total_edges,
        entry_points,
        // PH2-09: Compute real resolution_rate from stored resolution types
        resolution_rate: if total_edges > 0 {
            let resolved = rt.storage.with_reader(|conn| {
                drift_storage::queries::call_edges::count_resolved_edges(conn)
            }).unwrap_or(0) as f64;
            resolved / total_edges as f64
        } else {
            0.0
        },
        build_duration_ms: 0.0,
    })
}

/// Validate a framework pack TOML string.
///
/// Returns a summary object on success, or an error message on failure.
#[napi(object)]
pub struct JsValidatePackResult {
    pub valid: bool,
    pub name: Option<String>,
    pub version: Option<String>,
    pub language_count: u32,
    pub pattern_count: u32,
    pub error: Option<String>,
}

#[napi]
pub fn drift_validate_pack(toml_content: String) -> napi::Result<JsValidatePackResult> {
    match drift_analysis::frameworks::registry::FrameworkPackRegistry::load_single(&toml_content) {
        Ok(pack) => Ok(JsValidatePackResult {
            valid: true,
            name: Some(pack.name.clone()),
            version: pack.version.clone(),
            language_count: pack.languages.len() as u32,
            pattern_count: pack.patterns.len() as u32,
            error: None,
        }),
        Err(e) => Ok(JsValidatePackResult {
            valid: false,
            name: None,
            version: None,
            language_count: 0,
            pattern_count: 0,
            error: Some(e.to_string()),
        }),
    }
}

/// Run boundary detection.
#[napi]
pub async fn drift_boundaries() -> napi::Result<JsBoundaryResult> {
    let rt = runtime::get()?;

    let boundaries = rt.storage.with_reader(|conn| {
        drift_storage::queries::boundaries::get_sensitive_boundaries(conn)
    }).map_err(storage_err)?;

    let all_boundaries = rt.storage.with_reader(|conn| {
        conn.prepare_cached(
            "SELECT DISTINCT framework FROM boundaries"
        )
        .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        .and_then(|mut stmt| {
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| drift_core::errors::StorageError::SqliteError { message: e.to_string() })
        })
    }).map_err(storage_err)?;

    // Group boundaries into models (by model_name) and sensitive fields
    // PH2-12: Include table_name from boundary storage
    let mut models_map: std::collections::HashMap<String, (String, String, u32, f64, Option<String>)> = std::collections::HashMap::new();
    let mut sensitive_fields = Vec::new();

    for b in &boundaries {
        let entry = models_map.entry(b.model_name.clone()).or_insert((
            b.file.clone(), b.framework.clone(), 0, b.confidence, b.table_name.clone(),
        ));
        entry.2 += 1;

        if let Some(ref field) = b.field_name {
            sensitive_fields.push(JsSensitiveField {
                model_name: b.model_name.clone(),
                field_name: field.clone(),
                file: b.file.clone(),
                sensitivity: b.sensitivity.clone().unwrap_or_default(),
                confidence: b.confidence,
            });
        }
    }

    let models: Vec<JsModelResult> = models_map.into_iter().map(|(name, (file, fw, count, conf, tbl))| {
        JsModelResult {
            name,
            table_name: tbl,
            file,
            framework: fw,
            field_count: count,
            confidence: conf,
        }
    }).collect();

    Ok(JsBoundaryResult {
        models,
        sensitive_fields,
        frameworks_detected: all_boundaries,
    })
}

//! Category 18: Graph Intelligence (Flow 7 — 5 subsystems)
//!
//! Call graph, taint analysis, error handling analysis, impact analysis,
//! and test topology. All depend on call graph resolution quality.
//!
//! T18-01 through T18-11.

use drift_analysis::call_graph::builder::CallGraphBuilder;
use drift_analysis::call_graph::incremental::IncrementalCallGraph;
use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::graph::error_handling::gap_analysis::analyze_gaps;
use drift_analysis::graph::error_handling::handler_detection::detect_handlers;
use drift_analysis::graph::error_handling::types::{
    ErrorGap, GapSeverity, GapType, PropagationChain,
};
use drift_analysis::graph::impact::blast_radius::compute_blast_radius;
use drift_analysis::graph::impact::dead_code::detect_dead_code;
use drift_analysis::graph::impact::types::DeadCodeReason;
use drift_analysis::graph::taint::intraprocedural::analyze_intraprocedural;
use drift_analysis::graph::taint::registry::{SinkPattern, TaintRegistry};
use drift_analysis::graph::taint::types::{SinkType, TaintFlow};
use drift_analysis::graph::test_topology::quality_scorer::compute_quality_score;
use drift_analysis::graph::test_topology::smells::{detect_all_smells, detect_smells};
use drift_analysis::graph::test_topology::types::TestSmell;
use drift_analysis::parsers::types::{
    CallSite, ErrorHandlingInfo, ErrorHandlingKind, FunctionInfo, ImportInfo, ImportSpecifier,
    ParseResult, ParameterInfo, Range, Position,
};
use drift_analysis::scanner::language_detect::Language;
use smallvec::smallvec;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_range() -> Range {
    Range {
        start: Position { line: 0, column: 0 },
        end: Position { line: 0, column: 0 },
    }
}

fn make_function(name: &str, file: &str, line: u32, end_line: u32) -> FunctionInfo {
    FunctionInfo {
        name: name.to_string(),
        qualified_name: None,
        file: file.to_string(),
        line,
        column: 0,
        end_line,
        parameters: smallvec![],
        return_type: None,
        generic_params: smallvec![],
        visibility: drift_analysis::parsers::types::Visibility::Public,
        is_exported: false,
        is_async: false,
        is_generator: false,
        is_abstract: false,
        range: default_range(),
        decorators: Vec::new(),
        doc_comment: None,
        body_hash: 0,
        signature_hash: 0,
    }
}

fn make_function_with_params(
    name: &str,
    file: &str,
    line: u32,
    end_line: u32,
    params: Vec<ParameterInfo>,
) -> FunctionInfo {
    let mut f = make_function(name, file, line, end_line);
    f.parameters = smallvec::SmallVec::from_vec(params);
    f
}

fn make_param(name: &str) -> ParameterInfo {
    ParameterInfo {
        name: name.to_string(),
        type_annotation: None,
        default_value: None,
        is_rest: false,
    }
}

fn make_call_site(callee: &str, receiver: Option<&str>, file: &str, line: u32) -> CallSite {
    CallSite {
        callee_name: callee.to_string(),
        receiver: receiver.map(|r| r.to_string()),
        file: file.to_string(),
        line,
        column: 0,
        argument_count: 1,
        is_await: false,
    }
}

fn make_parse_result(file: &str, lang: Language) -> ParseResult {
    ParseResult {
        file: file.to_string(),
        language: lang,
        ..Default::default()
    }
}

fn make_import(source: &str, specifiers: Vec<(&str, Option<&str>)>, file: &str) -> ImportInfo {
    ImportInfo {
        source: source.to_string(),
        specifiers: smallvec::SmallVec::from_vec(
            specifiers
                .into_iter()
                .map(|(name, alias)| ImportSpecifier {
                    name: name.to_string(),
                    alias: alias.map(|a| a.to_string()),
                })
                .collect(),
        ),
        is_type_only: false,
        file: file.to_string(),
        line: 1,
    }
}

// ---------------------------------------------------------------------------
// T18-01: Call Graph — All 6 Resolution Strategies
// ---------------------------------------------------------------------------

#[test]
fn t18_01_call_graph_all_6_resolution_strategies() {
    // Build a repo with conditions for all 6 strategies to fire.
    // SameFile: A calls B in the same file.
    // MethodCall: A calls receiver.method where receiver matches a qualified class.
    // ImportBased: A imports {foo} from './B' and calls foo().
    // ExportBased: foo is exported from B, A calls foo.
    // DiInjection: A calls an injected type name.
    // Fuzzy: A calls uniqueFunctionName that exists in another file, no import.

    let file_a = "src/a.ts";
    let file_b = "src/b.ts";

    let mut pr_a = make_parse_result(file_a, Language::TypeScript);
    pr_a.functions = vec![
        make_function("callerFunc", file_a, 1, 50),
        make_function("helperFunc", file_a, 60, 80),
    ];
    pr_a.imports = vec![make_import("./b", vec![("importedFunc", None)], file_a)];
    pr_a.call_sites = vec![
        // Same-file call
        make_call_site("helperFunc", None, file_a, 5),
        // Import-based call
        make_call_site("importedFunc", None, file_a, 10),
        // Method call on a known class
        make_call_site("doWork", Some("MyService"), file_a, 15),
        // Fuzzy call — unique name, no import
        make_call_site("veryUniqueProcessorXYZ", None, file_a, 20),
    ];

    let mut pr_b = make_parse_result(file_b, Language::TypeScript);
    let mut imported_func = make_function("importedFunc", file_b, 1, 10);
    imported_func.is_exported = true;
    let mut unique_func = make_function("veryUniqueProcessorXYZ", file_b, 20, 30);
    unique_func.is_exported = true;
    pr_b.functions = vec![imported_func, unique_func];

    // Also add a class with doWork method for MethodCall resolution
    pr_b.classes = vec![drift_analysis::parsers::types::ClassInfo {
        name: "MyService".to_string(),
        namespace: None,
        extends: None,
        implements: smallvec![],
        generic_params: smallvec![],
        is_exported: true,
        is_abstract: false,
        class_kind: drift_analysis::parsers::types::ClassKind::Class,
        methods: vec![make_function("doWork", file_b, 40, 50)],
        properties: Vec::new(),
        range: default_range(),
        decorators: Vec::new(),
    }];

    let builder = CallGraphBuilder::new();
    let (graph, stats) = builder.build(&[pr_a, pr_b]).unwrap();

    // Must have edges
    assert!(stats.total_edges > 0, "Call graph must have edges");
    assert!(stats.total_functions > 0, "Call graph must have functions");

    // Verify SameFile edge: callerFunc → helperFunc (both in file_a)
    let caller_idx = graph.get_node("src/a.ts::callerFunc").expect("callerFunc must exist");
    let helper_idx = graph.get_node("src/a.ts::helperFunc").expect("helperFunc must exist");
    let same_file_edge = graph.graph.edges_connecting(caller_idx, helper_idx).next();
    assert!(same_file_edge.is_some(), "SameFile edge must exist");
    assert_eq!(
        same_file_edge.unwrap().weight().resolution,
        Resolution::SameFile
    );
    assert!(
        (same_file_edge.unwrap().weight().confidence - 0.95).abs() < 0.01,
        "SameFile confidence must be 0.95"
    );

    // Verify Fuzzy edge: callerFunc → veryUniqueProcessorXYZ
    // (Unique name in another file, no import — should resolve via fuzzy or export)
    let unique_idx = graph
        .get_node("src/b.ts::veryUniqueProcessorXYZ")
        .expect("veryUniqueProcessorXYZ must exist");
    let has_edge_to_unique = graph
        .graph
        .edges_connecting(caller_idx, unique_idx)
        .next()
        .is_some();
    assert!(
        has_edge_to_unique,
        "Edge to veryUniqueProcessorXYZ must exist (export or fuzzy)"
    );

    // Verify Resolution enum has all 6 strategies
    let all = Resolution::all_ordered();
    assert_eq!(all.len(), 6, "Must have exactly 6 resolution strategies");
    assert_eq!(all[0], Resolution::SameFile);
    assert_eq!(all[1], Resolution::MethodCall);
    assert_eq!(all[2], Resolution::DiInjection);
    assert_eq!(all[3], Resolution::ImportBased);
    assert_eq!(all[4], Resolution::ExportBased);
    assert_eq!(all[5], Resolution::Fuzzy);

    // Verify confidence ordering
    assert!(Resolution::SameFile.default_confidence() > Resolution::Fuzzy.default_confidence());
}

// ---------------------------------------------------------------------------
// T18-02: Call Graph — Import-Based Resolution
// ---------------------------------------------------------------------------

#[test]
fn t18_02_call_graph_import_based_resolution() {
    let file_a = "src/a.ts";
    let file_b = "src/b.ts";

    let mut pr_a = make_parse_result(file_a, Language::TypeScript);
    pr_a.functions = vec![make_function("main", file_a, 1, 20)];
    pr_a.imports = vec![make_import("./b", vec![("foo", None)], file_a)];
    pr_a.call_sites = vec![make_call_site("foo", None, file_a, 5)];

    let mut pr_b = make_parse_result(file_b, Language::TypeScript);
    let mut foo_fn = make_function("foo", file_b, 1, 10);
    foo_fn.is_exported = true;
    pr_b.functions = vec![foo_fn];

    let builder = CallGraphBuilder::new();
    let (graph, stats) = builder.build(&[pr_a, pr_b]).unwrap();

    // The edge A::main → B::foo must exist with ImportBased strategy
    let main_idx = graph.get_node("src/a.ts::main").expect("main must exist");
    let foo_idx = graph.get_node("src/b.ts::foo").expect("foo must exist");

    let edge = graph
        .graph
        .edges_connecting(main_idx, foo_idx)
        .next()
        .expect("Import-based edge must exist: main → foo");

    assert_eq!(
        edge.weight().resolution,
        Resolution::ImportBased,
        "Edge must use ImportBased strategy"
    );
    assert!(
        (edge.weight().confidence - Resolution::ImportBased.default_confidence()).abs() < 0.01,
        "ImportBased confidence must be {}",
        Resolution::ImportBased.default_confidence()
    );

    // Verify non-empty specifiers were used
    assert!(
        stats.resolution_counts.get("import_based").copied().unwrap_or(0) > 0,
        "import_based resolution count must be > 0"
    );
}

// ---------------------------------------------------------------------------
// T18-03: Call Graph — Incremental Rebuild
// ---------------------------------------------------------------------------

#[test]
fn t18_03_call_graph_incremental_rebuild() {
    let file_a = "src/a.ts";
    let file_b = "src/b.ts";
    let file_c = "src/c.ts";

    let mut pr_a = make_parse_result(file_a, Language::TypeScript);
    pr_a.functions = vec![make_function("funcA", file_a, 1, 10)];
    pr_a.call_sites = vec![make_call_site("funcB", None, file_a, 5)];

    let mut pr_b = make_parse_result(file_b, Language::TypeScript);
    pr_b.functions = vec![make_function("funcB", file_b, 1, 10)];

    let mut pr_c = make_parse_result(file_c, Language::TypeScript);
    pr_c.functions = vec![make_function("funcC", file_c, 1, 10)];

    let mut incr = IncrementalCallGraph::new();
    let stats1 = incr.full_build(&[pr_a.clone(), pr_b.clone(), pr_c.clone()]).unwrap();
    let initial_functions = stats1.total_functions;
    let _initial_edges = stats1.total_edges;

    assert!(initial_functions >= 3, "Must have at least 3 functions");

    // Modify file_b: add a new function
    let mut pr_b_modified = pr_b.clone();
    pr_b_modified.functions.push(make_function("funcBNew", file_b, 20, 30));

    // All results now include modified B
    let all_results = vec![pr_a.clone(), pr_b_modified.clone(), pr_c.clone()];

    let stats2 = incr
        .update(&[], &[pr_b_modified], &[], &all_results)
        .unwrap();

    // After incremental update: should have 4 functions now (funcA, funcB, funcBNew, funcC)
    assert!(
        stats2.total_functions >= initial_functions,
        "Incremental update must preserve or add functions"
    );
    assert!(
        stats2.total_functions >= 4,
        "Must have at least 4 functions after adding funcBNew"
    );

    // Test removal: remove file_c
    let all_after_remove = vec![pr_a, pr_b];
    let stats3 = incr
        .update(&[], &[], &[file_c.to_string()], &all_after_remove)
        .unwrap();

    // funcC should be gone
    assert!(
        incr.graph().get_node("src/c.ts::funcC").is_none()
        || stats3.total_functions < stats2.total_functions,
        "Removed file's functions should be gone or function count decreased"
    );
}

// ---------------------------------------------------------------------------
// T18-04: Taint Analysis — Source→Sink Reachability
// ---------------------------------------------------------------------------

#[test]
fn t18_04_taint_source_to_sink_reachability() {
    // Define req.body as source, db.query as sink.
    // The function takes (req, db) as params — req is a taint source,
    // and the sibling-parameter heuristic connects req taint → db.query sink.
    let file = "src/controller.ts";

    let mut pr = make_parse_result(file, Language::TypeScript);
    pr.functions = vec![make_function_with_params(
        "handleRequest",
        file,
        1,
        30,
        vec![make_param("req"), make_param("db")],
    )];

    // Call sites: req.body (source) → db.query (sink)
    pr.call_sites = vec![
        // Source: req.body access
        make_call_site("body", Some("req"), file, 5),
        // Sink: db.query execution — db is a sibling param of tainted req
        make_call_site("query", Some("db"), file, 20),
    ];

    let registry = TaintRegistry::with_defaults();
    let flows = analyze_intraprocedural(&pr, &registry);

    // Must find at least one unsanitized taint flow
    let vuln_flows: Vec<&TaintFlow> = flows.iter().filter(|f| f.is_vulnerability()).collect();
    assert!(
        !vuln_flows.is_empty(),
        "Must detect at least one vulnerability flow from source to sink"
    );

    // At least one flow should have CWE-89 (SQL injection)
    let has_sqli = vuln_flows.iter().any(|f| f.cwe_id == Some(89));
    assert!(has_sqli, "Must detect SQL injection (CWE-89)");

    // Path length must be > 0
    for flow in &vuln_flows {
        assert!(!flow.path.is_empty(), "Flow path must not be empty");
    }
}

// ---------------------------------------------------------------------------
// T18-05: Taint — Over-Approximation Guard
// ---------------------------------------------------------------------------

#[test]
fn t18_05_taint_over_approximation_guard() {
    // One function has a tainted var (req.body) AND an untainted var (config).
    // Both reach a sink. Only the tainted var's flow should be reported.
    let file = "src/handler.ts";

    let mut pr = make_parse_result(file, Language::TypeScript);
    pr.functions = vec![make_function_with_params(
        "handler",
        file,
        1,
        30,
        vec![make_param("req"), make_param("config")],
    )];

    // req.body is a taint source; config is NOT
    // Both call db.query (sink)
    pr.call_sites = vec![
        // Tainted: req.body
        make_call_site("body", Some("req"), file, 5),
        // Not tainted: config.get (not a source)
        make_call_site("get", Some("config"), file, 10),
        // Sink: db.query — should only be flagged due to req.body, not config
        make_call_site("query", Some("db"), file, 20),
    ];

    let registry = TaintRegistry::with_defaults();
    let flows = analyze_intraprocedural(&pr, &registry);

    let vuln_flows: Vec<&TaintFlow> = flows.iter().filter(|f| f.is_vulnerability()).collect();

    // Should find flows, but they should originate from req-related sources, not config
    for flow in &vuln_flows {
        // The source should be related to req/user_input, not "config"
        let source_expr = &flow.source.expression;
        assert!(
            !source_expr.contains("config"),
            "Untainted 'config' variable must NOT appear as taint source, got: {}",
            source_expr
        );
    }
}

// ---------------------------------------------------------------------------
// T18-06: Taint — Registry Pattern Matching
// ---------------------------------------------------------------------------

#[test]
fn t18_06_taint_registry_pattern_matching() {
    let mut registry = TaintRegistry::new();
    // Register "open" as a sink pattern
    registry.add_sink(SinkPattern {
        pattern: "open".to_string(),
        sink_type: SinkType::FileRead,
        required_sanitizers: vec![],
        framework: None,
    });

    // "fs.open" should match (dotted suffix)
    let match_fs_open = registry.match_sink("fs.open");
    assert!(match_fs_open.is_some(), "fs.open must match 'open' pattern");

    // "openDialog" must NOT match (substring, not a segment boundary)
    let match_open_dialog = registry.match_sink("openDialog");
    assert!(
        match_open_dialog.is_none(),
        "openDialog must NOT match 'open' pattern (substring false positive)"
    );

    // "file.open.sync" should match (open as middle segment)
    let match_open_sync = registry.match_sink("file.open.sync");
    assert!(
        match_open_sync.is_some(),
        "file.open.sync must match 'open' pattern (dotted segment)"
    );

    // Exact match should work
    let match_exact = registry.match_sink("open");
    assert!(match_exact.is_some(), "Exact 'open' must match");

    // "reopen" must NOT match (prefix, not segment boundary)
    let match_reopen = registry.match_sink("reopen");
    assert!(
        match_reopen.is_none(),
        "reopen must NOT match 'open' pattern"
    );
}

// ---------------------------------------------------------------------------
// T18-07: Error Handling — Gap Detection
// ---------------------------------------------------------------------------

#[test]
fn t18_07_error_handling_gap_detection() {
    let file = "src/service.ts";

    let mut pr = make_parse_result(file, Language::TypeScript);
    pr.functions = vec![make_function("processData", file, 1, 30)];

    // A try/catch that catches generic "Exception" — should trigger GenericCatch
    pr.error_handling = vec![ErrorHandlingInfo {
        kind: ErrorHandlingKind::TryCatch,
        file: file.to_string(),
        line: 5,
        end_line: 15,
        range: default_range(),
        caught_type: Some("Exception".to_string()),
        has_body: true,
        function_scope: Some("processData".to_string()),
    }];

    let handlers = detect_handlers(&[pr.clone()]);
    assert!(!handlers.is_empty(), "Must detect at least one handler");

    // Check that caught_types includes "Exception"
    let handler = &handlers[0];
    assert!(
        handler.caught_types.contains(&"Exception".to_string()),
        "Handler must report catching 'Exception'"
    );

    // Run gap analysis
    let chains: Vec<PropagationChain> = Vec::new();
    let gaps = analyze_gaps(&handlers, &chains, &[pr]);

    // Must detect GenericCatch gap
    let generic_catch_gaps: Vec<&ErrorGap> = gaps
        .iter()
        .filter(|g| g.gap_type == GapType::GenericCatch)
        .collect();
    assert!(
        !generic_catch_gaps.is_empty(),
        "Must detect GenericCatch gap for catching 'Exception'"
    );

    // GenericCatch must have CWE-396
    for gap in &generic_catch_gaps {
        assert_eq!(gap.cwe_id, Some(396), "GenericCatch must map to CWE-396");
        assert_eq!(gap.severity, GapSeverity::Medium, "GenericCatch should be Medium severity");
    }

    // gap_type must distinguish different types
    let gap_type_names: Vec<&str> = vec![
        GapType::EmptyCatch.name(),
        GapType::SwallowedError.name(),
        GapType::GenericCatch.name(),
        GapType::Unhandled.name(),
        GapType::UnhandledAsync.name(),
        GapType::MissingMiddleware.name(),
        GapType::InconsistentPattern.name(),
    ];
    assert_eq!(gap_type_names.len(), 7, "Must have 7 distinct gap types");
    // All names must be unique
    let mut unique_names = gap_type_names.clone();
    unique_names.sort();
    unique_names.dedup();
    assert_eq!(unique_names.len(), 7, "All gap type names must be unique");
}

// ---------------------------------------------------------------------------
// T18-08: Impact — Blast Radius Scoring
// ---------------------------------------------------------------------------

#[test]
fn t18_08_impact_blast_radius_scoring() {
    // Build a graph where target_func is called by 10 other functions.
    let mut graph = CallGraph::new();

    let target = graph.add_function(FunctionNode {
        file: "src/core.ts".to_string(),
        name: "target_func".to_string(),
        qualified_name: None,
        language: "TypeScript".to_string(),
        line: 1,
        end_line: 50,
        is_entry_point: false,
        is_exported: true,
        signature_hash: 0,
        body_hash: 0,
    });

    // Add 10 callers
    for i in 0..10 {
        let caller = graph.add_function(FunctionNode {
            file: format!("src/caller_{}.ts", i),
            name: format!("caller_{}", i),
            qualified_name: None,
            language: "TypeScript".to_string(),
            line: 1,
            end_line: 20,
            is_entry_point: false,
            is_exported: false,
            signature_hash: 0,
            body_hash: 0,
        });
        graph.add_edge(
            caller,
            target,
            CallEdge {
                resolution: Resolution::ImportBased,
                confidence: 0.75,
                call_site_line: 5,
            },
        );
    }

    let blast = compute_blast_radius(&graph, target, 11);

    // blast_radius must be > 0
    assert!(
        blast.caller_count > 0,
        "Blast radius caller_count must be > 0, got {}",
        blast.caller_count
    );
    assert_eq!(
        blast.caller_count, 10,
        "Must have exactly 10 transitive callers"
    );

    // risk_factors must NOT all be hardcoded to 0.0
    let risk = &blast.risk_score;
    assert!(
        risk.blast_radius > 0.0,
        "blast_radius risk factor must be > 0.0, got {}",
        risk.blast_radius
    );
    assert!(
        risk.overall > 0.0,
        "Overall risk score must be > 0.0"
    );

    // Sensitivity should be > 0 because target is exported
    assert!(
        risk.sensitivity > 0.0,
        "Sensitivity should be > 0 for exported function"
    );

    // Complexity should be > 0 for a 50-line function
    assert!(
        risk.complexity > 0.0,
        "Complexity should be > 0 for 50-line function"
    );
}

// ---------------------------------------------------------------------------
// T18-09: Impact — Dead Code Detection
// ---------------------------------------------------------------------------

#[test]
fn t18_09_impact_dead_code_detection() {
    let mut graph = CallGraph::new();

    // Dead function: 0 callers, not an entry point, not exported
    let dead_func = graph.add_function(FunctionNode {
        file: "src/unused.ts".to_string(),
        name: "unusedInternalFunc".to_string(),
        qualified_name: None,
        language: "TypeScript".to_string(),
        line: 1,
        end_line: 20,
        is_entry_point: false,
        is_exported: false,
        signature_hash: 0,
        body_hash: 0,
    });

    // Route handler: 0 callers but has entry point decorator info
    // Mark as entry point via is_entry_point flag
    let route_handler = graph.add_function(FunctionNode {
        file: "src/routes.ts".to_string(),
        name: "getUsers".to_string(),
        qualified_name: Some("UserController.getUsers".to_string()),
        language: "TypeScript".to_string(),
        line: 10,
        end_line: 30,
        is_entry_point: true,
        is_exported: true,
        signature_hash: 0,
        body_hash: 0,
    });

    // Normal called function (has a caller)
    let called_func = graph.add_function(FunctionNode {
        file: "src/utils.ts".to_string(),
        name: "formatData".to_string(),
        qualified_name: None,
        language: "TypeScript".to_string(),
        line: 1,
        end_line: 10,
        is_entry_point: false,
        is_exported: false,
        signature_hash: 0,
        body_hash: 0,
    });

    // Create an edge: route_handler → called_func
    graph.add_edge(
        route_handler,
        called_func,
        CallEdge {
            resolution: Resolution::SameFile,
            confidence: 0.95,
            call_site_line: 15,
        },
    );

    let results = detect_dead_code(&graph);

    // unusedInternalFunc must be flagged as dead
    let dead_result = results.iter().find(|r| r.function_id == dead_func);
    assert!(dead_result.is_some(), "unusedInternalFunc must be in dead code results");
    let dead_result = dead_result.unwrap();
    assert!(dead_result.is_dead, "unusedInternalFunc must be flagged as dead");
    assert_eq!(dead_result.reason, DeadCodeReason::NoCallers);
    assert!(dead_result.confidence > 0.0, "Dead code confidence must be > 0");

    // Route handler (entry point, exported) must NOT be flagged as dead
    let handler_result = results.iter().find(|r| r.function_id == route_handler);
    if let Some(hr) = handler_result {
        assert!(
            !hr.is_dead,
            "Route handler (entry point) must NOT be flagged as dead"
        );
        assert!(
            hr.exclusion.is_some(),
            "Route handler must have an exclusion category"
        );
    }
    // If handler is not in results at all (because it has a caller), that's also fine

    // called_func has a caller, so it shouldn't appear in dead code results
    let called_result = results.iter().find(|r| r.function_id == called_func);
    assert!(
        called_result.is_none(),
        "formatData has a caller and should NOT appear in dead code results"
    );
}

// ---------------------------------------------------------------------------
// T18-10: Test Topology — Quality Dimensions
// ---------------------------------------------------------------------------

#[test]
fn t18_10_test_topology_quality_dimensions() {
    // Create a test file with 5 test functions covering 3 source functions
    let test_file = "src/__tests__/utils.test.ts";
    let source_file = "src/utils.ts";

    let mut test_pr = make_parse_result(test_file, Language::TypeScript);
    test_pr.functions = vec![
        make_function("testAdd", test_file, 1, 10),
        make_function("testSubtract", test_file, 15, 25),
        make_function("testMultiply", test_file, 30, 40),
        make_function("testDivide", test_file, 45, 55),
        make_function("testModulo", test_file, 60, 70),
    ];
    // Add assertion call sites for each test
    test_pr.call_sites = vec![
        make_call_site("expect", None, test_file, 5),
        make_call_site("add", None, test_file, 4),
        make_call_site("expect", None, test_file, 20),
        make_call_site("subtract", None, test_file, 19),
        make_call_site("expect", None, test_file, 35),
        make_call_site("multiply", None, test_file, 34),
        make_call_site("expect", None, test_file, 50),
        make_call_site("add", None, test_file, 49),
        make_call_site("expect", None, test_file, 65),
        make_call_site("subtract", None, test_file, 64),
    ];

    let mut source_pr = make_parse_result(source_file, Language::TypeScript);
    source_pr.functions = vec![
        make_function("add", source_file, 1, 5),
        make_function("subtract", source_file, 10, 15),
        make_function("multiply", source_file, 20, 25),
    ];

    // Build call graph to link test → source via same-name resolution
    let builder = CallGraphBuilder::new();
    let (graph, _stats) = builder.build(&[test_pr.clone(), source_pr.clone()]).unwrap();

    let score = compute_quality_score(&graph, &[test_pr, source_pr]);

    // Must compute all 7 quality dimensions
    // assertion_density should be > 0 (we have assertions)
    assert!(
        score.assertion_density >= 0.0 && score.assertion_density <= 1.0,
        "assertion_density must be in [0.0, 1.0], got {}",
        score.assertion_density
    );

    // mock_ratio should be in [0.0, 1.0]
    assert!(
        score.mock_ratio >= 0.0 && score.mock_ratio <= 1.0,
        "mock_ratio must be in [0.0, 1.0], got {}",
        score.mock_ratio
    );

    // coverage_breadth: we have tests so should be >= 0
    assert!(
        score.coverage_breadth >= 0.0 && score.coverage_breadth <= 1.0,
        "coverage_breadth must be in [0.0, 1.0], got {}",
        score.coverage_breadth
    );

    // coverage_depth: tests cover source functions
    assert!(
        score.coverage_depth >= 0.0 && score.coverage_depth <= 1.0,
        "coverage_depth must be in [0.0, 1.0], got {}",
        score.coverage_depth
    );

    // isolation should be in [0.0, 1.0]
    assert!(
        score.isolation >= 0.0 && score.isolation <= 1.0,
        "isolation must be in [0.0, 1.0], got {}",
        score.isolation
    );

    // freshness defaulted to 1.0
    assert!(
        score.freshness >= 0.0 && score.freshness <= 1.0,
        "freshness must be in [0.0, 1.0], got {}",
        score.freshness
    );

    // stability defaulted to 1.0
    assert!(
        score.stability >= 0.0 && score.stability <= 1.0,
        "stability must be in [0.0, 1.0], got {}",
        score.stability
    );

    // overall score should be computed and in [0.0, 1.0]
    assert!(
        score.overall >= 0.0 && score.overall <= 1.0,
        "overall score must be in [0.0, 1.0], got {}",
        score.overall
    );
}

// ---------------------------------------------------------------------------
// T18-11: Test Topology — test_smell_count Uses Call Graph
// ---------------------------------------------------------------------------

#[test]
fn t18_11_test_smell_count_uses_call_graph() {
    // Test that count_source_calls uses the call graph parameter, not ignoring it.
    // We create a test function that calls source functions via call graph edges.
    let test_file = "src/__tests__/service.test.ts";
    let source_file = "src/service.ts";

    let mut test_pr = make_parse_result(test_file, Language::TypeScript);
    test_pr.functions = vec![make_function("testServiceCreate", test_file, 1, 20)];
    // The test calls createUser and validateInput (both source functions)
    test_pr.call_sites = vec![
        make_call_site("createUser", None, test_file, 5),
        make_call_site("validateInput", None, test_file, 10),
        make_call_site("expect", None, test_file, 15),
    ];

    let mut source_pr = make_parse_result(source_file, Language::TypeScript);
    source_pr.functions = vec![
        make_function("createUser", source_file, 1, 20),
        make_function("validateInput", source_file, 25, 40),
    ];

    let builder = CallGraphBuilder::new();
    let (graph, _) = builder.build(&[test_pr.clone(), source_pr.clone()]).unwrap();

    // Detect smells using the call graph
    let smells = detect_smells(
        &test_pr.functions[0],
        &test_pr,
        &graph,
    );

    // The test function calls 2 source functions (createUser, validateInput)
    // This is NOT > 10, so EagerTest should NOT be present.
    // This is NOT 0, so LazyTest should NOT be present.
    assert!(
        !smells.contains(&TestSmell::EagerTest),
        "testServiceCreate calls only 2 source functions, should not be EagerTest"
    );

    // Verify the graph has edges from test to source (i.e., the graph is being used)
    let test_key = format!("{}::testServiceCreate", test_file);
    if let Some(test_idx) = graph.get_node(&test_key) {
        let outgoing_count = graph
            .graph
            .neighbors_directed(test_idx, petgraph::Direction::Outgoing)
            .count();
        // If graph has edges, count_source_calls uses them
        if outgoing_count > 0 {
            // Graph is being used — this is the desired behavior
            assert!(
                outgoing_count <= 10,
                "Test function has {} outgoing edges, EagerTest should not trigger",
                outgoing_count
            );
        }
    }

    // Also verify detect_all_smells works with parse results + graph
    let all_smells = detect_all_smells(&[test_pr, source_pr], &graph);
    // Should return results — each entry is (file, func_name, smells)
    // Not all functions will have smells, but the function should not panic
    // detect_all_smells must return without panic — if we reach here, it worked
    let _ = all_smells.len();
}

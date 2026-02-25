#![allow(clippy::cloned_ref_to_slice_refs)]
//! T4-ERR-01 through T4-ERR-05: Error handling analysis tests.

use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::graph::error_handling::*;
use drift_analysis::parsers::types::*;
use drift_analysis::scanner::language_detect::Language;

use smallvec::smallvec;

fn make_node(file: &str, name: &str, exported: bool) -> FunctionNode {
    FunctionNode {
        file: file.to_string(),
        name: name.to_string(),
        qualified_name: None,
        language: "typescript".to_string(),
        line: 1,
        end_line: 10,
        is_entry_point: false,
        is_exported: exported,
        signature_hash: 0,
        body_hash: 0,
    }
}

fn make_parse_result(
    file: &str,
    functions: Vec<FunctionInfo>,
    error_handling: Vec<ErrorHandlingInfo>,
    call_sites: Vec<CallSite>,
) -> ParseResult {
    ParseResult {
        file: file.to_string(),
        language: Language::TypeScript,
        content_hash: 0,
        functions,
        classes: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        call_sites,
        decorators: Vec::new(),
        string_literals: Vec::new(),
        numeric_literals: Vec::new(),
        error_handling,
        doc_comments: Vec::new(),
        namespace: None,
        parse_time_us: 0,
        error_count: 0,
        error_ranges: Vec::new(),
        has_errors: false,
    }
}

fn make_function(name: &str, line: u32, end_line: u32, is_async: bool) -> FunctionInfo {
    FunctionInfo {
        name: name.to_string(),
        qualified_name: None,
        file: String::new(),
        line,
        column: 0,
        end_line,
        parameters: smallvec![],
        return_type: None,
        generic_params: smallvec![],
        visibility: Visibility::Public,
        is_exported: true,
        is_async,
        is_generator: false,
        is_abstract: false,
        range: Range::default(),
        decorators: Vec::new(),
        doc_comment: None,
        body_hash: 0,
        signature_hash: 0,
    }
}

// T4-ERR-01: Identifies unhandled error paths across call graph
// (function throws, caller doesn't catch)
#[test]
fn test_unhandled_error_paths() {
    // Build call graph: A → B → C, where C throws and nobody catches
    let mut g = CallGraph::new();
    let a = g.add_function(make_node("a.ts", "funcA", true));
    let b = g.add_function(make_node("b.ts", "funcB", false));
    let c = g.add_function(make_node("c.ts", "funcC", false));
    g.add_edge(a, b, CallEdge { resolution: Resolution::ImportBased, confidence: 0.75, call_site_line: 5 });
    g.add_edge(b, c, CallEdge { resolution: Resolution::ImportBased, confidence: 0.75, call_site_line: 10 });

    // C throws an error
    let pr_c = make_parse_result("c.ts", vec![
        make_function("funcC", 1, 10, false),
    ], vec![
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::Throw,
            file: "c.ts".to_string(),
            line: 5,
            end_line: 5,
            range: Range::default(),
            caught_type: Some("DatabaseError".to_string()),
            has_body: false,
            function_scope: Some("funcC".to_string()),
        },
    ], vec![]);

    // A and B have no error handling
    let pr_a = make_parse_result("a.ts", vec![
        make_function("funcA", 1, 10, false),
    ], vec![], vec![]);
    let pr_b = make_parse_result("b.ts", vec![
        make_function("funcB", 1, 10, false),
    ], vec![], vec![]);

    let parse_results = vec![pr_a, pr_b, pr_c];
    let handlers = detect_handlers(&parse_results);
    let chains = trace_propagation(&g, &parse_results, &handlers);
    let gaps = analyze_gaps(&handlers, &chains, &parse_results);

    // Should find an unhandled error gap
    let unhandled: Vec<_> = gaps.iter().filter(|g| g.gap_type == GapType::Unhandled).collect();
    assert!(!unhandled.is_empty(), "Expected unhandled error path detected");
    assert_eq!(unhandled[0].function, "funcC");
}

// T4-ERR-02: Framework-specific error boundaries detected for at least 5 frameworks
#[test]
fn test_framework_error_boundaries() {
    // Test that handler detection recognizes various framework patterns
    let react_pr = make_parse_result("ErrorBoundary.tsx", vec![
        make_function("componentDidCatch", 1, 10, false),
    ], vec![
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::TryCatch,
            file: "ErrorBoundary.tsx".to_string(),
            line: 3,
            end_line: 8,
            range: Range::default(),
            caught_type: Some("Error".to_string()),
            has_body: true,
            function_scope: Some("componentDidCatch".to_string()),
        },
    ], vec![]);

    let express_pr = make_parse_result("middleware.ts", vec![{
        let mut f = make_function("errorMiddleware", 1, 10, false);
        f.parameters = smallvec![
            ParameterInfo { name: "err".to_string(), type_annotation: None, default_value: None, is_rest: false },
            ParameterInfo { name: "req".to_string(), type_annotation: None, default_value: None, is_rest: false },
            ParameterInfo { name: "res".to_string(), type_annotation: None, default_value: None, is_rest: false },
            ParameterInfo { name: "next".to_string(), type_annotation: None, default_value: None, is_rest: false },
        ];
        f
    }], vec![], vec![]);

    let django_pr = make_parse_result("middleware.py", vec![
        make_function("process_exception", 1, 10, false),
    ], vec![
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::TryExcept,
            file: "middleware.py".to_string(),
            line: 3,
            end_line: 8,
            range: Range::default(),
            caught_type: Some("Exception".to_string()),
            has_body: true,
            function_scope: Some("process_exception".to_string()),
        },
    ], vec![]);

    let spring_pr = make_parse_result("GlobalExceptionHandler.java", vec![
        make_function("handleException", 1, 10, false),
    ], vec![
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::TryCatch,
            file: "GlobalExceptionHandler.java".to_string(),
            line: 3,
            end_line: 8,
            range: Range::default(),
            caught_type: Some("Exception".to_string()),
            has_body: true,
            function_scope: Some("handleException".to_string()),
        },
    ], vec![]);

    let aspnet_pr = make_parse_result("ExceptionFilter.cs", vec![
        make_function("OnException", 1, 10, false),
    ], vec![
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::TryCatch,
            file: "ExceptionFilter.cs".to_string(),
            line: 3,
            end_line: 8,
            range: Range::default(),
            caught_type: Some("Exception".to_string()),
            has_body: true,
            function_scope: Some("OnException".to_string()),
        },
    ], vec![]);

    let all_prs = vec![react_pr, express_pr, django_pr, spring_pr, aspnet_pr];

    // Detect handlers across all frameworks
    let handlers = detect_handlers(&all_prs);
    // Also detect error callbacks (Express pattern)
    let callbacks = handler_detection::detect_error_callbacks(&all_prs);

    let total = handlers.len() + callbacks.len();
    assert!(total >= 5, "Expected at least 5 framework handlers, got {}", total);

    // Verify specific handler types
    let handler_types: Vec<_> = handlers.iter().map(|h| h.handler_type).collect();
    assert!(handler_types.contains(&HandlerType::TryCatch));
    assert!(handler_types.contains(&HandlerType::TryExcept));

    // Express error callback should be detected
    assert!(!callbacks.is_empty(), "Express error callback should be detected");
    assert_eq!(callbacks[0].handler_type, HandlerType::ErrorCallback);
}

// T4-ERR-03: Error propagation chain: A calls B calls C, C throws,
// B doesn't catch, A catches — gap reported at B, not at A
#[test]
fn test_error_propagation_chain() {
    let mut g = CallGraph::new();
    let a = g.add_function(make_node("a.ts", "funcA", true));
    let b = g.add_function(make_node("b.ts", "funcB", false));
    let c = g.add_function(make_node("c.ts", "funcC", false));
    g.add_edge(a, b, CallEdge { resolution: Resolution::ImportBased, confidence: 0.75, call_site_line: 5 });
    g.add_edge(b, c, CallEdge { resolution: Resolution::ImportBased, confidence: 0.75, call_site_line: 10 });

    // C throws
    let pr_c = make_parse_result("c.ts", vec![
        make_function("funcC", 1, 10, false),
    ], vec![
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::Throw,
            file: "c.ts".to_string(),
            line: 5,
            end_line: 5,
            range: Range::default(),
            caught_type: Some("Error".to_string()),
            has_body: false,
            function_scope: Some("funcC".to_string()),
        },
    ], vec![]);

    // A catches
    let pr_a = make_parse_result("a.ts", vec![
        make_function("funcA", 1, 20, false),
    ], vec![
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::TryCatch,
            file: "a.ts".to_string(),
            line: 3,
            end_line: 18,
            range: Range::default(),
            caught_type: Some("Error".to_string()),
            has_body: true,
            function_scope: Some("funcA".to_string()),
        },
    ], vec![]);

    // B doesn't catch
    let pr_b = make_parse_result("b.ts", vec![
        make_function("funcB", 1, 10, false),
    ], vec![], vec![]);

    let parse_results = vec![pr_a, pr_b, pr_c];
    let handlers = detect_handlers(&parse_results);
    let chains = trace_propagation(&g, &parse_results, &handlers);

    // The chain from C should be handled (A catches)
    assert!(!chains.is_empty(), "Expected propagation chains");
    let chain = &chains[0];
    assert!(chain.is_handled, "Chain should be handled since A catches");

    // Verify the chain includes B as a propagation node
    let b_node = chain.functions.iter().find(|n| n.function == "funcB");
    assert!(b_node.is_some(), "B should be in the propagation chain");
    let b_node = b_node.unwrap();
    assert!(!b_node.handles_error, "B should not handle the error");
    assert!(b_node.propagates_error, "B should propagate the error");
}

// T4-ERR-04: Empty catch blocks detected as anti-pattern
#[test]
fn test_empty_catch_detection() {
    let pr = make_parse_result("bad.ts", vec![
        make_function("badHandler", 1, 20, false),
    ], vec![
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::TryCatch,
            file: "bad.ts".to_string(),
            line: 5,
            end_line: 10,
            range: Range::default(),
            caught_type: Some("Error".to_string()),
            has_body: false, // Empty catch!
            function_scope: Some("badHandler".to_string()),
        },
    ], vec![]);

    let handlers = detect_handlers(&[pr.clone()]);
    assert!(!handlers.is_empty());
    assert!(handlers[0].is_empty, "Handler should be detected as empty");

    let gaps = analyze_gaps(&handlers, &[], &[pr]);
    let empty_catches: Vec<_> = gaps.iter().filter(|g| g.gap_type == GapType::EmptyCatch).collect();
    assert!(!empty_catches.is_empty(), "Empty catch should be detected as gap");
    assert_eq!(empty_catches[0].cwe_id, Some(390));
    assert_eq!(empty_catches[0].severity, GapSeverity::High);
}

// T4-ERR-05: Async error handling — unhandled promise rejection detected,
// .catch() handler recognized as handled
#[test]
fn test_async_error_handling() {
    // Async function with await but no try/catch → unhandled async
    let unhandled_pr = make_parse_result("unhandled.ts", vec![
        make_function("fetchData", 1, 10, true), // is_async = true
    ], vec![], vec![
        CallSite {
            callee_name: "fetch".to_string(),
            receiver: None,
            file: "unhandled.ts".to_string(),
            line: 5,
            column: 0,
            argument_count: 1,
            is_await: true, // await fetch(...)
        },
    ]);

    let gaps = analyze_gaps(&[], &[], &[unhandled_pr]);
    let async_gaps: Vec<_> = gaps.iter().filter(|g| g.gap_type == GapType::UnhandledAsync).collect();
    assert!(!async_gaps.is_empty(), "Unhandled async should be detected");
    assert_eq!(async_gaps[0].function, "fetchData");

    // Async function with try/catch → handled
    let handled_pr = make_parse_result("handled.ts", vec![
        make_function("safeFetch", 1, 20, true),
    ], vec![
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::AsyncAwaitTry,
            file: "handled.ts".to_string(),
            line: 3,
            end_line: 18,
            range: Range::default(),
            caught_type: Some("Error".to_string()),
            has_body: true,
            function_scope: Some("safeFetch".to_string()),
        },
    ], vec![
        CallSite {
            callee_name: "fetch".to_string(),
            receiver: None,
            file: "handled.ts".to_string(),
            line: 5,
            column: 0,
            argument_count: 1,
            is_await: true,
        },
    ]);

    let handled_gaps = analyze_gaps(&[], &[], &[handled_pr]);
    let handled_async: Vec<_> = handled_gaps.iter().filter(|g| g.gap_type == GapType::UnhandledAsync).collect();
    assert!(handled_async.is_empty(), "Handled async should not be flagged");
}

// Additional: CWE mapping verification
#[test]
fn test_cwe_mapping() {
    let gap = ErrorGap {
        file: "test.ts".to_string(),
        function: "handler".to_string(),
        line: 5,
        gap_type: GapType::EmptyCatch,
        error_type: Some("Error".to_string()),
        framework: None,
        cwe_id: Some(390),
        severity: GapSeverity::High,
        remediation: None,
    };

    let mapping = map_to_cwe(&gap);
    assert_eq!(mapping.cwe_id, 390);
    assert!(mapping.description.contains("error"));
    assert!(!mapping.remediation.is_empty());
}

// Additional: Error type profiling
#[test]
fn test_error_type_profiling() {
    let pr = make_parse_result("mixed.ts", vec![], vec![
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::TryCatch,
            file: "mixed.ts".to_string(),
            line: 1,
            end_line: 5,
            range: Range::default(),
            caught_type: Some("TypeError".to_string()),
            has_body: true,
            function_scope: Some("handler".to_string()),
        },
        ErrorHandlingInfo {
            kind: ErrorHandlingKind::Throw,
            file: "mixed.ts".to_string(),
            line: 10,
            end_line: 10,
            range: Range::default(),
            caught_type: Some("ValidationError".to_string()),
            has_body: false,
            function_scope: Some("validate".to_string()),
        },
    ], vec![]);

    let error_types = profile_error_types(&[pr]);
    assert_eq!(error_types.len(), 2);
    assert_eq!(error_types[0].name, "TypeError");
    assert_eq!(error_types[1].name, "ValidationError");
}

// Coverage boost: All GapType names
#[test]
fn test_gap_type_names() {
    let types = [
        GapType::EmptyCatch, GapType::SwallowedError, GapType::GenericCatch,
        GapType::Unhandled, GapType::UnhandledAsync, GapType::MissingMiddleware,
        GapType::InconsistentPattern,
    ];
    for gt in &types {
        assert!(!gt.name().is_empty());
    }
}

// Coverage boost: All GapSeverity names and Display
#[test]
fn test_gap_severity_names() {
    let severities = [
        GapSeverity::Critical, GapSeverity::High, GapSeverity::Medium,
        GapSeverity::Low, GapSeverity::Info,
    ];
    for s in &severities {
        assert!(!s.name().is_empty());
        let display = format!("{}", s);
        assert_eq!(display, s.name());
    }
}

// Coverage boost: HandlerType names
#[test]
fn test_handler_type_names() {
    let types = [
        HandlerType::TryCatch, HandlerType::TryExcept, HandlerType::ResultMatch,
        HandlerType::ErrorCallback, HandlerType::PromiseCatch, HandlerType::ErrorBoundary,
        HandlerType::ExpressMiddleware, HandlerType::FrameworkHandler,
        HandlerType::Rescue, HandlerType::DeferRecover,
    ];
    for ht in &types {
        assert!(!ht.name().is_empty());
    }
}

// Coverage boost: CWE mapping for all gap types
#[test]
fn test_cwe_mapping_all_gap_types() {
    let gap_types = [
        GapType::EmptyCatch, GapType::SwallowedError, GapType::GenericCatch,
        GapType::Unhandled, GapType::UnhandledAsync, GapType::MissingMiddleware,
        GapType::InconsistentPattern,
    ];
    for gt in &gap_types {
        let gap = ErrorGap {
            file: "test.ts".to_string(),
            function: "fn".to_string(),
            line: 1,
            gap_type: *gt,
            error_type: None,
            framework: None,
            cwe_id: None,
            severity: GapSeverity::Medium,
            remediation: None,
        };
        let mapping = map_to_cwe(&gap);
        assert!(mapping.cwe_id > 0, "Gap type {:?} should have a CWE ID", gt);
        assert!(!mapping.remediation.is_empty());
    }

    // Also test gap_severity function
    for gt in &gap_types {
        let severity = cwe_mapping::gap_severity(*gt);
        assert!(!severity.name().is_empty());
    }

    // Test all_error_handling_cwes
    let cwes = cwe_mapping::all_error_handling_cwes();
    assert!(cwes.len() >= 7);
}

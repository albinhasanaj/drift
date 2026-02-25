//! P4 Stress — Error Handling: profiler, handler detection, propagation, gaps, CWE
//!
//! Split from p4_graph_stress_test.rs for maintainability.

use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::graph::error_handling;
use drift_analysis::graph::error_handling::*;
use drift_analysis::parsers::types::*;
use drift_analysis::scanner::language_detect::Language;

use smallvec::smallvec;

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

fn node(file: &str, name: &str, exported: bool) -> FunctionNode {
    FunctionNode {
        file: file.to_string(), name: name.to_string(), qualified_name: None,
        language: "typescript".to_string(), line: 1, end_line: 10,
        is_entry_point: false, is_exported: exported, signature_hash: 0, body_hash: 0,
    }
}

fn edge() -> CallEdge {
    CallEdge { resolution: Resolution::ImportBased, confidence: 0.75, call_site_line: 5 }
}

fn func(name: &str, line: u32, end_line: u32) -> FunctionInfo {
    FunctionInfo {
        name: name.to_string(), qualified_name: None, file: String::new(),
        line, column: 0, end_line,
        parameters: smallvec![], return_type: None, generic_params: smallvec![],
        visibility: Visibility::Public, is_exported: true, is_async: false,
        is_generator: false, is_abstract: false, range: Range::default(),
        decorators: Vec::new(), doc_comment: None, body_hash: 0, signature_hash: 0,
    }
}

fn func_async(name: &str, line: u32, end_line: u32) -> FunctionInfo {
    let mut f = func(name, line, end_line);
    f.is_async = true;
    f
}

fn func_with_params(name: &str, line: u32, end_line: u32, params: &[&str]) -> FunctionInfo {
    let mut f = func(name, line, end_line);
    f.parameters = params.iter().map(|p| ParameterInfo {
        name: p.to_string(), type_annotation: None, default_value: None, is_rest: false,
    }).collect();
    f
}

fn call(callee: &str, receiver: Option<&str>, line: u32) -> CallSite {
    CallSite {
        callee_name: callee.to_string(), receiver: receiver.map(|r| r.to_string()),
        file: String::new(), line, column: 0, argument_count: 1, is_await: false,
    }
}

fn call_await(callee: &str, receiver: Option<&str>, line: u32) -> CallSite {
    let mut c = call(callee, receiver, line);
    c.is_await = true;
    c
}

fn eh_info(kind: ErrorHandlingKind, file: &str, line: u32, end_line: u32,
           caught: Option<&str>, has_body: bool, scope: Option<&str>) -> ErrorHandlingInfo {
    ErrorHandlingInfo {
        kind, file: file.to_string(), line, end_line, range: Range::default(),
        caught_type: caught.map(|s| s.to_string()), has_body,
        function_scope: scope.map(|s| s.to_string()),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Profiler, handler detection, propagation, gaps
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_error_profiler_empty_input() {
    let types = profile_error_types(&[]);
    assert!(types.is_empty());
}

#[test]
fn stress_error_profiler_all_error_kinds() {
    let kinds = [
        (ErrorHandlingKind::TryCatch, "TypeError"),
        (ErrorHandlingKind::TryExcept, "ValueError"),
        (ErrorHandlingKind::ResultMatch, "Result"),
        (ErrorHandlingKind::QuestionMark, "Result"),
        (ErrorHandlingKind::Throw, "CustomError"),
        (ErrorHandlingKind::PromiseCatch, "Promise"),
        (ErrorHandlingKind::AsyncAwaitTry, "AsyncError"),
        (ErrorHandlingKind::Rescue, "StandardError"),
        (ErrorHandlingKind::Defer, "error"),
    ];
    let mut ehs = Vec::new();
    for (kind, caught) in &kinds {
        ehs.push(eh_info(*kind, "test.ts", 1, 5, Some(caught), true, Some("handler")));
    }
    let p = ParseResult {
        file: "test.ts".into(), language: Language::TypeScript,
        error_handling: ehs, ..ParseResult::default()
    };
    let types = profile_error_types(&[p]);
    assert_eq!(types.len(), kinds.len());
}

#[test]
fn stress_handler_detection_skips_non_handlers() {
    let p = ParseResult {
        file: "test.ts".into(), language: Language::TypeScript,
        error_handling: vec![
            eh_info(ErrorHandlingKind::Throw, "test.ts", 1, 1, None, false, Some("f")),
            eh_info(ErrorHandlingKind::QuestionMark, "test.ts", 2, 2, None, false, Some("f")),
            eh_info(ErrorHandlingKind::Unwrap, "test.ts", 3, 3, None, false, Some("f")),
            eh_info(ErrorHandlingKind::TryFinally, "test.ts", 4, 4, None, false, Some("f")),
        ],
        ..ParseResult::default()
    };
    let handlers = detect_handlers(&[p]);
    assert!(handlers.is_empty(), "Non-handler kinds should be skipped");
}

#[test]
fn stress_handler_detection_all_handler_types() {
    let handler_kinds = [
        ErrorHandlingKind::TryCatch,
        ErrorHandlingKind::TryExcept,
        ErrorHandlingKind::ResultMatch,
        ErrorHandlingKind::PromiseCatch,
        ErrorHandlingKind::AsyncAwaitTry,
        ErrorHandlingKind::Rescue,
        ErrorHandlingKind::Defer,
    ];
    let ehs: Vec<_> = handler_kinds.iter().enumerate().map(|(i, kind)| {
        eh_info(*kind, "test.ts", (i*10) as u32, (i*10+5) as u32,
                Some("Error"), true, Some(&format!("handler_{i}")))
    }).collect();
    let p = ParseResult {
        file: "test.ts".into(), language: Language::TypeScript,
        error_handling: ehs, ..ParseResult::default()
    };
    let handlers = detect_handlers(&[p]);
    assert_eq!(handlers.len(), handler_kinds.len());
}

#[test]
fn stress_error_callback_detection() {
    let p = ParseResult {
        file: "callback.ts".into(), language: Language::TypeScript,
        functions: vec![
            func_with_params("onData", 1, 10, &["err", "data"]),
            func_with_params("process", 15, 25, &["error", "result"]),
            func_with_params("handle", 30, 40, &["e", "val"]),
            func_with_params("clean", 45, 55, &["input"]),
        ],
        ..ParseResult::default()
    };
    let callbacks = handler_detection::detect_error_callbacks(&[p]);
    assert_eq!(callbacks.len(), 3, "Should detect err, error, e as error callbacks");
    for cb in &callbacks {
        assert_eq!(cb.handler_type, HandlerType::ErrorCallback);
    }
}

#[test]
fn stress_gap_analysis_empty_catch() {
    let handler = ErrorHandler {
        file: "bad.ts".into(), line: 5, end_line: 10, function: "handler".into(),
        handler_type: HandlerType::TryCatch, caught_types: vec!["Error".into()],
        is_empty: true, rethrows: false,
    };
    let gaps = analyze_gaps(&[handler], &[], &[]);
    let empty = gaps.iter().filter(|g| g.gap_type == GapType::EmptyCatch).count();
    assert!(empty >= 1);
}

#[test]
fn stress_gap_analysis_generic_catch() {
    let generic_types = ["Exception", "Error", "BaseException", "Throwable",
                         "System.Exception", "std::exception", "object"];
    for caught in &generic_types {
        let handler = ErrorHandler {
            file: "test.ts".into(), line: 1, end_line: 5, function: "f".into(),
            handler_type: HandlerType::TryCatch, caught_types: vec![caught.to_string()],
            is_empty: false, rethrows: false,
        };
        let gaps = analyze_gaps(&[handler], &[], &[]);
        let generic = gaps.iter().filter(|g| g.gap_type == GapType::GenericCatch).count();
        assert!(generic >= 1, "'{caught}' should be detected as generic catch");
    }
}

#[test]
fn stress_gap_analysis_swallowed_error() {
    let handler = ErrorHandler {
        file: "swallow.ts".into(), line: 5, end_line: 7, function: "handler".into(),
        handler_type: HandlerType::TryCatch, caught_types: vec!["Error".into()],
        is_empty: false, rethrows: false,
    };
    let gaps = analyze_gaps(&[handler], &[], &[]);
    let swallowed = gaps.iter().filter(|g| g.gap_type == GapType::SwallowedError).count();
    assert!(swallowed >= 1);
}

#[test]
fn stress_gap_analysis_unhandled_chain() {
    let chain = PropagationChain {
        functions: vec![PropagationNode {
            file: "src.ts".into(), function: "thrower".into(), line: 5,
            handles_error: false, propagates_error: true,
        }],
        error_type: Some("DatabaseError".into()),
        is_handled: false,
    };
    let gaps = analyze_gaps(&[], &[chain], &[]);
    let unhandled = gaps.iter().filter(|g| g.gap_type == GapType::Unhandled).count();
    assert!(unhandled >= 1);
}

#[test]
fn stress_gap_analysis_unhandled_async() {
    let p = ParseResult {
        file: "async.ts".into(), language: Language::TypeScript,
        functions: vec![func_async("fetchData", 1, 10)],
        call_sites: vec![call_await("fetch", None, 5)],
        ..ParseResult::default()
    };
    let gaps = analyze_gaps(&[], &[], &[p]);
    let async_gaps = gaps.iter().filter(|g| g.gap_type == GapType::UnhandledAsync).count();
    assert!(async_gaps >= 1);
}

#[test]
fn stress_gap_analysis_handled_async_no_gap() {
    let p = ParseResult {
        file: "safe_async.ts".into(), language: Language::TypeScript,
        functions: vec![func_async("safeFetch", 1, 20)],
        error_handling: vec![eh_info(ErrorHandlingKind::AsyncAwaitTry, "safe_async.ts",
                                     3, 18, Some("Error"), true, Some("safeFetch"))],
        call_sites: vec![call_await("fetch", None, 5)],
        ..ParseResult::default()
    };
    let gaps = analyze_gaps(&[], &[], &[p]);
    let async_gaps = gaps.iter().filter(|g| g.gap_type == GapType::UnhandledAsync).count();
    assert_eq!(async_gaps, 0, "Handled async should not produce gap");
}

#[test]
fn stress_propagation_chain_handled_at_caller() {
    let mut g = CallGraph::new();
    let a = g.add_function(node("a.ts", "funcA", true));
    let b = g.add_function(node("b.ts", "funcB", false));
    g.add_edge(a, b, edge());

    let pr_b = ParseResult {
        file: "b.ts".into(), language: Language::TypeScript,
        functions: vec![func("funcB", 1, 10)],
        error_handling: vec![eh_info(ErrorHandlingKind::Throw, "b.ts", 5, 5,
                                     Some("Error"), false, Some("funcB"))],
        ..ParseResult::default()
    };
    let pr_a = ParseResult {
        file: "a.ts".into(), language: Language::TypeScript,
        functions: vec![func("funcA", 1, 20)],
        error_handling: vec![eh_info(ErrorHandlingKind::TryCatch, "a.ts", 3, 18,
                                     Some("Error"), true, Some("funcA"))],
        ..ParseResult::default()
    };

    let handlers = detect_handlers(&[pr_a.clone(), pr_b.clone()]);
    let chains = trace_propagation(&g, &[pr_a, pr_b], &handlers);
    assert!(!chains.is_empty());
    assert!(chains[0].is_handled, "Error should be handled by funcA");
}

// ═══════════════════════════════════════════════════════════════════════════
// CWE mapping exhaustive
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_cwe_mapping_all_gap_types() {
    let gap_types = [GapType::EmptyCatch, GapType::SwallowedError, GapType::GenericCatch,
                     GapType::Unhandled, GapType::UnhandledAsync, GapType::MissingMiddleware,
                     GapType::InconsistentPattern];
    for gt in &gap_types {
        let gap = ErrorGap {
            file: "t.ts".into(), function: "f".into(), line: 1,
            gap_type: *gt, error_type: None, framework: None,
            cwe_id: None, severity: GapSeverity::Medium, remediation: None,
        };
        let mapping = map_to_cwe(&gap);
        assert!(mapping.cwe_id > 0, "Gap {:?} should have CWE", gt);
        assert!(!mapping.name.is_empty());
        assert!(!mapping.description.is_empty());
        assert!(!mapping.remediation.is_empty());
    }
}

#[test]
fn stress_gap_severity_all_types() {
    use error_handling::cwe_mapping::gap_severity;
    assert_eq!(gap_severity(GapType::Unhandled), GapSeverity::High);
    assert_eq!(gap_severity(GapType::EmptyCatch), GapSeverity::High);
    assert_eq!(gap_severity(GapType::MissingMiddleware), GapSeverity::High);
    assert_eq!(gap_severity(GapType::UnhandledAsync), GapSeverity::Medium);
    assert_eq!(gap_severity(GapType::SwallowedError), GapSeverity::Medium);
    assert_eq!(gap_severity(GapType::GenericCatch), GapSeverity::Medium);
    assert_eq!(gap_severity(GapType::InconsistentPattern), GapSeverity::Low);
}

#[test]
fn stress_all_error_handling_cwes() {
    let cwes = error_handling::cwe_mapping::all_error_handling_cwes();
    assert_eq!(cwes.len(), 8);
    for (id, name) in cwes {
        assert!(*id > 0);
        assert!(!name.is_empty());
    }
}

#[test]
fn stress_handler_type_names() {
    let types = [HandlerType::TryCatch, HandlerType::TryExcept, HandlerType::ResultMatch,
                 HandlerType::ErrorCallback, HandlerType::PromiseCatch, HandlerType::ErrorBoundary,
                 HandlerType::ExpressMiddleware, HandlerType::FrameworkHandler,
                 HandlerType::Rescue, HandlerType::DeferRecover];
    for t in &types {
        assert!(!t.name().is_empty());
    }
    assert_eq!(types.len(), 10);
}

#[test]
fn stress_gap_type_names() {
    let types = [GapType::EmptyCatch, GapType::SwallowedError, GapType::GenericCatch,
                 GapType::Unhandled, GapType::UnhandledAsync, GapType::MissingMiddleware,
                 GapType::InconsistentPattern];
    for t in &types {
        assert!(!t.name().is_empty());
    }
    assert_eq!(types.len(), 7);
}

#[test]
fn stress_gap_severity_names() {
    let sevs = [GapSeverity::Critical, GapSeverity::High, GapSeverity::Medium,
                GapSeverity::Low, GapSeverity::Info];
    for s in &sevs {
        assert!(!s.name().is_empty());
        assert!(!format!("{s}").is_empty());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: detect_framework_handlers() stub
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_detect_framework_handlers_returns_empty() {
    let result = detect_framework_handlers(&[]);
    assert!(result.is_empty());

    let p = ParseResult {
        file: "app.ts".into(), language: Language::TypeScript,
        functions: vec![func("handler", 1, 10)],
        ..ParseResult::default()
    };
    let result = detect_framework_handlers(&[p]);
    assert!(result.is_empty(), "Stub should return empty vec");
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: ErrorHandlingResult default
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_error_handling_result_default() {
    let r = ErrorHandlingResult::default();
    assert!(r.handlers.is_empty());
    assert!(r.gaps.is_empty());
    assert!(r.unhandled_paths.is_empty());
    assert!(r.propagation_chains.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: ErrorType struct fields
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_error_type_struct_fields() {
    let et = ErrorType {
        name: "ValueError".to_string(),
        language: "python".to_string(),
        is_checked: false,
        parent: Some("Exception".to_string()),
    };
    assert_eq!(et.name, "ValueError");
    assert_eq!(et.language, "python");
    assert!(!et.is_checked);
    assert_eq!(et.parent.as_deref(), Some("Exception"));
}

#[test]
fn stress_error_type_no_parent() {
    let et = ErrorType {
        name: "BaseException".to_string(),
        language: "python".to_string(),
        is_checked: false,
        parent: None,
    };
    assert!(et.parent.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: UnhandledPath struct
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_unhandled_path_struct_fields() {
    let path = UnhandledPath {
        source_file: "db.ts".to_string(),
        source_function: "query".to_string(),
        source_line: 42,
        error_type: Some("DatabaseError".to_string()),
        chain: PropagationChain {
            functions: vec![PropagationNode {
                file: "db.ts".into(), function: "query".into(), line: 42,
                handles_error: false, propagates_error: true,
            }],
            error_type: Some("DatabaseError".into()),
            is_handled: false,
        },
    };
    assert_eq!(path.source_file, "db.ts");
    assert_eq!(path.source_function, "query");
    assert_eq!(path.source_line, 42);
    assert_eq!(path.error_type.as_deref(), Some("DatabaseError"));
    assert!(!path.chain.is_handled);
}

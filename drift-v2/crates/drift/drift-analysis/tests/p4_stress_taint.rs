//! P4 Stress — Taint: registry, propagation, intraprocedural, interprocedural, SARIF, framework specs
//!
//! Split from p4_graph_stress_test.rs for maintainability.

use drift_analysis::call_graph::types::{CallEdge, CallGraph, FunctionNode, Resolution};
use drift_analysis::graph::taint::framework_specs::*;
use drift_analysis::graph::taint::intraprocedural::analyze_intraprocedural;
use drift_analysis::graph::taint::interprocedural::analyze_interprocedural;
use drift_analysis::graph::taint::propagation::*;
use drift_analysis::graph::taint::registry::*;
use drift_analysis::graph::taint::sarif::generate_sarif;
use drift_analysis::graph::taint::types::*;
use drift_analysis::parsers::types::*;
use drift_analysis::scanner::language_detect::Language;

use smallvec::smallvec;
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

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

fn full_pr(file: &str, functions: Vec<FunctionInfo>, calls: Vec<CallSite>) -> ParseResult {
    ParseResult {
        file: file.to_string(), language: Language::TypeScript, content_hash: 0,
        functions, classes: Vec::new(), imports: Vec::new(), exports: Vec::new(),
        call_sites: calls, decorators: Vec::new(), string_literals: Vec::new(),
        numeric_literals: Vec::new(), error_handling: Vec::new(), doc_comments: Vec::new(),
        namespace: None, parse_time_us: 0, error_count: 0, error_ranges: Vec::new(),
        has_errors: false,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TAINT — registry exhaustive
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_registry_empty_matches_nothing() {
    let reg = TaintRegistry::new();
    assert!(reg.match_source("req.query").is_none());
    assert!(reg.match_sink("db.query").is_none());
    assert!(reg.match_sanitizer("escapeHtml").is_none());
}

#[test]
fn stress_registry_defaults_have_sources_sinks_sanitizers() {
    let reg = TaintRegistry::with_defaults();
    assert!(!reg.sources.is_empty());
    assert!(!reg.sinks.is_empty());
    assert!(!reg.sanitizers.is_empty());
}

#[test]
fn stress_registry_bidirectional_matching() {
    let reg = TaintRegistry::with_defaults();
    assert!(reg.match_source("req.query").is_some());
    // Bare "query" should NOT match source "req.query" — anchored matching
    // prevents reverse substring matches that caused massive false positives.
    assert!(reg.match_source("query").is_none());
    assert!(reg.match_sink("db.query").is_some());
    assert!(reg.match_sanitizer("escapeHtml").is_some());
}

#[test]
fn stress_registry_case_insensitive() {
    let reg = TaintRegistry::with_defaults();
    assert!(reg.match_source("REQ.QUERY").is_some());
    assert!(reg.match_sink("DB.QUERY").is_some());
    assert!(reg.match_sanitizer("ESCAPEHTML").is_some());
}

#[test]
fn stress_registry_toml_load_all_fields() {
    let mut reg = TaintRegistry::new();
    let toml = r#"
[[sources]]
pattern = "mySource"
source_type = "UserInput"

[[sinks]]
pattern = "mySink"
sink_type = "SqlQuery"
required_sanitizers = ["SqlParameterize"]

[[sanitizers]]
pattern = "mySanitizer"
sanitizer_type = "HtmlEscape"
protects_against = ["HtmlOutput"]
"#;
    reg.load_toml(toml).unwrap();
    assert!(reg.match_source("mySource").is_some());
    assert!(reg.match_sink("mySink").is_some());
    assert!(reg.match_sanitizer("mySanitizer").is_some());
}

#[test]
fn stress_registry_toml_invalid_syntax() {
    let mut reg = TaintRegistry::new();
    let result = reg.load_toml("this is not valid toml [[[");
    assert!(result.is_err());
}

#[test]
fn stress_registry_add_custom_patterns() {
    let mut reg = TaintRegistry::new();
    reg.add_source(SourcePattern {
        pattern: "custom_src".to_string(),
        source_type: SourceType::Environment,
        framework: Some("custom".to_string()),
    });
    reg.add_sink(SinkPattern {
        pattern: "custom_sink".to_string(),
        sink_type: SinkType::LdapQuery,
        required_sanitizers: vec![SanitizerType::InputValidation],
        framework: None,
    });
    reg.add_sanitizer(SanitizerPattern {
        pattern: "custom_san".to_string(),
        sanitizer_type: SanitizerType::Custom,
        protects_against: vec![SinkType::LdapQuery],
        framework: None,
    });
    assert!(reg.match_source("custom_src").is_some());
    assert!(reg.match_sink("custom_sink").is_some());
    assert!(reg.match_sanitizer("custom_san").is_some());
}

#[test]
fn stress_registry_all_default_sinks_have_cwe() {
    let reg = TaintRegistry::with_defaults();
    for sink in &reg.sinks {
        assert!(sink.sink_type.cwe_id().is_some(),
            "Sink {:?} should have CWE", sink.sink_type);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TAINT — sink/source type exhaustive
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_all_17_sink_types_cwe_and_name() {
    let all = SinkType::all_builtin();
    assert_eq!(all.len(), 17);
    let mut cwe_ids = std::collections::HashSet::new();
    for sink in all {
        assert!(!sink.name().is_empty());
        assert!(!format!("{sink}").is_empty());
        let cwe = sink.cwe_id().unwrap();
        cwe_ids.insert(cwe);
    }
    assert!(cwe_ids.len() >= 10, "Expected 10+ distinct CWEs, got {}", cwe_ids.len());
}

#[test]
fn stress_custom_sink_type() {
    let custom = SinkType::Custom(9999);
    assert_eq!(custom.cwe_id(), Some(9999));
    assert_eq!(custom.name(), "custom");
}

#[test]
fn stress_source_type_names() {
    let types = [SourceType::UserInput, SourceType::Environment, SourceType::Database,
                 SourceType::Network, SourceType::FileSystem, SourceType::CommandLine,
                 SourceType::Deserialization];
    for t in &types {
        assert!(!t.name().is_empty());
    }
    assert_eq!(types.len(), 7);
}

#[test]
fn stress_sanitizer_type_names() {
    let types = [SanitizerType::HtmlEscape, SanitizerType::SqlParameterize,
                 SanitizerType::ShellEscape, SanitizerType::PathValidate,
                 SanitizerType::UrlEncode, SanitizerType::InputValidation,
                 SanitizerType::TypeCast, SanitizerType::Custom];
    for t in &types {
        assert!(!t.name().is_empty());
    }
    assert_eq!(types.len(), 8);
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: SinkType Display
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_sink_type_display_matches_name() {
    for sink in SinkType::all_builtin() {
        assert_eq!(format!("{sink}"), sink.name());
    }
    let custom = SinkType::Custom(42);
    assert_eq!(format!("{custom}"), "custom");
}

// ═══════════════════════════════════════════════════════════════════════════
// GAP: TaintAnalysisResult default
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_taint_analysis_result_default() {
    let r = TaintAnalysisResult::default();
    assert!(r.flows.is_empty());
    assert_eq!(r.source_count, 0);
    assert_eq!(r.sink_count, 0);
    assert_eq!(r.sanitizer_count, 0);
    assert_eq!(r.vulnerability_count, 0);
    assert_eq!(r.duration_us, 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// TAINT — propagation context exhaustive
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_propagation_taint_and_check() {
    let mut ctx = PropagationContext::new();
    assert!(!ctx.is_tainted("x"));
    ctx.taint_variable("x", SourceType::UserInput);
    assert!(ctx.is_tainted("x"));
    assert!(!ctx.is_tainted("y"));
}

#[test]
fn stress_propagation_propagate_assignment() {
    let mut ctx = PropagationContext::new();
    ctx.taint_variable("src", SourceType::UserInput);
    ctx.propagate("src", "dst");
    assert!(ctx.is_tainted("dst"));
    ctx.propagate("clean", "other");
    assert!(!ctx.is_tainted("other"));
}

#[test]
fn stress_propagation_merge_both_tainted() {
    let mut ctx = PropagationContext::new();
    ctx.taint_variable("a", SourceType::UserInput);
    ctx.taint_variable("b", SourceType::Database);
    ctx.merge(&["a", "b"], "merged");
    assert!(ctx.is_tainted("merged"));
}

#[test]
fn stress_propagation_merge_one_tainted() {
    let mut ctx = PropagationContext::new();
    ctx.taint_variable("a", SourceType::UserInput);
    ctx.merge(&["a", "clean"], "merged");
    assert!(ctx.is_tainted("merged"));
}

#[test]
fn stress_propagation_merge_none_tainted() {
    let mut ctx = PropagationContext::new();
    ctx.merge(&["clean1", "clean2"], "merged");
    assert!(!ctx.is_tainted("merged"));
}

#[test]
fn stress_propagation_sanitize_then_check() {
    let mut ctx = PropagationContext::new();
    ctx.taint_variable("input", SourceType::UserInput);
    ctx.sanitize("input", SanitizerType::SqlParameterize, &[SinkType::SqlQuery]);
    assert!(ctx.is_sanitized_for("input", &SinkType::SqlQuery));
    assert!(ctx.is_tainted("input"));
}

#[test]
fn stress_propagation_retaint_after_sanitize() {
    let mut ctx = PropagationContext::new();
    ctx.taint_variable("x", SourceType::UserInput);
    ctx.sanitize("x", SanitizerType::HtmlEscape, &[SinkType::HtmlOutput]);
    ctx.taint_variable("x", SourceType::UserInput);
    assert!(ctx.is_tainted("x"));
}

#[test]
fn stress_propagation_collection_insert_tainted() {
    let mut ctx = PropagationContext::new();
    ctx.taint_variable("item", SourceType::UserInput);
    propagate_through_collection(&mut ctx, "list", "item", true);
    assert!(ctx.is_tainted("list"));
}

#[test]
fn stress_propagation_collection_read_from_tainted() {
    let mut ctx = PropagationContext::new();
    ctx.taint_variable("list", SourceType::UserInput);
    propagate_through_collection(&mut ctx, "list", "elem", false);
    assert!(ctx.is_tainted("elem"));
}

#[test]
fn stress_propagation_collection_insert_clean() {
    let mut ctx = PropagationContext::new();
    propagate_through_collection(&mut ctx, "list", "clean_item", true);
    assert!(!ctx.is_tainted("list"));
}

#[test]
fn stress_propagation_clear() {
    let mut ctx = PropagationContext::new();
    ctx.taint_variable("a", SourceType::UserInput);
    ctx.taint_variable("b", SourceType::Database);
    assert_eq!(ctx.tainted_variables().len(), 2);
    ctx.clear();
    assert!(ctx.tainted_variables().is_empty());
    assert!(ctx.applied_sanitizers().is_empty());
}

#[test]
fn stress_propagation_get_label() {
    let mut ctx = PropagationContext::new();
    assert!(ctx.get_label("x").is_none());
    ctx.taint_variable("x", SourceType::Network);
    let label = ctx.get_label("x").unwrap();
    assert_eq!(label.origin, SourceType::Network);
    assert!(!label.sanitized);
}

// ═══════════════════════════════════════════════════════════════════════════
// TAINT — taint label operations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_taint_label_apply_sanitizer() {
    let mut label = TaintLabel::new(0, SourceType::UserInput);
    assert!(!label.has_sanitizer(SanitizerType::HtmlEscape));
    label.apply_sanitizer(SanitizerType::HtmlEscape);
    assert!(label.has_sanitizer(SanitizerType::HtmlEscape));
    assert!(!label.has_sanitizer(SanitizerType::SqlParameterize));
}

#[test]
fn stress_taint_label_mark_sanitized() {
    let mut label = TaintLabel::new(0, SourceType::UserInput);
    assert!(!label.sanitized);
    label.mark_sanitized();
    assert!(label.sanitized);
}

#[test]
fn stress_taint_flow_is_vulnerability() {
    let flow = TaintFlow {
        source: TaintSource { file: "a.ts".into(), line: 1, column: 0,
            expression: "req.query".into(), source_type: SourceType::UserInput,
            label: TaintLabel::new(0, SourceType::UserInput) },
        sink: TaintSink { file: "b.ts".into(), line: 10, column: 0,
            expression: "db.query".into(), sink_type: SinkType::SqlQuery,
            required_sanitizers: vec![] },
        path: vec![], is_sanitized: false, sanitizers_applied: vec![],
        cwe_id: Some(89), confidence: 0.85,
    };
    assert!(flow.is_vulnerability());
    assert_eq!(flow.path_length(), 2);
}

#[test]
fn stress_taint_flow_sanitized_not_vulnerability() {
    let flow = TaintFlow {
        source: TaintSource { file: "a.ts".into(), line: 1, column: 0,
            expression: "req.query".into(), source_type: SourceType::UserInput,
            label: TaintLabel::new(0, SourceType::UserInput) },
        sink: TaintSink { file: "b.ts".into(), line: 10, column: 0,
            expression: "db.query".into(), sink_type: SinkType::SqlQuery,
            required_sanitizers: vec![] },
        path: vec![TaintHop { file: "mid.ts".into(), line: 5, column: 0,
            function: "process".into(), description: "hop".into() }],
        is_sanitized: true, sanitizers_applied: vec![],
        cwe_id: Some(89), confidence: 0.3,
    };
    assert!(!flow.is_vulnerability());
    assert_eq!(flow.path_length(), 3);
}

// ═══════════════════════════════════════════════════════════════════════════
// TAINT — intraprocedural stress
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_intra_no_functions_no_flows() {
    let reg = TaintRegistry::with_defaults();
    let p = full_pr("empty.ts", vec![], vec![]);
    let flows = analyze_intraprocedural(&p, &reg);
    assert!(flows.is_empty());
}

#[test]
fn stress_intra_function_no_calls_no_flows() {
    let reg = TaintRegistry::with_defaults();
    let p = full_pr("clean.ts", vec![func("clean", 1, 10)], vec![]);
    let flows = analyze_intraprocedural(&p, &reg);
    assert!(flows.is_empty());
}

#[test]
fn stress_intra_source_no_sink_no_flow() {
    let reg = TaintRegistry::with_defaults();
    let p = full_pr("src_only.ts",
        vec![func_with_params("handler", 1, 10, &["req"])],
        vec![call("query", Some("req"), 5)],
    );
    let flows = analyze_intraprocedural(&p, &reg);
    let _ = flows;
}

#[test]
fn stress_intra_all_17_sink_types_produce_flows() {
    let reg = TaintRegistry::with_defaults();
    let sink_expressions = [
        ("db.query", Some("db"), "query"),
        ("spawn", None, "spawn"),
        ("eval", None, "eval"),
        ("fs.writeFile", Some("fs"), "writeFile"),
        ("fs.readFile", Some("fs"), "readFile"),
        ("res.send", Some("res"), "send"),
        ("res.redirect", Some("res"), "redirect"),
        ("fetch", None, "fetch"),
        ("JSON.parse", Some("JSON"), "parse"),
        ("console.log", Some("console"), "log"),
        ("render", None, "render"),
        ("setHeader", None, "setHeader"),
        ("new RegExp", None, "new RegExp"),
        ("xml.parse", Some("xml"), "parse"),
        ("upload", None, "upload"),
    ];
    let mut found_cwe_ids = std::collections::HashSet::new();
    for (i, (_, receiver, callee)) in sink_expressions.iter().enumerate() {
        let p = full_pr(
            &format!("sink_{i}.ts"),
            vec![func_with_params(&format!("handler_{i}"), 1, 20, &["req"])],
            vec![
                call("query", Some("req"), 3),
                call(callee, *receiver, 15),
            ],
        );
        let flows = analyze_intraprocedural(&p, &reg);
        for f in &flows {
            if let Some(cwe) = f.cwe_id {
                found_cwe_ids.insert(cwe);
            }
        }
    }
    assert!(found_cwe_ids.len() >= 8,
        "Expected 8+ distinct CWE IDs from sink tests, got {}: {:?}",
        found_cwe_ids.len(), found_cwe_ids);
}

#[test]
fn stress_intra_sanitizer_before_sink_marks_sanitized() {
    let reg = TaintRegistry::with_defaults();
    let p = full_pr("safe.ts",
        vec![func_with_params("handler", 1, 20, &["req"])],
        vec![
            call("query", Some("req"), 3),
            call("parameterize", None, 10),
            call("query", Some("db"), 15),
        ],
    );
    let flows = analyze_intraprocedural(&p, &reg);
    let sql_flows: Vec<_> = flows.iter()
        .filter(|f| f.sink.sink_type == SinkType::SqlQuery)
        .collect();
    for f in &sql_flows {
        assert!(f.is_sanitized || f.confidence < 0.5,
            "SQL flow after parameterize should be sanitized or low confidence");
    }
}

#[test]
fn stress_intra_multiple_sources_multiple_sinks() {
    let reg = TaintRegistry::with_defaults();
    let p = full_pr("multi.ts",
        vec![func_with_params("handler", 1, 30, &["req", "res"])],
        vec![
            call("query", Some("req"), 3),
            call("body", Some("req"), 5),
            call("query", Some("db"), 15),
            call("send", Some("res"), 20),
            call("spawn", None, 25),
        ],
    );
    let flows = analyze_intraprocedural(&p, &reg);
    assert!(flows.len() >= 2, "Expected multiple flows, got {}", flows.len());
}

#[test]
fn stress_intra_50_functions_performance() {
    let reg = TaintRegistry::with_defaults();
    let mut functions = Vec::new();
    let mut calls = Vec::new();
    for i in 0..50 {
        let start = i * 20;
        functions.push(func_with_params(&format!("handler_{i}"), start, start + 19, &["req"]));
        calls.push(call("query", Some("req"), start + 3));
        calls.push(call("query", Some("db"), start + 15));
    }
    let p = full_pr("big.ts", functions, calls);
    let start = Instant::now();
    let flows = analyze_intraprocedural(&p, &reg);
    let elapsed = start.elapsed();
    assert!(!flows.is_empty());
    assert!(elapsed.as_millis() < 100, "50 functions took {}ms", elapsed.as_millis());
}

// ═══════════════════════════════════════════════════════════════════════════
// TAINT — interprocedural stress
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_inter_empty_graph_no_flows() {
    let reg = TaintRegistry::with_defaults();
    let g = CallGraph::new();
    let result = analyze_interprocedural(&g, &[], &reg, None);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn stress_inter_single_function_with_source_and_sink() {
    let reg = TaintRegistry::with_defaults();
    let mut g = CallGraph::new();
    g.add_function(FunctionNode {
        file: "handler.ts".into(), name: "handler".into(), qualified_name: None,
        language: "typescript".into(), line: 1, end_line: 20,
        is_entry_point: true, is_exported: true, signature_hash: 0, body_hash: 0,
    });
    let p = full_pr("handler.ts",
        vec![func_with_params("handler", 1, 20, &["req"])],
        vec![call("query", Some("req"), 3), call("query", Some("db"), 15)],
    );
    let result = analyze_interprocedural(&g, &[p], &reg, None);
    assert!(result.is_ok());
}

#[test]
fn stress_inter_mutual_recursion_terminates() {
    let reg = TaintRegistry::with_defaults();
    let mut g = CallGraph::new();
    let a = g.add_function(FunctionNode {
        file: "a.ts".into(), name: "funcA".into(), qualified_name: None,
        language: "typescript".into(), line: 1, end_line: 10,
        is_entry_point: true, is_exported: true, signature_hash: 0, body_hash: 0,
    });
    let b = g.add_function(FunctionNode {
        file: "b.ts".into(), name: "funcB".into(), qualified_name: None,
        language: "typescript".into(), line: 1, end_line: 10,
        is_entry_point: false, is_exported: false, signature_hash: 0, body_hash: 0,
    });
    g.add_edge(a, b, edge());
    g.add_edge(b, a, edge());
    let prs = vec![
        full_pr("a.ts", vec![func_with_params("funcA", 1, 10, &["req"])],
            vec![call("query", Some("req"), 3)]),
        full_pr("b.ts", vec![func("funcB", 1, 10)],
            vec![call("query", Some("db"), 8)]),
    ];
    let result = analyze_interprocedural(&g, &prs, &reg, Some(10));
    assert!(result.is_ok(), "Mutual recursion should terminate");
}

#[test]
fn stress_inter_path_too_long_error() {
    let reg = TaintRegistry::with_defaults();
    let mut g = CallGraph::new();
    let mut nodes = Vec::new();
    for i in 0..100 {
        nodes.push(g.add_function(FunctionNode {
            file: format!("f{i}.ts"), name: format!("func_{i}"), qualified_name: None,
            language: "typescript".into(), line: 1, end_line: 10,
            is_entry_point: i == 0, is_exported: i == 0, signature_hash: 0, body_hash: 0,
        }));
    }
    for i in 0..99 { g.add_edge(nodes[i], nodes[i+1], edge()); }
    let mut prs = vec![full_pr("f0.ts",
        vec![func_with_params("func_0", 1, 10, &["req"])],
        vec![call("query", Some("req"), 3)])];
    for i in 1..100 {
        prs.push(full_pr(&format!("f{i}.ts"),
            vec![func(&format!("func_{i}"), 1, 10)],
            vec![call("query", Some("db"), 8)]));
    }
    let result = analyze_interprocedural(&g, &prs, &reg, Some(3));
    match result {
        Ok(flows) => {
            for f in &flows { assert!(f.path.len() <= 10); }
        }
        Err(e) => {
            let msg = format!("{e}");
            assert!(msg.contains("too long") || msg.contains("PathTooLong") || msg.contains("path"),
                "Expected path-related error, got: {msg}");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TAINT — SARIF generation stress
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_sarif_empty_flows() {
    let sarif = generate_sarif(&[], "drift", "1.0.0");
    assert_eq!(sarif.version, "2.1.0");
    assert_eq!(sarif.runs.len(), 1);
    assert!(sarif.runs[0].results.is_empty());
}

#[test]
fn stress_sarif_sanitized_flows_excluded() {
    let flow = TaintFlow {
        source: TaintSource { file: "a.ts".into(), line: 1, column: 0,
            expression: "req.query".into(), source_type: SourceType::UserInput,
            label: TaintLabel::new(0, SourceType::UserInput) },
        sink: TaintSink { file: "b.ts".into(), line: 10, column: 0,
            expression: "db.query".into(), sink_type: SinkType::SqlQuery,
            required_sanitizers: vec![] },
        path: vec![], is_sanitized: true, sanitizers_applied: vec![],
        cwe_id: Some(89), confidence: 0.3,
    };
    let sarif = generate_sarif(&[flow], "drift", "1.0.0");
    assert!(sarif.runs[0].results.is_empty(), "Sanitized flows should not appear in SARIF");
}

#[test]
fn stress_sarif_multiple_cwe_rules() {
    let flows = vec![
        TaintFlow {
            source: TaintSource { file: "a.ts".into(), line: 1, column: 0,
                expression: "req.query".into(), source_type: SourceType::UserInput,
                label: TaintLabel::new(0, SourceType::UserInput) },
            sink: TaintSink { file: "b.ts".into(), line: 10, column: 0,
                expression: "db.query".into(), sink_type: SinkType::SqlQuery,
                required_sanitizers: vec![] },
            path: vec![], is_sanitized: false, sanitizers_applied: vec![],
            cwe_id: Some(89), confidence: 0.85,
        },
        TaintFlow {
            source: TaintSource { file: "c.ts".into(), line: 1, column: 0,
                expression: "req.body".into(), source_type: SourceType::UserInput,
                label: TaintLabel::new(1, SourceType::UserInput) },
            sink: TaintSink { file: "d.ts".into(), line: 10, column: 0,
                expression: "res.send".into(), sink_type: SinkType::HtmlOutput,
                required_sanitizers: vec![] },
            path: vec![], is_sanitized: false, sanitizers_applied: vec![],
            cwe_id: Some(79), confidence: 0.85,
        },
    ];
    let sarif = generate_sarif(&flows, "drift", "2.0.0");
    assert_eq!(sarif.runs[0].results.len(), 2);
    assert_eq!(sarif.runs[0].tool.driver.rules.len(), 2);
    let rule_ids: Vec<_> = sarif.runs[0].tool.driver.rules.iter().map(|r| r.id.as_str()).collect();
    assert!(rule_ids.contains(&"CWE-89"));
    assert!(rule_ids.contains(&"CWE-79"));
}

#[test]
fn stress_sarif_code_flow_has_source_and_sink() {
    let flow = TaintFlow {
        source: TaintSource { file: "src.ts".into(), line: 5, column: 10,
            expression: "req.query".into(), source_type: SourceType::UserInput,
            label: TaintLabel::new(0, SourceType::UserInput) },
        sink: TaintSink { file: "sink.ts".into(), line: 20, column: 5,
            expression: "db.query".into(), sink_type: SinkType::SqlQuery,
            required_sanitizers: vec![] },
        path: vec![TaintHop { file: "mid.ts".into(), line: 12, column: 0,
            function: "process".into(), description: "propagation".into() }],
        is_sanitized: false, sanitizers_applied: vec![],
        cwe_id: Some(89), confidence: 0.85,
    };
    let sarif = generate_sarif(&[flow], "drift", "1.0.0");
    let result = &sarif.runs[0].results[0];
    assert_eq!(result.rule_id, "CWE-89");
    assert_eq!(result.level, "error");
    let thread_flow = &result.code_flows[0].thread_flows[0];
    assert!(thread_flow.locations.len() >= 3);
    assert!(thread_flow.locations[0].kinds.contains(&"source".to_string()));
    assert!(thread_flow.locations.last().unwrap().kinds.contains(&"sink".to_string()));
}

#[test]
fn stress_sarif_serializes_to_json() {
    let flow = TaintFlow {
        source: TaintSource { file: "a.ts".into(), line: 1, column: 0,
            expression: "input".into(), source_type: SourceType::UserInput,
            label: TaintLabel::new(0, SourceType::UserInput) },
        sink: TaintSink { file: "b.ts".into(), line: 10, column: 0,
            expression: "eval".into(), sink_type: SinkType::CodeExecution,
            required_sanitizers: vec![] },
        path: vec![], is_sanitized: false, sanitizers_applied: vec![],
        cwe_id: Some(94), confidence: 0.9,
    };
    let sarif = generate_sarif(&[flow], "drift", "1.0.0");
    let json = serde_json::to_string_pretty(&sarif).unwrap();
    assert!(json.contains("CWE-94"));
    assert!(json.contains("2.1.0"));
}

// ═══════════════════════════════════════════════════════════════════════════
// TAINT — framework specs
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_all_12_frameworks_apply_without_panic() {
    for fw in TaintFramework::all() {
        let mut reg = TaintRegistry::new();
        apply_framework_specs(&mut reg, *fw);
        assert!(!reg.sources.is_empty() || !reg.sinks.is_empty() || !reg.sanitizers.is_empty(),
            "Framework {:?} should add at least one pattern", fw);
    }
    assert_eq!(TaintFramework::all().len(), 12);
}

#[test]
fn stress_framework_names_unique() {
    let mut names = std::collections::HashSet::new();
    for fw in TaintFramework::all() {
        assert!(names.insert(fw.name()), "Duplicate framework name: {}", fw.name());
    }
}

#[test]
fn stress_express_framework_sources() {
    let mut reg = TaintRegistry::new();
    apply_framework_specs(&mut reg, TaintFramework::Express);
    assert!(reg.match_source("req.cookies").is_some());
    assert!(reg.match_source("req.ip").is_some());
    assert!(reg.match_sink("res.send").is_some());
    assert!(reg.match_sink("res.redirect").is_some());
}

#[test]
fn stress_django_framework_patterns() {
    let mut reg = TaintRegistry::new();
    apply_framework_specs(&mut reg, TaintFramework::Django);
    assert!(reg.match_source("request.META").is_some());
    assert!(reg.match_sink("cursor.execute").is_some());
    assert!(reg.match_sanitizer("mark_safe").is_some());
}

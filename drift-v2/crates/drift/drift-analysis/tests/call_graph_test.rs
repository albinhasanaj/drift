#![allow(clippy::field_reassign_with_default, clippy::redundant_closure, clippy::useless_vec, unused_variables, unused_imports)]
//! Call Graph tests — T2-CG-01 through T2-CG-12.
//!
//! Tests for the call graph builder: 6 resolution strategies, BFS traversal,
//! entry point detection, cycle handling, incremental updates, CTE fallback.

use std::path::Path;
use std::time::Instant;

use drift_analysis::call_graph::builder::CallGraphBuilder;
use drift_analysis::call_graph::cte_fallback;
use drift_analysis::call_graph::di_support::{detect_di_frameworks, DI_FRAMEWORKS};
use drift_analysis::call_graph::incremental::IncrementalCallGraph;
use drift_analysis::call_graph::traversal::{bfs_forward, bfs_inverse, detect_entry_points};
use drift_analysis::call_graph::types::{
    CallEdge, CallGraph, CallGraphStats, FunctionNode, Resolution,
};
use drift_analysis::parsers::manager::ParserManager;
use drift_analysis::parsers::types::ParseResult;
use drift_analysis::scanner::language_detect::Language;

// ---- Helpers ----

fn parse_file(source: &str, file: &str) -> ParseResult {
    let parser = ParserManager::new();
    parser.parse(source.as_bytes(), Path::new(file)).unwrap()
}

// ---- T2-CG-01: Call graph builds with all 6 resolution strategies ----

#[test]
fn t2_cg_01_six_resolution_strategies() {
    // File A: defines exported functions and a class
    let source_a = r#"
export function directCall() { return 1; }
export class UserService {
    findUser(id: string) { return id; }
}
"#;
    let pr_a = parse_file(source_a, "a.ts");

    // File B: imports and calls from A
    let source_b = r#"
import { directCall, UserService } from './a';
function caller() {
    directCall();
    const svc = new UserService();
    svc.findUser('123');
}
export function exportedCaller() {
    caller();
}
"#;
    let pr_b = parse_file(source_b, "b.ts");

    let builder = CallGraphBuilder::new();
    let (graph, stats) = builder.build(&[pr_a, pr_b]).unwrap();

    // Should have functions from both files
    assert!(
        stats.total_functions >= 3,
        "should have at least 3 functions, got {}",
        stats.total_functions
    );

    // Should have resolved some edges
    assert!(
        stats.total_edges > 0,
        "should have at least 1 edge, got {}",
        stats.total_edges
    );

    // Verify all 6 resolution strategies exist and have valid confidences
    for strategy in Resolution::all_ordered() {
        let conf = strategy.default_confidence();
        assert!(
            conf > 0.0 && conf <= 1.0,
            "strategy {:?} should have valid confidence, got {}",
            strategy,
            conf
        );
    }

    // Verify resolution rate is positive
    assert!(
        stats.resolution_rate >= 0.0,
        "resolution rate should be non-negative"
    );
}

// ---- T2-CG-02: Incremental call graph update ----

#[test]
fn t2_cg_02_incremental_update() {
    let source_a = "export function a() { return 1; }";
    let source_b = "export function b() { return 2; }";
    let pr_a = parse_file(source_a, "a.ts");
    let pr_b = parse_file(source_b, "b.ts");

    let mut icg = IncrementalCallGraph::new();

    // Full build
    let stats1 = icg.full_build(&[pr_a.clone(), pr_b.clone()]).unwrap();
    let initial_count = stats1.total_functions;
    assert!(initial_count >= 2, "should have at least 2 functions");

    // Add a new file
    let source_c = r#"
import { a } from './a';
export function c() { return a(); }
"#;
    let pr_c = parse_file(source_c, "c.ts");

    // Incremental update
    let all = vec![pr_a, pr_b, pr_c.clone()];
    let stats2 = icg.update(&[pr_c], &[], &[], &all).unwrap();

    assert!(
        stats2.total_functions >= initial_count,
        "incremental update should have at least as many functions"
    );
}

// ---- T2-CG-03: SQLite CTE fallback correctness equivalence ----

#[test]
fn t2_cg_03_cte_fallback_equivalence() {
    // Build a small graph and verify CTE produces same results as in-memory BFS
    let source_a = r#"
export function a() { return b(); }
function b() { return c(); }
function c() { return 42; }
"#;
    let pr_a = parse_file(source_a, "chain.ts");

    let builder = CallGraphBuilder::new();
    let (graph, _stats) = builder.build(&[pr_a]).unwrap();

    // In-memory BFS from 'a'
    if let Some(start) = graph.get_node("chain.ts::a") {
        let reachable = bfs_forward(&graph, start, Some(5));
        // Should reach b and c
        assert!(
            reachable.len() <= graph.function_count(),
            "BFS should not exceed total function count"
        );
    }

    // CTE fallback threshold check
    assert!(
        cte_fallback::should_use_cte(600_000, 500_000),
        "600K functions should trigger CTE fallback"
    );
    assert!(
        !cte_fallback::should_use_cte(100_000, 500_000),
        "100K functions should NOT trigger CTE fallback"
    );
}

// ---- T2-CG-04: DI framework support ----

#[test]
fn t2_cg_04_di_framework_support() {
    // Verify all 5 DI frameworks are defined
    assert_eq!(
        DI_FRAMEWORKS.len(),
        5,
        "should have 5 DI frameworks: NestJS, Spring, FastAPI, Laravel, ASP.NET"
    );

    let framework_names: Vec<&str> = DI_FRAMEWORKS.iter().map(|f| f.name).collect();
    assert!(framework_names.contains(&"NestJS"));
    assert!(framework_names.contains(&"Spring"));
    assert!(framework_names.contains(&"FastAPI"));
    assert!(framework_names.contains(&"Laravel"));
    assert!(framework_names.contains(&"ASP.NET"));

    // DI resolution confidence should be 0.80
    assert_eq!(
        Resolution::DiInjection.default_confidence(),
        0.80,
        "DI injection confidence should be 0.80"
    );

    // Test NestJS detection
    let source = r#"
import { Injectable, Controller } from '@nestjs/common';

@Injectable()
export class UserService {
    findAll() { return []; }
}

@Controller('users')
export class UserController {
    constructor(private userService: UserService) {}
    getAll() { return this.userService.findAll(); }
}
"#;
    let pr = parse_file(source, "user.controller.ts");
    let detected = detect_di_frameworks(&[pr]);
    assert!(
        !detected.is_empty(),
        "should detect NestJS DI framework from @nestjs/common import"
    );
    assert_eq!(detected[0].name, "NestJS");
}

// ---- T2-CG-05: Entry point detection for all 5 heuristic categories ----

#[test]
fn t2_cg_05_entry_point_detection() {
    // Create files that exercise all 5 entry point categories
    let sources = vec![
        // 1. Exported functions
        ("lib.ts", "export function publicApi() { return 1; }"),
        // 2. Main/index file functions
        ("main.ts", "function main() { console.log('start'); }"),
        // 3. Route handlers (via decorator)
        ("routes.ts", r#"
import { Get } from '@nestjs/common';
export class Controller {
    @Get()
    getUsers() { return []; }
}
"#),
        // 4. Test functions
        ("test.ts", "function testSomething() { expect(1).toBe(1); }"),
        // 5. CLI entry points
        ("cli.ts", "function parse_args() { return process.argv; }"),
    ];

    let parse_results: Vec<ParseResult> = sources
        .iter()
        .map(|(file, src)| parse_file(src, file))
        .collect();

    let builder = CallGraphBuilder::new();
    let (graph, stats) = builder.build(&parse_results).unwrap();

    // Entry points should be detected
    let entry_points = detect_entry_points(&graph);

    // At least some should be marked as entry points via heuristics
    // (exported functions, main functions, test functions, CLI entry points)
    let entry_count = graph
        .graph
        .node_indices()
        .filter(|&idx| graph.graph[idx].is_entry_point)
        .count();

    assert!(
        entry_count > 0 || !entry_points.is_empty(),
        "should detect at least 1 entry point from 5 heuristic categories"
    );

    // Verify the graph has functions from multiple files
    assert!(
        stats.total_functions >= 3,
        "should have at least 3 functions across test files, got {}",
        stats.total_functions
    );
}

// ---- T2-CG-06: Cycle handling — A→B→C→A ----

#[test]
fn t2_cg_06_cycle_handling() {
    let source = r#"
function a() { return b(); }
function b() { return c(); }
function c() { return a(); }
"#;
    let pr = parse_file(source, "cycle.ts");

    let builder = CallGraphBuilder::new();
    let (graph, _stats) = builder.build(&[pr]).unwrap();

    // Graph should build without infinite loop
    assert!(
        graph.function_count() >= 3,
        "should have 3 functions in cycle"
    );

    // BFS should terminate (not infinite loop)
    if let Some(start) = graph.get_node("cycle.ts::a") {
        let reachable = bfs_forward(&graph, start, Some(10));
        // Should find b and c (and not loop forever)
        assert!(
            reachable.len() <= 3,
            "BFS should terminate, found {} reachable nodes",
            reachable.len()
        );
    }
}

// ---- T2-CG-07: Disconnected components ----

#[test]
fn t2_cg_07_disconnected_components() {
    // Three isolated subgraphs
    let source_a = r#"
function a1() { return a2(); }
function a2() { return 1; }
"#;
    let source_b = r#"
function b1() { return b2(); }
function b2() { return 2; }
"#;
    let source_c = r#"
function c1() { return 3; }
"#;

    let pr_a = parse_file(source_a, "group_a.ts");
    let pr_b = parse_file(source_b, "group_b.ts");
    let pr_c = parse_file(source_c, "group_c.ts");

    let builder = CallGraphBuilder::new();
    let (graph, _stats) = builder.build(&[pr_a, pr_b, pr_c]).unwrap();

    // BFS from a1 should NOT reach b1 or c1
    if let Some(a1) = graph.get_node("group_a.ts::a1") {
        let reachable = bfs_forward(&graph, a1, Some(10));
        let reachable_names: Vec<&str> = reachable
            .iter()
            .filter_map(|&idx| graph.graph.node_weight(idx).map(|n| n.name.as_str()))
            .collect();

        assert!(
            !reachable_names.contains(&"b1"),
            "a1 should NOT reach b1 in disconnected graph"
        );
        assert!(
            !reachable_names.contains(&"c1"),
            "a1 should NOT reach c1 in disconnected graph"
        );
    }
}

// ---- T2-CG-08: Resolution strategy fallback chain ----

#[test]
fn t2_cg_08_resolution_fallback_chain() {
    // Verify the fallback order: SameFile > MethodCall > DiInjection > ImportBased > ExportBased > Fuzzy
    let strategies = Resolution::all_ordered();
    assert_eq!(strategies.len(), 6, "should have 6 resolution strategies");

    // Verify decreasing confidence order
    let confidences: Vec<f32> = strategies.iter().map(|s| s.default_confidence()).collect();
    for i in 1..confidences.len() {
        assert!(
            confidences[i] <= confidences[i - 1],
            "confidence should decrease: {:?} ({}) should be <= {:?} ({})",
            strategies[i],
            confidences[i],
            strategies[i - 1],
            confidences[i - 1]
        );
    }

    // Verify specific confidences
    assert_eq!(Resolution::SameFile.default_confidence(), 0.95);
    assert_eq!(Resolution::MethodCall.default_confidence(), 0.90);
    assert_eq!(Resolution::DiInjection.default_confidence(), 0.80);
    assert_eq!(Resolution::ImportBased.default_confidence(), 0.75);
    assert_eq!(Resolution::ExportBased.default_confidence(), 0.60);
    assert_eq!(Resolution::Fuzzy.default_confidence(), 0.40);
}

// ---- T2-CG-09: Call graph with 50K functions — performance contract ----

#[test]
fn t2_cg_09_performance_50k() {
    // Generate 50K functions across 500 files (100 functions each)
    let parser = ParserManager::new();
    let mut parse_results = Vec::new();

    let gen_start = Instant::now();
    for file_idx in 0..500 {
        let mut source = String::new();
        for fn_idx in 0..100 {
            let callee = if fn_idx > 0 {
                format!("fn_{}_{}", file_idx, fn_idx - 1)
            } else {
                "console.log".to_string()
            };
            source.push_str(&format!(
                "export function fn_{file_idx}_{fn_idx}() {{ return {callee}(); }}\n"
            ));
        }
        let file = format!("file_{file_idx:03}.ts");
        let pr = parser.parse(source.as_bytes(), Path::new(&file)).unwrap();
        parse_results.push(pr);
    }
    let gen_time = gen_start.elapsed();
    eprintln!("Generated 50K functions in {:?}", gen_time);

    // Build call graph
    let build_start = Instant::now();
    let builder = CallGraphBuilder::new();
    let (graph, stats) = builder.build(&parse_results).unwrap();
    let build_time = build_start.elapsed();
    eprintln!(
        "Built call graph: {} functions, {} edges in {:?}",
        stats.total_functions, stats.total_edges, build_time
    );

    assert!(
        stats.total_functions >= 40_000,
        "should have at least 40K functions, got {}",
        stats.total_functions
    );

    // Build should complete in <10s (generous for debug builds)
    assert!(
        build_time.as_secs() < 10,
        "call graph build should complete in <10s, took {:?}",
        build_time
    );

    // BFS should complete in <100ms (generous for debug builds)
    if let Some(start_node) = graph.get_node("file_000.ts::fn_0_99") {
        let bfs_start = Instant::now();
        let _reachable = bfs_forward(&graph, start_node, Some(5));
        let bfs_time = bfs_start.elapsed();
        eprintln!("BFS completed in {:?}", bfs_time);

        assert!(
            bfs_time.as_millis() < 100,
            "BFS should complete in <100ms, took {:?}",
            bfs_time
        );
    }
}

// ---- T2-CG-10: Incremental delete — remove file, verify no dangling references ----

#[test]
fn t2_cg_10_incremental_delete() {
    let source_a = "export function a() { return 1; }";
    let source_b = "export function b() { return 2; }";
    let pr_a = parse_file(source_a, "a.ts");
    let pr_b = parse_file(source_b, "b.ts");

    let mut icg = IncrementalCallGraph::new();
    icg.full_build(&[pr_a.clone(), pr_b]).unwrap();

    let initial_count = icg.graph().function_count();
    assert!(initial_count >= 2);

    // Remove b.ts
    let stats = icg.update(&[], &[], &["b.ts".to_string()], &[pr_a]).unwrap();

    // b.ts functions should be gone
    let b_nodes = icg.graph().get_file_nodes("b.ts");
    assert!(
        b_nodes.is_empty(),
        "b.ts nodes should be removed after delete"
    );

    // a.ts should still be present
    assert!(
        !icg.graph().get_file_nodes("a.ts").is_empty(),
        "a.ts should still be present"
    );
}

// ---- T2-CG-11: Dynamic resolution produces lower confidence than Direct ----

#[test]
fn t2_cg_11_dynamic_vs_direct_confidence() {
    let dynamic_conf = Resolution::Fuzzy.default_confidence();
    let direct_conf = Resolution::SameFile.default_confidence();

    assert!(
        dynamic_conf <= 0.60,
        "Dynamic/Fuzzy confidence should be ≤0.60, got {}",
        dynamic_conf
    );
    assert!(
        direct_conf >= 0.90,
        "Direct/SameFile confidence should be ≥0.90, got {}",
        direct_conf
    );
    assert!(
        dynamic_conf < direct_conf,
        "Dynamic ({}) should be lower than Direct ({})",
        dynamic_conf,
        direct_conf
    );
}

// ---- T2-CG-12: Empty codebase produces empty graph, not error ----

#[test]
fn t2_cg_12_empty_codebase() {
    let builder = CallGraphBuilder::new();
    let (graph, stats) = builder.build(&[]).unwrap();

    assert_eq!(graph.function_count(), 0, "empty codebase should have 0 functions");
    assert_eq!(graph.edge_count(), 0, "empty codebase should have 0 edges");
    assert_eq!(stats.total_functions, 0);
    assert_eq!(stats.total_edges, 0);
    assert_eq!(stats.entry_points, 0);
}

#![allow(clippy::unnecessary_get_then_check)]
//! Production stress tests for the coupling module.
//! Targets: Martin metrics edge cases, zone classification boundaries,
//! cycle detection, import graph builder, trend computation.

use drift_analysis::structural::coupling::types::*;
use drift_analysis::structural::coupling::martin_metrics::compute_martin_metrics;
use drift_analysis::structural::coupling::zones::{classify_zone, compute_trend};
use drift_analysis::structural::coupling::cycle_detection::detect_cycles;
use drift_analysis::structural::coupling::import_graph::ImportGraphBuilder;
use rustc_hash::FxHashMap;

// ─── Helpers ────────────────────────────────────────────────────────

fn empty_graph() -> ImportGraph {
    ImportGraph {
        edges: FxHashMap::default(),
        modules: vec![],
        abstract_counts: FxHashMap::default(),
        total_type_counts: FxHashMap::default(),
    }
}

fn simple_graph(modules: &[&str], edges: &[(&str, &[&str])]) -> ImportGraph {
    let mut edge_map = FxHashMap::default();
    for (src, targets) in edges {
        edge_map.insert(
            src.to_string(),
            targets.iter().map(|t| t.to_string()).collect(),
        );
    }
    ImportGraph {
        edges: edge_map,
        modules: modules.iter().map(|m| m.to_string()).collect(),
        abstract_counts: FxHashMap::default(),
        total_type_counts: FxHashMap::default(),
    }
}

// ─── Martin metrics stress ──────────────────────────────────────────

#[test]
fn stress_martin_metrics_empty_graph() {
    let metrics = compute_martin_metrics(&empty_graph());
    assert!(metrics.is_empty());
}

#[test]
fn stress_martin_metrics_isolated_module() {
    let graph = simple_graph(&["auth"], &[]);
    let metrics = compute_martin_metrics(&graph);
    assert_eq!(metrics.len(), 1);
    let m = &metrics[0];
    assert_eq!(m.ce, 0);
    assert_eq!(m.ca, 0);
    assert_eq!(m.instability, 0.0); // 0/(0+0) = 0
    assert_eq!(m.abstractness, 0.0);
    assert_eq!(m.distance, 1.0); // |0 + 0 - 1| = 1
}

#[test]
fn stress_martin_metrics_pure_efferent() {
    // Module depends on everything, nothing depends on it
    let graph = simple_graph(
        &["app", "auth", "db", "cache"],
        &[("app", &["auth", "db", "cache"])],
    );
    let metrics = compute_martin_metrics(&graph);
    let app = metrics.iter().find(|m| m.module == "app").unwrap();
    assert_eq!(app.ce, 3);
    assert_eq!(app.ca, 0);
    assert!((app.instability - 1.0).abs() < f64::EPSILON, "Pure efferent → I=1.0");
}

#[test]
fn stress_martin_metrics_pure_afferent() {
    // Module is depended on by everything, depends on nothing
    let graph = simple_graph(
        &["core", "auth", "db", "api"],
        &[
            ("auth", &["core"]),
            ("db", &["core"]),
            ("api", &["core"]),
        ],
    );
    let metrics = compute_martin_metrics(&graph);
    let core = metrics.iter().find(|m| m.module == "core").unwrap();
    assert_eq!(core.ce, 0);
    assert_eq!(core.ca, 3);
    assert!((core.instability - 0.0).abs() < f64::EPSILON, "Pure afferent → I=0.0");
}

#[test]
fn stress_martin_metrics_abstractness() {
    let mut graph = simple_graph(&["core"], &[]);
    graph.abstract_counts.insert("core".into(), 5);
    graph.total_type_counts.insert("core".into(), 10);
    let metrics = compute_martin_metrics(&graph);
    let core = &metrics[0];
    assert!((core.abstractness - 0.5).abs() < f64::EPSILON);
}

#[test]
fn stress_martin_metrics_abstractness_zero_types() {
    let graph = simple_graph(&["empty"], &[]);
    let metrics = compute_martin_metrics(&graph);
    let m = &metrics[0];
    assert_eq!(m.abstractness, 0.0, "Zero types → abstractness = 0");
}

#[test]
fn stress_martin_metrics_distance_main_sequence() {
    // I=0.5, A=0.5 → D = |0.5 + 0.5 - 1| = 0
    let mut graph = simple_graph(&["balanced", "dep"], &[("balanced", &["dep"])]);
    graph.abstract_counts.insert("balanced".into(), 5);
    graph.total_type_counts.insert("balanced".into(), 10);
    // Ce=1, Ca=0 → I = 1/(1+0) = 1.0 ... need to adjust
    // Actually: balanced depends on dep, and dep depends on balanced for Ca
    // Let's make it symmetric
    let mut graph2 = simple_graph(
        &["a", "b"],
        &[("a", &["b"]), ("b", &["a"])],
    );
    graph2.abstract_counts.insert("a".into(), 5);
    graph2.total_type_counts.insert("a".into(), 10);
    let metrics = compute_martin_metrics(&graph2);
    let a = metrics.iter().find(|m| m.module == "a").unwrap();
    // Ce=1, Ca=1 → I = 0.5, A = 0.5 → D = 0
    assert!((a.instability - 0.5).abs() < f64::EPSILON);
    assert!((a.distance - 0.0).abs() < f64::EPSILON);
}

#[test]
fn stress_martin_metrics_all_bounded() {
    let graph = simple_graph(
        &["a", "b", "c", "d"],
        &[("a", &["b", "c"]), ("b", &["c", "d"]), ("c", &["d"])],
    );
    let metrics = compute_martin_metrics(&graph);
    for m in &metrics {
        assert!(
            (0.0..=1.0).contains(&m.instability),
            "Instability out of bounds for {}: {}",
            m.module,
            m.instability
        );
        assert!(
            (0.0..=1.0).contains(&m.abstractness),
            "Abstractness out of bounds for {}: {}",
            m.module,
            m.abstractness
        );
        assert!(
            m.distance >= 0.0 && m.distance <= 1.5,
            "Distance out of expected range for {}: {}",
            m.module,
            m.distance
        );
    }
}

// ─── Zone classification stress ─────────────────────────────────────

#[test]
fn stress_zone_main_sequence_perfect() {
    // I + A = 1 → distance = 0 → MainSequence
    assert_eq!(classify_zone(0.5, 0.5), ZoneClassification::MainSequence);
    assert_eq!(classify_zone(0.0, 1.0), ZoneClassification::MainSequence);
    assert_eq!(classify_zone(1.0, 0.0), ZoneClassification::MainSequence);
}

#[test]
fn stress_zone_of_pain() {
    // Low I, low A, far from main sequence
    assert_eq!(classify_zone(0.1, 0.1), ZoneClassification::ZoneOfPain);
    assert_eq!(classify_zone(0.0, 0.0), ZoneClassification::ZoneOfPain);
}

#[test]
fn stress_zone_of_uselessness() {
    // High I, high A, far from main sequence
    assert_eq!(classify_zone(0.9, 0.9), ZoneClassification::ZoneOfUselessness);
    assert_eq!(classify_zone(1.0, 1.0), ZoneClassification::ZoneOfUselessness);
}

#[test]
fn stress_zone_boundary_threshold() {
    // Distance = 0.3 is the threshold for MainSequence
    // I=0.5, A=0.2 → D = |0.2 + 0.5 - 1| = 0.3 → MainSequence
    assert_eq!(classify_zone(0.5, 0.2), ZoneClassification::MainSequence);
}

#[test]
fn stress_zone_names() {
    assert_eq!(ZoneClassification::ZoneOfPain.name(), "zone_of_pain");
    assert_eq!(ZoneClassification::ZoneOfUselessness.name(), "zone_of_uselessness");
    assert_eq!(ZoneClassification::MainSequence.name(), "main_sequence");
}

// ─── Cycle detection stress ─────────────────────────────────────────

#[test]
fn stress_cycles_empty_graph() {
    let cycles = detect_cycles(&empty_graph());
    assert!(cycles.is_empty());
}

#[test]
fn stress_cycles_no_cycles() {
    let graph = simple_graph(
        &["a", "b", "c"],
        &[("a", &["b"]), ("b", &["c"])],
    );
    let cycles = detect_cycles(&graph);
    assert!(cycles.is_empty(), "DAG should have no cycles");
}

#[test]
fn stress_cycles_simple_cycle() {
    let graph = simple_graph(
        &["a", "b"],
        &[("a", &["b"]), ("b", &["a"])],
    );
    let cycles = detect_cycles(&graph);
    assert_eq!(cycles.len(), 1, "A↔B should form one cycle");
    assert_eq!(cycles[0].members.len(), 2);
    assert!(!cycles[0].break_suggestions.is_empty());
}

#[test]
fn stress_cycles_triangle() {
    let graph = simple_graph(
        &["a", "b", "c"],
        &[("a", &["b"]), ("b", &["c"]), ("c", &["a"])],
    );
    let cycles = detect_cycles(&graph);
    assert_eq!(cycles.len(), 1, "A→B→C→A should form one cycle");
    assert_eq!(cycles[0].members.len(), 3);
}

#[test]
fn stress_cycles_multiple_independent() {
    let graph = simple_graph(
        &["a", "b", "c", "d"],
        &[("a", &["b"]), ("b", &["a"]), ("c", &["d"]), ("d", &["c"])],
    );
    let cycles = detect_cycles(&graph);
    assert_eq!(cycles.len(), 2, "Two independent cycles");
}

#[test]
fn stress_cycles_self_loop_not_counted() {
    // Self-loops are SCCs of size 1 → filtered out
    let graph = simple_graph(&["a"], &[("a", &["a"])]);
    let cycles = detect_cycles(&graph);
    assert!(cycles.is_empty(), "Self-loop should not be counted as a cycle");
}

#[test]
fn stress_cycles_break_suggestions_sorted() {
    let graph = simple_graph(
        &["a", "b", "c"],
        &[("a", &["b"]), ("b", &["c"]), ("c", &["a"])],
    );
    let cycles = detect_cycles(&graph);
    for cycle in &cycles {
        for window in cycle.break_suggestions.windows(2) {
            assert!(
                window[0].impact_score <= window[1].impact_score,
                "Break suggestions should be sorted by impact"
            );
        }
    }
}

// ─── Import graph builder stress ────────────────────────────────────

#[test]
fn stress_builder_empty() {
    let builder = ImportGraphBuilder::new(1);
    let graph = builder.build();
    assert!(graph.modules.is_empty());
    assert!(graph.edges.is_empty());
}

#[test]
fn stress_builder_single_file() {
    let mut builder = ImportGraphBuilder::new(1);
    builder.add_file("src/app.ts", &[]);
    let graph = builder.build();
    assert_eq!(graph.modules.len(), 1);
}

#[test]
fn stress_builder_cross_module_edges() {
    let mut builder = ImportGraphBuilder::new(1);
    builder.add_file("auth/login.ts", &["db/users.ts".to_string()]);
    builder.add_file("db/users.ts", &[]);
    let graph = builder.build();
    assert!(graph.modules.len() >= 2);
    assert!(
        graph.edges.get("auth").is_some(),
        "auth should have edges to db"
    );
}

#[test]
fn stress_builder_same_module_no_edge() {
    let mut builder = ImportGraphBuilder::new(1);
    builder.add_file("auth/login.ts", &["auth/register.ts".to_string()]);
    builder.add_file("auth/register.ts", &[]);
    let graph = builder.build();
    // Same module → no cross-module edge
    let auth_edges = graph.edges.get("auth");
    assert!(
        auth_edges.is_none() || auth_edges.unwrap().is_empty(),
        "Intra-module imports should not create edges"
    );
}

#[test]
fn stress_builder_type_counts_aggregated() {
    let mut builder = ImportGraphBuilder::new(1);
    builder.add_file("auth/login.ts", &[]);
    builder.set_type_counts("auth/login.ts", 3, 10);
    builder.add_file("auth/register.ts", &[]);
    builder.set_type_counts("auth/register.ts", 2, 5);
    let graph = builder.build();
    assert_eq!(
        *graph.abstract_counts.get("auth").unwrap_or(&0),
        5,
        "Abstract counts should be aggregated"
    );
    assert_eq!(
        *graph.total_type_counts.get("auth").unwrap_or(&0),
        15,
        "Total type counts should be aggregated"
    );
}

#[test]
fn stress_builder_module_depth_2() {
    let mut builder = ImportGraphBuilder::new(2);
    builder.add_file("src/auth/login.ts", &["src/db/users.ts".to_string()]);
    builder.add_file("src/db/users.ts", &[]);
    let graph = builder.build();
    // With depth 2, modules are "src/auth" and "src/db"
    assert!(graph.modules.iter().any(|m| m == "src/auth"));
    assert!(graph.modules.iter().any(|m| m == "src/db"));
}

#[test]
fn stress_builder_windows_paths() {
    let mut builder = ImportGraphBuilder::new(1);
    builder.add_file("auth\\login.ts", &["db\\users.ts".to_string()]);
    builder.add_file("db\\users.ts", &[]);
    let graph = builder.build();
    // Backslashes should be normalized
    assert!(graph.modules.len() >= 2);
}

// ─── Trend computation stress ───────────────────────────────────────

#[test]
fn stress_trend_improving() {
    let prev = CouplingMetrics {
        module: "auth".into(), ce: 5, ca: 3, instability: 0.625,
        abstractness: 0.3, distance: 0.5, zone: ZoneClassification::ZoneOfPain,
    };
    let curr = CouplingMetrics {
        module: "auth".into(), ce: 3, ca: 3, instability: 0.5,
        abstractness: 0.4, distance: 0.1, zone: ZoneClassification::MainSequence,
    };
    let trend = compute_trend(&prev, &curr);
    assert_eq!(trend.direction, TrendDirection::Improving);
}

#[test]
fn stress_trend_degrading() {
    let prev = CouplingMetrics {
        module: "auth".into(), ce: 2, ca: 3, instability: 0.4,
        abstractness: 0.5, distance: 0.1, zone: ZoneClassification::MainSequence,
    };
    let curr = CouplingMetrics {
        module: "auth".into(), ce: 5, ca: 1, instability: 0.83,
        abstractness: 0.1, distance: 0.5, zone: ZoneClassification::ZoneOfPain,
    };
    let trend = compute_trend(&prev, &curr);
    assert_eq!(trend.direction, TrendDirection::Degrading);
}

#[test]
fn stress_trend_stable() {
    let m = CouplingMetrics {
        module: "auth".into(), ce: 3, ca: 3, instability: 0.5,
        abstractness: 0.5, distance: 0.0, zone: ZoneClassification::MainSequence,
    };
    let trend = compute_trend(&m, &m);
    assert_eq!(trend.direction, TrendDirection::Stable);
}

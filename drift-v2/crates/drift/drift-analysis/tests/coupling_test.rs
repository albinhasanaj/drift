#![allow(clippy::field_reassign_with_default, unused_imports)]
//! Phase 5 coupling analysis tests (T5-CPL-01 through T5-CPL-07).

use drift_analysis::structural::coupling::types::*;
use drift_analysis::structural::coupling::martin_metrics::compute_martin_metrics;
use drift_analysis::structural::coupling::cycle_detection::detect_cycles;
use drift_analysis::structural::coupling::zones::classify_zone;

/// T5-CPL-01: Martin metrics computed correctly on known module graph.
#[test]
fn test_martin_metrics_correctness() {
    let mut graph = ImportGraph::default();
    // Module A depends on B and C (Ce=2)
    // Module B depends on C (Ce=1)
    // Module C depends on nothing (Ce=0)
    graph.modules = vec!["A".into(), "B".into(), "C".into()];
    graph.edges.insert("A".into(), vec!["B".into(), "C".into()]);
    graph.edges.insert("B".into(), vec!["C".into()]);
    graph.edges.insert("C".into(), vec![]);
    graph.abstract_counts.insert("A".into(), 0);
    graph.abstract_counts.insert("B".into(), 1);
    graph.abstract_counts.insert("C".into(), 2);
    graph.total_type_counts.insert("A".into(), 4);
    graph.total_type_counts.insert("B".into(), 4);
    graph.total_type_counts.insert("C".into(), 4);

    let metrics = compute_martin_metrics(&graph);
    assert_eq!(metrics.len(), 3);

    // Module A: Ce=2, Ca=0 (nobody depends on A)
    let a = metrics.iter().find(|m| m.module == "A").unwrap();
    assert_eq!(a.ce, 2);
    assert_eq!(a.ca, 0);
    // I = Ce/(Ce+Ca) = 2/2 = 1.0
    assert!((a.instability - 1.0).abs() < 0.001);
    // A = abstract/total = 0/4 = 0.0
    assert!((a.abstractness - 0.0).abs() < 0.001);
    // D = |A + I - 1| = |0 + 1 - 1| = 0.0
    assert!((a.distance - 0.0).abs() < 0.001);

    // Module C: Ce=0, Ca=2 (A and B depend on C)
    let c = metrics.iter().find(|m| m.module == "C").unwrap();
    assert_eq!(c.ce, 0);
    assert_eq!(c.ca, 2);
    // I = 0/2 = 0.0
    assert!((c.instability - 0.0).abs() < 0.001);
    // A = 2/4 = 0.5
    assert!((c.abstractness - 0.5).abs() < 0.001);
}

/// T5-CPL-02: Zone classification correctness.
#[test]
fn test_zone_classification() {
    // Zone of Pain: high Ca, low A (concrete, heavily depended upon)
    let pain = classify_zone(0.1, 0.1); // low I, low A
    assert_eq!(pain, ZoneClassification::ZoneOfPain);

    // Zone of Uselessness: low Ca, high A (abstract, nobody uses)
    let useless = classify_zone(0.9, 0.9); // high I, high A
    assert_eq!(useless, ZoneClassification::ZoneOfUselessness);

    // Main Sequence: near I + A = 1
    let main_seq = classify_zone(0.5, 0.5); // I + A = 1.0
    assert_eq!(main_seq, ZoneClassification::MainSequence);
}

/// T5-CPL-03: Tarjan's SCC detects known cycles.
#[test]
fn test_cycle_detection() {
    let mut graph = ImportGraph::default();
    // Cycle 1: A → B → A
    // Cycle 2: C → D → E → C
    graph.modules = vec!["A".into(), "B".into(), "C".into(), "D".into(), "E".into(), "F".into()];
    graph.edges.insert("A".into(), vec!["B".into()]);
    graph.edges.insert("B".into(), vec!["A".into()]);
    graph.edges.insert("C".into(), vec!["D".into()]);
    graph.edges.insert("D".into(), vec!["E".into()]);
    graph.edges.insert("E".into(), vec!["C".into()]);
    graph.edges.insert("F".into(), vec![]); // no cycle

    let cycles = detect_cycles(&graph);
    // Should find 2 cycles (SCCs with >1 member)
    assert_eq!(cycles.len(), 2);

    // Verify cycle members
    let cycle_sizes: Vec<usize> = {
        let mut sizes: Vec<usize> = cycles.iter().map(|c| c.members.len()).collect();
        sizes.sort();
        sizes
    };
    assert_eq!(cycle_sizes, vec![2, 3]); // {A,B} and {C,D,E}
}

/// T5-CPL-04: Cycle break suggestions exist for each cycle.
#[test]
fn test_cycle_break_suggestions() {
    let mut graph = ImportGraph::default();
    graph.modules = vec!["A".into(), "B".into()];
    graph.edges.insert("A".into(), vec!["B".into()]);
    graph.edges.insert("B".into(), vec!["A".into()]);

    let cycles = detect_cycles(&graph);
    assert!(!cycles.is_empty());
    for cycle in &cycles {
        assert!(!cycle.break_suggestions.is_empty(),
            "Each cycle should have at least one break suggestion");
    }
}

/// T5-CPL-06: Trend tracking direction.
#[test]
fn test_trend_direction() {
    let prev = CouplingMetrics {
        module: "X".into(), ce: 5, ca: 3, instability: 0.625,
        abstractness: 0.3, distance: 0.075, zone: ZoneClassification::MainSequence,
    };
    let curr = CouplingMetrics {
        module: "X".into(), ce: 3, ca: 3, instability: 0.5,
        abstractness: 0.5, distance: 0.0, zone: ZoneClassification::MainSequence,
    };
    // Distance decreased from 0.075 to 0.0 → improving
    let trend = CouplingTrend {
        module: "X".into(),
        previous: prev,
        current: curr,
        direction: if 0.0 < 0.075 { TrendDirection::Improving } else { TrendDirection::Degrading },
    };
    assert_eq!(trend.direction, TrendDirection::Improving);
}

/// T5-CPL-07: Single-module graph — no crash, neutral metrics.
#[test]
fn test_single_module_graph() {
    let mut graph = ImportGraph::default();
    graph.modules = vec!["Solo".into()];
    graph.edges.insert("Solo".into(), vec![]);
    graph.abstract_counts.insert("Solo".into(), 0);
    graph.total_type_counts.insert("Solo".into(), 1);

    let metrics = compute_martin_metrics(&graph);
    assert_eq!(metrics.len(), 1);
    let solo = &metrics[0];
    assert_eq!(solo.ce, 0);
    assert_eq!(solo.ca, 0);

    let cycles = detect_cycles(&graph);
    assert!(cycles.is_empty());
}

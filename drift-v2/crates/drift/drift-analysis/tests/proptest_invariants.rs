//! Property-based tests for mathematical invariants across Phase 5.
//!
//! Uses proptest to fuzz-verify:
//!   - Shannon entropy bounds (0.0 ≤ H ≤ 8.0)
//!   - Bayesian confidence monotonicity and bounds
//!   - Martin metric algebraic invariants (I, A, D relationships)
//!
//! Tests prefixed `regression_gate_` are CI SLO gates — failures here
//! block merge. Run with: `cargo test regression_gate_`

use proptest::prelude::*;

use drift_analysis::structural::constants::entropy::shannon_entropy;
use drift_analysis::structural::contracts::confidence::bayesian_confidence;
use drift_analysis::structural::coupling::martin_metrics::compute_martin_metrics;
use drift_analysis::structural::coupling::types::ImportGraph;
use drift_analysis::structural::coupling::zones::classify_zone;
use rustc_hash::FxHashMap;

// ═══════════════════════════════════════════════════════════════════
// Shannon Entropy Properties
// ═══════════════════════════════════════════════════════════════════

proptest! {
    /// REGRESSION GATE: Entropy is always in [0.0, 8.0] for any byte string.
    /// 8.0 = theoretical max for 256 equally-distributed byte values.
    #[test]
    fn regression_gate_entropy_bounded(s in "\\PC{0,512}") {
        let h = shannon_entropy(&s);
        prop_assert!(h >= 0.0, "Entropy must be >= 0.0, got {}", h);
        prop_assert!(h <= 8.0, "Entropy must be <= 8.0 (log2(256)), got {}", h);
    }

    /// Entropy of a single repeated character is always 0.
    #[test]
    fn prop_entropy_repeated_char_is_zero(c in any::<char>(), n in 1usize..200) {
        let s: String = std::iter::repeat(c).take(n).collect();
        let h = shannon_entropy(&s);
        // A single unique byte → 0 entropy. But multi-byte chars may have
        // multiple distinct bytes, so only assert 0 for ASCII.
        if c.is_ascii() {
            prop_assert!(
                h < 0.01,
                "Repeated ASCII '{}' x{} should have ~0 entropy, got {}",
                c, n, h
            );
        }
    }

    /// Entropy is non-negative for any arbitrary bytes.
    #[test]
    fn prop_entropy_non_negative(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let s = String::from_utf8_lossy(&bytes);
        let h = shannon_entropy(&s);
        prop_assert!(h >= 0.0, "Entropy must be non-negative, got {}", h);
    }

    /// Adding distinct characters can only increase or maintain entropy.
    #[test]
    fn prop_entropy_monotonic_with_diversity(base in "[a-z]{10,50}") {
        let h_base = shannon_entropy(&base);
        // Append digits to increase character diversity
        let enriched = format!("{}0123456789!@#$", base);
        let h_enriched = shannon_entropy(&enriched);
        // More diverse character set → entropy should not decrease significantly
        // (it can decrease slightly due to frequency redistribution, so we allow a small margin)
        prop_assert!(
            h_enriched >= h_base - 0.5,
            "Adding diversity should not drastically reduce entropy: base={}, enriched={}",
            h_base, h_enriched
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Bayesian Confidence Properties
// ═══════════════════════════════════════════════════════════════════

proptest! {
    /// REGRESSION GATE: Bayesian confidence is always in [0.0, 1.0].
    #[test]
    fn regression_gate_bayesian_bounded(
        s0 in -10.0f64..10.0,
        s1 in -10.0f64..10.0,
        s2 in -10.0f64..10.0,
        s3 in -10.0f64..10.0,
        s4 in -10.0f64..10.0,
        s5 in -10.0f64..10.0,
        s6 in -10.0f64..10.0,
    ) {
        let signals = [s0, s1, s2, s3, s4, s5, s6];
        let c = bayesian_confidence(&signals);
        prop_assert!(c >= 0.0, "Confidence must be >= 0.0, got {} for {:?}", c, signals);
        prop_assert!(c <= 1.0, "Confidence must be <= 1.0, got {} for {:?}", c, signals);
    }

    /// Monotonicity: increasing any single signal should not decrease confidence.
    #[test]
    fn regression_gate_bayesian_monotonic(
        s0 in 0.0f64..1.0,
        s1 in 0.0f64..1.0,
        s2 in 0.0f64..1.0,
        s3 in 0.0f64..1.0,
        s4 in 0.0f64..1.0,
        s5 in 0.0f64..1.0,
        s6 in 0.0f64..1.0,
        idx in 0usize..7,
    ) {
        let signals = [s0, s1, s2, s3, s4, s5, s6];
        let base = bayesian_confidence(&signals);

        let mut boosted = signals;
        boosted[idx] = 1.0; // max out one signal
        let after = bayesian_confidence(&boosted);

        prop_assert!(
            after >= base - f64::EPSILON,
            "Boosting signal[{}] from {} to 1.0 should not decrease confidence: {} -> {}",
            idx, signals[idx], base, after
        );
    }

    /// All-zero signals → confidence = 0.
    #[test]
    fn prop_bayesian_all_zero_is_zero(
        _dummy in 0..1  // proptest needs at least one input
    ) {
        let c = bayesian_confidence(&[0.0; 7]);
        prop_assert!((c - 0.0).abs() < f64::EPSILON, "All-zero signals should give 0.0, got {}", c);
    }

    /// All-one signals → confidence = 1.0.
    #[test]
    fn prop_bayesian_all_one_is_one(
        _dummy in 0..1
    ) {
        let c = bayesian_confidence(&[1.0; 7]);
        prop_assert!((c - 1.0).abs() < f64::EPSILON, "All-one signals should give 1.0, got {}", c);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Martin Metrics Properties
// ═══════════════════════════════════════════════════════════════════

/// Build a random ImportGraph with `n` modules and random edges.
fn random_import_graph(
    n: usize,
    edges: Vec<(usize, usize)>,
    abstract_ratios: Vec<(usize, u32, u32)>,
) -> ImportGraph {
    let modules: Vec<String> = (0..n).map(|i| format!("mod_{}", i)).collect();
    let mut edge_map: FxHashMap<String, Vec<String>> = FxHashMap::default();
    let mut abstract_counts: FxHashMap<String, u32> = FxHashMap::default();
    let mut total_type_counts: FxHashMap<String, u32> = FxHashMap::default();

    for (src, dst) in edges {
        if src < n && dst < n && src != dst {
            edge_map
                .entry(modules[src].clone())
                .or_default()
                .push(modules[dst].clone());
        }
    }

    // Dedup edges
    for targets in edge_map.values_mut() {
        targets.sort();
        targets.dedup();
    }

    for (idx, abs_count, total) in abstract_ratios {
        if idx < n && total > 0 {
            let abs_clamped = abs_count.min(total);
            abstract_counts.insert(modules[idx].clone(), abs_clamped);
            total_type_counts.insert(modules[idx].clone(), total);
        }
    }

    ImportGraph {
        edges: edge_map,
        modules,
        abstract_counts,
        total_type_counts,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// REGRESSION GATE: Instability is always in [0.0, 1.0].
    #[test]
    fn regression_gate_instability_bounded(
        n in 2usize..20,
        edges in prop::collection::vec((0usize..20, 0usize..20), 0..50),
    ) {
        let graph = random_import_graph(n, edges, vec![]);
        let metrics = compute_martin_metrics(&graph);
        for m in &metrics {
            prop_assert!(
                m.instability >= 0.0 && m.instability <= 1.0,
                "Instability must be in [0,1], got {} for {}",
                m.instability, m.module
            );
        }
    }

    /// REGRESSION GATE: Abstractness is always in [0.0, 1.0].
    #[test]
    fn regression_gate_abstractness_bounded(
        n in 2usize..15,
        edges in prop::collection::vec((0usize..15, 0usize..15), 0..30),
        abs_ratios in prop::collection::vec((0usize..15, 0u32..50, 1u32..50), 0..15),
    ) {
        let graph = random_import_graph(n, edges, abs_ratios);
        let metrics = compute_martin_metrics(&graph);
        for m in &metrics {
            prop_assert!(
                m.abstractness >= 0.0 && m.abstractness <= 1.0,
                "Abstractness must be in [0,1], got {} for {}",
                m.abstractness, m.module
            );
        }
    }

    /// REGRESSION GATE: Distance D = |A + I - 1| and D ∈ [0.0, 1.0].
    #[test]
    fn regression_gate_distance_invariant(
        n in 2usize..15,
        edges in prop::collection::vec((0usize..15, 0usize..15), 0..30),
        abs_ratios in prop::collection::vec((0usize..15, 0u32..50, 1u32..50), 0..15),
    ) {
        let graph = random_import_graph(n, edges, abs_ratios);
        let metrics = compute_martin_metrics(&graph);
        for m in &metrics {
            let expected_d = (m.abstractness + m.instability - 1.0).abs();
            prop_assert!(
                (m.distance - expected_d).abs() < 1e-10,
                "D should equal |A+I-1|: got D={}, expected {} (A={}, I={})",
                m.distance, expected_d, m.abstractness, m.instability
            );
            prop_assert!(
                m.distance >= 0.0 && m.distance <= 1.0,
                "Distance must be in [0,1], got {} for {}",
                m.distance, m.module
            );
        }
    }

    /// Isolated module (no edges) has I=0, D=|A-1|.
    #[test]
    fn prop_isolated_module_stable(
        abs_count in 0u32..10,
        total in 1u32..10,
    ) {
        let abs_clamped = abs_count.min(total);
        let graph = random_import_graph(1, vec![], vec![(0, abs_clamped, total)]);
        let metrics = compute_martin_metrics(&graph);
        prop_assert_eq!(metrics.len(), 1);
        let m = &metrics[0];
        prop_assert!(
            m.instability.abs() < f64::EPSILON,
            "Isolated module should have I=0, got {}", m.instability
        );
        let expected_a = abs_clamped as f64 / total as f64;
        prop_assert!(
            (m.abstractness - expected_a).abs() < 1e-10,
            "Abstractness should be {}/{} = {}, got {}",
            abs_clamped, total, expected_a, m.abstractness
        );
    }

    /// Zone classification is total — every (I, A) pair maps to some zone.
    #[test]
    fn regression_gate_zone_classification_total(
        i in 0.0f64..1.0,
        a in 0.0f64..1.0,
    ) {
        let zone = classify_zone(i, a);
        // Just verify it returns one of the three variants (no panic)
        let _ = zone.name();
    }
}

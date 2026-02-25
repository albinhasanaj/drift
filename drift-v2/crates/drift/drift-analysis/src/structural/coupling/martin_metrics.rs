//! Robert C. Martin coupling metrics computation.
//!
//! Ce (efferent), Ca (afferent), I (instability), A (abstractness),
//! D (distance from main sequence).

use drift_core::types::collections::FxHashMap;

use super::types::{CouplingMetrics, ImportGraph};
use super::zones::classify_zone;

/// Compute Martin metrics for every module in the import graph.
pub fn compute_martin_metrics(graph: &ImportGraph) -> Vec<CouplingMetrics> {
    // Ce: count of distinct modules this module depends on
    let mut ce_map: FxHashMap<String, u32> = FxHashMap::default();
    // Ca: count of distinct modules that depend on this module
    let mut ca_map: FxHashMap<String, u32> = FxHashMap::default();

    // Initialize all modules
    for module in &graph.modules {
        ce_map.entry(module.clone()).or_insert(0);
        ca_map.entry(module.clone()).or_insert(0);
    }

    // Compute Ce and Ca
    for (src, targets) in &graph.edges {
        let ce = targets.len() as u32;
        *ce_map.entry(src.clone()).or_default() = ce;
        for target in targets {
            *ca_map.entry(target.clone()).or_default() += 1;
        }
    }

    graph
        .modules
        .iter()
        .map(|module| {
            let ce = *ce_map.get(module).unwrap_or(&0);
            let ca = *ca_map.get(module).unwrap_or(&0);

            // I = Ce / (Ce + Ca), 0 if both are 0
            let instability = if ce + ca == 0 {
                0.0
            } else {
                ce as f64 / (ce + ca) as f64
            };

            // A = abstract_types / total_types, 0 if no types
            let abstract_count = graph.abstract_counts.get(module).copied().unwrap_or(0);
            let total_count = graph.total_type_counts.get(module).copied().unwrap_or(0);
            let abstractness = if total_count == 0 {
                0.0
            } else {
                abstract_count as f64 / total_count as f64
            };

            // D = |A + I - 1|
            let distance = (abstractness + instability - 1.0).abs();

            let zone = classify_zone(instability, abstractness);

            CouplingMetrics {
                module: module.clone(),
                ce,
                ca,
                instability,
                abstractness,
                distance,
                zone,
            }
        })
        .collect()
}

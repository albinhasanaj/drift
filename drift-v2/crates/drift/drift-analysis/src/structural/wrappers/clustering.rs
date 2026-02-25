//! Wrapper clustering — groups related wrappers by category, primitive, and similarity.
//!
//! Algorithm:
//! 1. Group wrappers by (category, primary_primitive)
//! 2. Refine via Jaccard similarity on wrapped primitives
//! 3. Generate cluster names and descriptions
//! 4. Compute per-cluster health scores

use super::types::{Wrapper, WrapperCategory, WrapperHealth};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

/// A group of related wrappers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperCluster {
    /// Deterministic cluster ID.
    pub id: String,
    /// Auto-generated cluster name.
    pub name: String,
    /// Primary category.
    pub category: WrapperCategory,
    /// Member wrappers.
    pub wrappers: Vec<Wrapper>,
    /// Sum of all member usage counts.
    pub total_usage: u32,
    /// Intra-cluster similarity (0.0–1.0).
    pub similarity_score: f64,
    /// Cluster health score (0.0–100.0).
    pub health: f64,
    /// Auto-generated description.
    pub description: String,
}

/// Cluster wrappers by category and primitive similarity.
pub fn cluster_wrappers(wrappers: &[Wrapper]) -> Vec<WrapperCluster> {
    let mut clusters = Vec::new();

    // Phase 1: Group by (category, primary_primitive)
    let mut groups: FxHashMap<(WrapperCategory, String), Vec<&Wrapper>> =
        FxHashMap::default();

    for wrapper in wrappers {
        let primary = wrapper.wrapped_primitives.first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        groups.entry((wrapper.category, primary))
            .or_default()
            .push(wrapper);
    }

    // Phase 2: Similarity refinement
    for ((category, primary), members) in &groups {
        if members.len() == 1 {
            clusters.push(build_cluster(category, primary, members, 1.0));
            continue;
        }

        let avg_sim = avg_pairwise_similarity(members);
        if avg_sim >= 0.3 {
            // Keep as single cluster
            clusters.push(build_cluster(category, primary, members, avg_sim));
        } else {
            // Split: each member becomes its own cluster
            for member in members {
                clusters.push(build_cluster(
                    category, primary, &[member], 1.0,
                ));
            }
        }
    }

    // Sort clusters by total_usage descending for deterministic output
    clusters.sort_by(|a, b| {
        b.total_usage.cmp(&a.total_usage)
            .then_with(|| a.name.cmp(&b.name))
    });

    clusters
}

/// Compute wrapper health from cluster data.
pub fn compute_wrapper_health(wrappers: &[Wrapper], _clusters: &[WrapperCluster]) -> WrapperHealth {
    if wrappers.is_empty() {
        return WrapperHealth {
            consistency: 0.0,
            coverage: 0.0,
            abstraction_depth: 0.0,
            overall: 0.0,
        };
    }

    // Consistency: how uniformly wrappers are used across the project.
    // Measured by the coefficient of variation of usage counts.
    let usage_counts: Vec<f64> = wrappers.iter().map(|w| w.usage_count as f64).collect();
    let mean_usage = usage_counts.iter().sum::<f64>() / usage_counts.len() as f64;
    let variance = if usage_counts.len() > 1 {
        usage_counts.iter().map(|u| (u - mean_usage).powi(2)).sum::<f64>()
            / (usage_counts.len() - 1) as f64
    } else {
        0.0
    };
    let cv = if mean_usage > 0.0 { variance.sqrt() / mean_usage } else { 0.0 };
    let consistency = ((1.0 - cv.min(1.0)) * 100.0).clamp(0.0, 100.0);

    // Coverage: fraction of wrappers that are exported (available for reuse).
    let exported = wrappers.iter().filter(|w| w.is_exported).count() as f64;
    let coverage = (exported / wrappers.len() as f64 * 100.0).clamp(0.0, 100.0);

    // Abstraction depth: average number of wrapped primitives (lower is better).
    let avg_prims: f64 = wrappers.iter()
        .map(|w| w.wrapped_primitives.len() as f64)
        .sum::<f64>() / wrappers.len() as f64;
    // Score: 1 primitive = 100, 2 = 80, 3 = 60, 4+ = 40
    let abstraction_depth = (120.0 - avg_prims * 20.0).clamp(0.0, 100.0);

    // Overall: weighted composite
    let overall = (consistency * 0.40 + coverage * 0.30 + abstraction_depth * 0.30)
        .clamp(0.0, 100.0);

    WrapperHealth {
        consistency,
        coverage,
        abstraction_depth,
        overall,
    }
}

/// Jaccard similarity between two sets of wrapped primitives.
fn jaccard_similarity(a: &[String], b: &[String]) -> f64 {
    let set_a: FxHashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let set_b: FxHashSet<&str> = b.iter().map(|s| s.as_str()).collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 {
        return 0.0;
    }
    intersection as f64 / union as f64
}

/// Average pairwise Jaccard similarity across cluster members.
fn avg_pairwise_similarity(members: &[&Wrapper]) -> f64 {
    if members.len() < 2 {
        return 1.0;
    }
    let mut total = 0.0;
    let mut count = 0u32;
    for i in 0..members.len() {
        for j in (i + 1)..members.len() {
            total += jaccard_similarity(
                &members[i].wrapped_primitives,
                &members[j].wrapped_primitives,
            );
            count += 1;
        }
    }
    if count == 0 { 1.0 } else { total / count as f64 }
}

/// Build a cluster from its members.
fn build_cluster(
    category: &WrapperCategory,
    primary: &str,
    members: &[&Wrapper],
    similarity: f64,
) -> WrapperCluster {
    let total_usage: u32 = members.iter().map(|w| w.usage_count).sum();
    let avg_confidence: f64 = members.iter().map(|w| w.confidence).sum::<f64>()
        / members.len().max(1) as f64;
    let member_count = members.len();
    let file_count = members.iter()
        .map(|w| w.file.as_str())
        .collect::<FxHashSet<_>>()
        .len();

    // Deterministic ID from sorted member names + files
    let mut id_parts: Vec<String> = members.iter()
        .map(|w| format!("{}:{}", w.file, w.name))
        .collect();
    id_parts.sort();
    let id_source = id_parts.join("|");
    let id = format!("{:016x}", hash_string(&id_source));

    let name = format!("{} wrappers ({})", category.name(), primary);
    let description = format!(
        "{} {} wrapper{} around {}, used {} time{} across {} file{}",
        member_count,
        category.name(),
        if member_count != 1 { "s" } else { "" },
        primary,
        total_usage,
        if total_usage != 1 { "s" } else { "" },
        file_count,
        if file_count != 1 { "s" } else { "" },
    );

    WrapperCluster {
        id,
        name,
        category: *category,
        wrappers: members.iter().map(|w| (*w).clone()).collect(),
        total_usage,
        similarity_score: similarity,
        health: avg_confidence * 100.0,
        description,
    }
}

/// Simple deterministic hash for cluster IDs.
fn hash_string(s: &str) -> u64 {
    // Use FxHash for deterministic, fast hashing
    use std::hash::{Hash, Hasher};
    let mut hasher = rustc_hash::FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

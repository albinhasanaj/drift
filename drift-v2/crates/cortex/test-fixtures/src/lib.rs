//! Test fixture loader for Cortex golden datasets, benchmarks, and integration scenarios.
//!
//! Provides typed deserialization of all fixture JSON files and helper functions
//! for loading them in tests across crates.

use serde::de::DeserializeOwned;
use std::path::PathBuf;

/// Root directory of the test-fixtures folder.
fn fixtures_root() -> PathBuf {
    // Works from any crate in the workspace: walk up to find test-fixtures.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let mut path = PathBuf::from(&manifest_dir);

    // If we're inside a crate (e.g. cortex-consolidation), go up to workspace root.
    while !path.join("test-fixtures").exists() {
        if !path.pop() {
            panic!(
                "Could not find test-fixtures directory from CARGO_MANIFEST_DIR={}",
                manifest_dir
            );
        }
    }
    path.join("test-fixtures")
}

/// Load and deserialize a JSON fixture file.
///
/// # Panics
/// Panics if the file doesn't exist or can't be deserialized.
pub fn load_fixture<T: DeserializeOwned>(relative_path: &str) -> T {
    let path = fixtures_root().join(relative_path);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse fixture {}: {}", path.display(), e))
}

/// Load a fixture file as raw JSON Value.
pub fn load_fixture_value(relative_path: &str) -> serde_json::Value {
    load_fixture(relative_path)
}

/// Check that a fixture file exists.
pub fn fixture_exists(relative_path: &str) -> bool {
    fixtures_root().join(relative_path).exists()
}

/// Get the absolute path to a fixture file.
pub fn fixture_path(relative_path: &str) -> PathBuf {
    fixtures_root().join(relative_path)
}

/// List all JSON files in a fixture subdirectory.
pub fn list_fixtures(subdir: &str) -> Vec<PathBuf> {
    let dir = fixtures_root().join(subdir);
    if !dir.exists() {
        return Vec::new();
    }
    std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("Failed to read directory {}: {}", dir.display(), e))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                Some(path)
            } else {
                None
            }
        })
        .collect()
}

/// Load the binary embeddings file.
///
/// Format: header (count: u32 LE, dims: u32 LE) + body (count * dims * f32 LE).
pub fn load_embeddings_binary(relative_path: &str) -> (usize, usize, Vec<Vec<f32>>) {
    let path = fixtures_root().join(relative_path);
    let data = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("Failed to read embeddings {}: {}", path.display(), e));

    assert!(data.len() >= 8, "Embeddings file too small for header");

    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let dims = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

    let expected_size = 8 + count * dims * 4;
    assert_eq!(
        data.len(),
        expected_size,
        "Embeddings file size mismatch: expected {} bytes, got {}",
        expected_size,
        data.len()
    );

    let mut vectors = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 8 + i * dims * 4;
        let mut vec = Vec::with_capacity(dims);
        for j in 0..dims {
            let idx = offset + j * 4;
            let val = f32::from_le_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]);
            vec.push(val);
        }
        vectors.push(vec);
    }

    (count, dims, vectors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_root_exists() {
        assert!(
            fixtures_root().exists(),
            "test-fixtures directory not found"
        );
    }

    #[test]
    fn all_golden_consolidation_files_exist() {
        let files = [
            "golden/consolidation/cluster_2_basic.json",
            "golden/consolidation/cluster_3_overlapping.json",
            "golden/consolidation/cluster_5_diverse.json",
            "golden/consolidation/cluster_with_noise.json",
            "golden/consolidation/anchor_selection.json",
            "golden/consolidation/summary_generation.json",
            "golden/consolidation/metadata_union.json",
            "golden/consolidation/confidence_boost.json",
            "golden/consolidation/integration_dedup.json",
            "golden/consolidation/recall_gate_fail.json",
        ];
        for f in &files {
            assert!(fixture_exists(f), "Missing fixture: {}", f);
        }
    }

    #[test]
    fn all_golden_retrieval_files_exist() {
        let files = [
            "golden/retrieval/keyword_match.json",
            "golden/retrieval/semantic_match.json",
            "golden/retrieval/hybrid_rrf.json",
            "golden/retrieval/intent_weighting.json",
            "golden/retrieval/importance_ranking.json",
            "golden/retrieval/session_dedup.json",
            "golden/retrieval/budget_packing.json",
            "golden/retrieval/empty_query.json",
            "golden/retrieval/file_proximity.json",
            "golden/retrieval/reranking.json",
        ];
        for f in &files {
            assert!(fixture_exists(f), "Missing fixture: {}", f);
        }
    }

    #[test]
    fn all_golden_contradiction_files_exist() {
        let files = [
            "golden/contradiction/direct_conflict.json",
            "golden/contradiction/partial_conflict.json",
            "golden/contradiction/temporal_supersession.json",
            "golden/contradiction/consensus_resistance.json",
            "golden/contradiction/propagation_chain.json",
        ];
        for f in &files {
            assert!(fixture_exists(f), "Missing fixture: {}", f);
        }
    }

    #[test]
    fn all_golden_causal_files_exist() {
        let files = [
            "golden/causal/simple_chain.json",
            "golden/causal/branching.json",
            "golden/causal/cycle_rejection.json",
            "golden/causal/counterfactual.json",
            "golden/causal/narrative_output.json",
        ];
        for f in &files {
            assert!(fixture_exists(f), "Missing fixture: {}", f);
        }
    }

    #[test]
    fn all_golden_privacy_files_exist() {
        let files = [
            "golden/privacy/pii_samples.json",
            "golden/privacy/secret_samples.json",
            "golden/privacy/false_positives.json",
            "golden/privacy/idempotency.json",
        ];
        for f in &files {
            assert!(fixture_exists(f), "Missing fixture: {}", f);
        }
    }

    #[test]
    fn all_golden_multiagent_files_exist() {
        let files = [
            "golden/multiagent/crdt_merge_simple.json",
            "golden/multiagent/crdt_merge_conflict.json",
            "golden/multiagent/crdt_merge_confidence.json",
            "golden/multiagent/namespace_permissions.json",
            "golden/multiagent/namespace_default_compat.json",
            "golden/multiagent/provenance_chain.json",
            "golden/multiagent/provenance_correction.json",
            "golden/multiagent/trust_scoring.json",
            "golden/multiagent/trust_decay.json",
            "golden/multiagent/consensus_detection.json",
        ];
        for f in &files {
            assert!(fixture_exists(f), "Missing fixture: {}", f);
        }
    }

    #[test]
    fn all_benchmark_files_exist() {
        let files = [
            "benchmarks/memories_100.json",
            "benchmarks/memories_1k.json",
            "benchmarks/memories_10k.json",
            "benchmarks/embeddings_1024dim.bin",
            "benchmarks/queries_50.json",
            "benchmarks/causal_graph_1k_edges.json",
        ];
        for f in &files {
            assert!(fixture_exists(f), "Missing fixture: {}", f);
        }
    }

    #[test]
    fn all_integration_files_exist() {
        let files = [
            "integration/full_lifecycle.json",
            "integration/concurrent_access.json",
            "integration/embedding_migration.json",
            "integration/degradation_scenarios.json",
        ];
        for f in &files {
            assert!(fixture_exists(f), "Missing fixture: {}", f);
        }
    }

    #[test]
    fn all_44_golden_files_parse_as_json() {
        let dirs = [
            "golden/consolidation",
            "golden/retrieval",
            "golden/contradiction",
            "golden/causal",
            "golden/privacy",
            "golden/multiagent",
        ];
        let mut total = 0;
        for dir in &dirs {
            let files = list_fixtures(dir);
            for file in &files {
                let content = std::fs::read_to_string(file)
                    .unwrap_or_else(|e| panic!("Failed to read {}: {}", file.display(), e));
                let _: serde_json::Value = serde_json::from_str(&content)
                    .unwrap_or_else(|e| panic!("Failed to parse {}: {}", file.display(), e));
                total += 1;
            }
        }
        assert_eq!(
            total, 44,
            "Expected 44 golden dataset files, found {}",
            total
        );
    }

    #[test]
    fn embeddings_binary_loads_correctly() {
        let (count, dims, vectors) = load_embeddings_binary("benchmarks/embeddings_1024dim.bin");
        assert_eq!(count, 100);
        assert_eq!(dims, 1024);
        assert_eq!(vectors.len(), 100);
        // Verify vectors are normalized (L2 norm ≈ 1.0).
        for (i, vec) in vectors.iter().enumerate() {
            assert_eq!(vec.len(), 1024);
            let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
            assert!(
                (norm - 1.0).abs() < 0.01,
                "Vector {} not normalized: norm = {}",
                i,
                norm
            );
        }
    }

    #[test]
    fn benchmark_memories_have_correct_counts() {
        let m100: serde_json::Value = load_fixture("benchmarks/memories_100.json");
        assert_eq!(m100["count"], 100);
        assert_eq!(m100["memories"].as_array().unwrap().len(), 100);

        let m1k: serde_json::Value = load_fixture("benchmarks/memories_1k.json");
        assert_eq!(m1k["count"], 1000);
        assert_eq!(m1k["memories"].as_array().unwrap().len(), 1000);

        let m10k: serde_json::Value = load_fixture("benchmarks/memories_10k.json");
        assert_eq!(m10k["count"], 10000);
        assert_eq!(m10k["memories"].as_array().unwrap().len(), 10000);
    }

    #[test]
    fn benchmark_queries_have_50_entries() {
        let queries: serde_json::Value = load_fixture("benchmarks/queries_50.json");
        assert_eq!(queries["queries"].as_array().unwrap().len(), 50);
    }

    #[test]
    fn causal_graph_has_1k_edges() {
        let graph: serde_json::Value = load_fixture("benchmarks/causal_graph_1k_edges.json");
        assert_eq!(graph["edge_count"], 1000);
        assert_eq!(graph["edges"].as_array().unwrap().len(), 1000);
    }
}

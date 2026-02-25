//! Phase 3-4: Jaccard similarity + MinHash LSH for near-duplicate detection.
//!
//! Exact Jaccard for small pattern sets, MinHash LSH for n > 50K.

use drift_core::types::collections::{FxHashMap, FxHashSet};

use super::types::{AggregatedPattern, MergeCandidate, MergeDecision};

/// Compute exact Jaccard similarity between two sets of location keys.
///
/// J(A, B) = |A ∩ B| / |A ∪ B|
/// Returns 0.0 if both sets are empty.
pub fn jaccard_similarity(set_a: &FxHashSet<String>, set_b: &FxHashSet<String>) -> f64 {
    if set_a.is_empty() && set_b.is_empty() {
        return 0.0;
    }
    let intersection = set_a.intersection(set_b).count();
    let union = set_a.union(set_b).count();
    if union == 0 {
        return 0.0;
    }
    intersection as f64 / union as f64
}

/// Extract the location key set from an aggregated pattern (file:line).
pub fn location_key_set(pattern: &AggregatedPattern) -> FxHashSet<String> {
    pattern
        .locations
        .iter()
        .map(|loc| format!("{}:{}", loc.file, loc.line))
        .collect()
}

/// Find near-duplicate pattern pairs using exact Jaccard similarity.
///
/// O(n²) pairwise comparison — suitable for n < 50K patterns.
/// For larger sets, use MinHashIndex.
pub fn find_duplicates(
    patterns: &[&AggregatedPattern],
    flag_threshold: f64,
    auto_merge_threshold: f64,
) -> Vec<MergeCandidate> {
    let n = patterns.len();
    let mut candidates = Vec::new();

    // Pre-compute location key sets
    let key_sets: Vec<FxHashSet<String>> = patterns.iter().map(|p| location_key_set(p)).collect();

    // Pairwise comparison (same category only)
    for i in 0..n {
        for j in (i + 1)..n {
            // Only compare within same category
            if patterns[i].category != patterns[j].category {
                continue;
            }

            let sim = jaccard_similarity(&key_sets[i], &key_sets[j]);
            if sim >= flag_threshold {
                let decision = if sim >= auto_merge_threshold {
                    MergeDecision::AutoMerge
                } else {
                    MergeDecision::FlagReview
                };
                candidates.push(MergeCandidate {
                    pattern_a: patterns[i].pattern_id.clone(),
                    pattern_b: patterns[j].pattern_id.clone(),
                    similarity: sim,
                    decision,
                });
            }
        }
    }

    candidates
}

/// MinHash LSH index for approximate near-duplicate detection at scale (n > 50K).
///
/// Uses random hash permutations to create compact signatures, then LSH banding
/// to find candidate pairs in O(n) expected time.
pub struct MinHashIndex {
    num_perm: usize,
    num_bands: usize,
    rows_per_band: usize,
    /// Signatures: pattern_id → MinHash signature vector.
    signatures: FxHashMap<String, Vec<u64>>,
    /// LSH buckets: (band_index, bucket_hash) → list of pattern_ids.
    buckets: FxHashMap<(usize, u64), Vec<String>>,
}

impl MinHashIndex {
    /// Create a new MinHash LSH index.
    ///
    /// `num_perm`: number of hash permutations (higher = more accurate, default 128).
    /// `num_bands`: number of LSH bands (default 32, with 128 perms → 4 rows per band).
    pub fn new(num_perm: usize, num_bands: usize) -> Self {
        assert!(num_perm > 0 && num_bands > 0);
        assert!(
            num_perm % num_bands == 0,
            "num_perm must be divisible by num_bands"
        );
        Self {
            num_perm,
            num_bands,
            rows_per_band: num_perm / num_bands,
            signatures: FxHashMap::default(),
            buckets: FxHashMap::default(),
        }
    }

    /// Compute MinHash signature for a set of string elements.
    ///
    /// Uses universal hashing: h_i(x) = (a_i * x + b_i) mod p
    /// where a_i, b_i are deterministic per-permutation coefficients derived
    /// from a seeded PRNG, and p is a large prime.
    fn compute_signature(&self, elements: &FxHashSet<String>) -> Vec<u64> {
        let mut signature = vec![u64::MAX; self.num_perm];

        // Large Mersenne prime for universal hashing
        const PRIME: u64 = (1u64 << 61) - 1;

        for element in elements {
            let base_hash = xxhash_rust::xxh3::xxh3_64(element.as_bytes());
            for (i, sig_val) in signature.iter_mut().enumerate() {
                // Deterministic per-permutation coefficients via mixing
                let seed = i as u64;
                let a = seed.wrapping_mul(0x517cc1b727220a95).wrapping_add(0x6c62272e07bb0142) | 1;
                let b = seed.wrapping_mul(0x6c62272e07bb0142).wrapping_add(0x517cc1b727220a95);
                // Universal hash: (a * x + b) mod p
                let perm_hash = (a.wrapping_mul(base_hash).wrapping_add(b)) % PRIME;
                *sig_val = (*sig_val).min(perm_hash);
            }
        }

        signature
    }

    /// Hash a band (sub-signature) to a bucket key.
    fn band_hash(&self, signature: &[u64], band: usize) -> u64 {
        let start = band * self.rows_per_band;
        let end = start + self.rows_per_band;
        let mut hash = 0u64;
        for &val in &signature[start..end] {
            hash = hash.wrapping_mul(31).wrapping_add(val);
        }
        hash
    }

    /// Insert a pattern into the index.
    pub fn insert(&mut self, pattern_id: &str, elements: &FxHashSet<String>) {
        let sig = self.compute_signature(elements);

        // Insert into LSH buckets
        for band in 0..self.num_bands {
            let bucket_key = self.band_hash(&sig, band);
            self.buckets
                .entry((band, bucket_key))
                .or_default()
                .push(pattern_id.to_string());
        }

        self.signatures.insert(pattern_id.to_string(), sig);
    }

    /// Find candidate pairs that are likely near-duplicates.
    ///
    /// Returns pairs of pattern_ids that share at least one LSH bucket.
    pub fn find_candidates(&self) -> Vec<(String, String)> {
        let mut seen_pairs = FxHashSet::default();
        let mut candidates = Vec::new();

        for members in self.buckets.values() {
            if members.len() < 2 {
                continue;
            }
            for i in 0..members.len() {
                for j in (i + 1)..members.len() {
                    let (a, b) = if members[i] < members[j] {
                        (&members[i], &members[j])
                    } else {
                        (&members[j], &members[i])
                    };
                    let pair_key = format!("{}|{}", a, b);
                    if seen_pairs.insert(pair_key) {
                        candidates.push((a.clone(), b.clone()));
                    }
                }
            }
        }

        candidates
    }

    /// Estimate Jaccard similarity from MinHash signatures.
    pub fn estimate_similarity(&self, id_a: &str, id_b: &str) -> Option<f64> {
        let sig_a = self.signatures.get(id_a)?;
        let sig_b = self.signatures.get(id_b)?;

        let matching = sig_a
            .iter()
            .zip(sig_b.iter())
            .filter(|(a, b)| a == b)
            .count();

        Some(matching as f64 / self.num_perm as f64)
    }

    /// Number of indexed patterns.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jaccard_identical_sets() {
        let mut a = FxHashSet::default();
        a.insert("a:1".to_string());
        a.insert("b:2".to_string());
        let sim = jaccard_similarity(&a, &a);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_jaccard_disjoint_sets() {
        let mut a = FxHashSet::default();
        a.insert("a:1".to_string());
        let mut b = FxHashSet::default();
        b.insert("b:2".to_string());
        let sim = jaccard_similarity(&a, &b);
        assert!((sim - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_jaccard_empty_sets() {
        let a = FxHashSet::default();
        let b = FxHashSet::default();
        assert_eq!(jaccard_similarity(&a, &b), 0.0);
    }

    #[test]
    fn test_jaccard_partial_overlap() {
        let mut a = FxHashSet::default();
        a.insert("x:1".to_string());
        a.insert("x:2".to_string());
        a.insert("x:3".to_string());
        let mut b = FxHashSet::default();
        b.insert("x:1".to_string());
        b.insert("x:2".to_string());
        b.insert("x:4".to_string());
        // intersection = 2, union = 4
        let sim = jaccard_similarity(&a, &b);
        assert!((sim - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_minhash_accuracy_50_percent_overlap() {
        // Two sets with 50% Jaccard overlap: 50 shared, 25 unique each
        // True Jaccard = 50 / 100 = 0.5
        let mut set_a = FxHashSet::default();
        let mut set_b = FxHashSet::default();

        // 50 shared elements
        for i in 0..50 {
            let key = format!("shared:{}", i);
            set_a.insert(key.clone());
            set_b.insert(key);
        }
        // 25 unique to A
        for i in 0..25 {
            set_a.insert(format!("only_a:{}", i));
        }
        // 25 unique to B
        for i in 0..25 {
            set_b.insert(format!("only_b:{}", i));
        }

        let true_jaccard = jaccard_similarity(&set_a, &set_b);
        assert!((true_jaccard - 0.5).abs() < 1e-10, "True Jaccard should be 0.5");

        let mut index = MinHashIndex::new(128, 32);
        index.insert("a", &set_a);
        index.insert("b", &set_b);

        let estimate = index.estimate_similarity("a", "b").unwrap();
        assert!(
            (estimate - 0.5).abs() < 0.10,
            "MinHash estimate ({:.4}) should be within 10% of true Jaccard (0.5)",
            estimate
        );
    }

    #[test]
    fn test_minhash_accuracy_90_percent_overlap() {
        // Two sets with ~90% Jaccard overlap: 90 shared, 5 unique each
        // True Jaccard = 90 / 100 = 0.9
        let mut set_a = FxHashSet::default();
        let mut set_b = FxHashSet::default();

        for i in 0..90 {
            let key = format!("shared:{}", i);
            set_a.insert(key.clone());
            set_b.insert(key);
        }
        for i in 0..5 {
            set_a.insert(format!("only_a:{}", i));
        }
        for i in 0..5 {
            set_b.insert(format!("only_b:{}", i));
        }

        let true_jaccard = jaccard_similarity(&set_a, &set_b);
        assert!((true_jaccard - 0.9).abs() < 0.01);

        let mut index = MinHashIndex::new(128, 32);
        index.insert("a", &set_a);
        index.insert("b", &set_b);

        let estimate = index.estimate_similarity("a", "b").unwrap();
        assert!(
            (estimate - 0.9).abs() < 0.05,
            "MinHash estimate ({:.4}) should be within 5% of true Jaccard (0.9)",
            estimate
        );
    }
}

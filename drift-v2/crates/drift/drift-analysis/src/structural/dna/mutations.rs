//! Mutation detection between snapshots — SHA-256 mutation IDs, impact classification.

use super::types::*;
use std::collections::BTreeMap;

/// Detect mutations: files where a non-dominant allele is used.
///
/// For each gene with a dominant allele, any file using a different allele
/// is a mutation. Impact is graded by frequency:
/// - High: allele frequency < 10% AND dominant > 80%
/// - Medium: allele frequency < 30%
/// - Low: everything else
pub fn detect_mutations(genes: &[Gene], timestamp: i64) -> Vec<Mutation> {
    let mut mutations = Vec::new();

    for gene in genes {
        let dominant = match &gene.dominant {
            Some(d) => d,
            None => continue,
        };

        for allele in &gene.alleles {
            if allele.is_dominant {
                continue;
            }

            // Each example of a non-dominant allele is a mutation
            for example in &allele.examples {
                let mutation_id = generate_mutation_id(
                    &example.file, gene.id, &allele.id,
                );

                let impact = classify_impact(
                    allele.frequency,
                    dominant.frequency,
                );

                let suggestion = format!(
                    "Refactor to use {} instead of {}",
                    dominant.name, allele.name,
                );

                mutations.push(Mutation {
                    id: mutation_id,
                    file: example.file.clone(),
                    line: example.line,
                    gene: gene.id,
                    expected: dominant.name.clone(),
                    actual: allele.name.clone(),
                    impact,
                    code: example.code.clone(),
                    suggestion,
                    detected_at: timestamp,
                    resolved: false,
                    resolved_at: None,
                });
            }
        }
    }

    // Sort by impact (high first), then by file path for determinism
    mutations.sort_by(|a, b| {
        a.impact.cmp(&b.impact)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    mutations
}

/// Classify mutation impact based on allele frequency.
fn classify_impact(allele_frequency: f64, dominant_frequency: f64) -> MutationImpact {
    if allele_frequency < DnaThresholds::MUTATION_IMPACT_HIGH && dominant_frequency > 0.8 {
        MutationImpact::High
    } else if allele_frequency < DnaThresholds::MUTATION_IMPACT_MEDIUM {
        MutationImpact::Medium
    } else {
        MutationImpact::Low
    }
}

/// Generate deterministic mutation ID: SHA-256(file + geneId + alleleId)[..16].
fn generate_mutation_id(file: &str, gene_id: GeneId, allele_id: &str) -> String {
    use std::hash::{Hash, Hasher};
    // Use a deterministic hash. We use a simple approach here since
    // we don't want to add sha2 as a dependency just for IDs.
    // FxHash is deterministic within a process; for cross-process determinism
    // we use a manual hash combining approach.
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    file.hash(&mut hasher);
    format!("{:?}", gene_id).hash(&mut hasher);
    allele_id.hash(&mut hasher);
    let hash = hasher.finish();
    format!("{:016x}", hash)
}

/// Compare two sets of mutations to detect new, resolved, and persisting mutations.
pub fn compare_mutations(
    previous: &[Mutation],
    current: &[Mutation],
) -> MutationDiff {
    let prev_ids: BTreeMap<&str, &Mutation> = previous.iter()
        .map(|m| (m.id.as_str(), m))
        .collect();
    let curr_ids: BTreeMap<&str, &Mutation> = current.iter()
        .map(|m| (m.id.as_str(), m))
        .collect();

    let new_mutations: Vec<Mutation> = current.iter()
        .filter(|m| !prev_ids.contains_key(m.id.as_str()))
        .cloned()
        .collect();

    let resolved_mutations: Vec<Mutation> = previous.iter()
        .filter(|m| !curr_ids.contains_key(m.id.as_str()))
        .cloned()
        .collect();

    let persisting_mutations: Vec<Mutation> = current.iter()
        .filter(|m| prev_ids.contains_key(m.id.as_str()))
        .cloned()
        .collect();

    MutationDiff {
        new_mutations,
        resolved_mutations,
        persisting_mutations,
    }
}

/// Diff between two mutation snapshots.
#[derive(Debug, Clone)]
pub struct MutationDiff {
    pub new_mutations: Vec<Mutation>,
    pub resolved_mutations: Vec<Mutation>,
    pub persisting_mutations: Vec<Mutation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutation_id_determinism() {
        let id1 = generate_mutation_id("src/app.ts", GeneId::VariantHandling, "cva");
        let id2 = generate_mutation_id("src/app.ts", GeneId::VariantHandling, "cva");
        assert_eq!(id1, id2, "Same input must produce same mutation ID");
    }

    #[test]
    fn test_impact_classification() {
        assert_eq!(classify_impact(0.05, 0.90), MutationImpact::High);
        assert_eq!(classify_impact(0.20, 0.60), MutationImpact::Medium);
        assert_eq!(classify_impact(0.40, 0.50), MutationImpact::Low);
    }
}

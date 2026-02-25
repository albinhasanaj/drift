//! Health scoring: consistency(40%) + confidence(30%) + mutations(20%) + coverage(10%).
//! Clamped to [0, 100].

use super::types::*;

/// Calculate DNA health score from genes and mutations.
///
/// Formula: `healthScore = consistency(40%) + confidence(30%) + mutations(20%) + coverage(10%)`
/// Result clamped to [0, 100] and rounded.
pub fn calculate_health_score(genes: &[Gene], mutations: &[Mutation]) -> DnaHealthScore {
    if genes.is_empty() {
        return DnaHealthScore {
            overall: 0.0,
            consistency: 0.0,
            confidence: 0.0,
            mutation_score: 1.0,
            coverage: 0.0,
        };
    }

    // Consistency = average consistency across all genes
    let consistency = genes.iter()
        .map(|g| g.consistency)
        .sum::<f64>() / genes.len() as f64;

    // Confidence = average dominant allele frequency
    let confidence = genes.iter()
        .map(|g| g.confidence)
        .sum::<f64>() / genes.len() as f64;

    // Mutation penalty: (1 - penalty) scaled by mutation count relative to gene count
    let mutation_ratio = if genes.is_empty() {
        0.0
    } else {
        mutations.len() as f64 / genes.len().max(1) as f64
    };
    // Cap the penalty at 1.0 (100% penalty when mutations >= genes)
    let mutation_penalty = mutation_ratio.min(1.0);
    let mutation_score = 1.0 - mutation_penalty;

    // Dominant coverage = proportion of genes with a dominant allele
    let genes_with_dominant = genes.iter()
        .filter(|g| g.dominant.is_some())
        .count() as f64;
    let coverage = genes_with_dominant / genes.len() as f64;

    // Weighted composite
    let overall = (
        consistency * 0.40
        + confidence * 0.30
        + mutation_score * 0.20
        + coverage * 0.10
    ) * 100.0;

    DnaHealthScore {
        overall: overall.clamp(0.0, 100.0).round(),
        consistency,
        confidence,
        mutation_score,
        coverage,
    }
}

/// Calculate genetic diversity — normalized allele count across all genes.
pub fn calculate_genetic_diversity(genes: &[Gene]) -> f64 {
    if genes.is_empty() {
        return 0.0;
    }

    let total_alleles: usize = genes.iter()
        .map(|g| g.alleles.len())
        .sum();

    // Normalize: diversity = total_alleles / (genes * max_expected_alleles)
    // max_expected_alleles = 5 (reasonable upper bound per gene)
    let max_expected = genes.len() as f64 * 5.0;
    if max_expected == 0.0 {
        return 0.0;
    }

    (total_alleles as f64 / max_expected).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gene(consistency: f64, confidence: f64, has_dominant: bool, allele_count: usize) -> Gene {
        let alleles: Vec<Allele> = (0..allele_count).map(|i| Allele {
            id: format!("allele-{}", i),
            name: format!("Allele {}", i),
            description: String::new(),
            frequency: if i == 0 { confidence } else { (1.0 - confidence) / (allele_count - 1).max(1) as f64 },
            file_count: 5,
            pattern: String::new(),
            examples: Vec::new(),
            is_dominant: i == 0 && has_dominant,
        }).collect();

        Gene {
            id: GeneId::VariantHandling,
            name: "Test Gene".into(),
            description: String::new(),
            dominant: if has_dominant { alleles.first().cloned() } else { None },
            alleles,
            confidence,
            consistency,
            exemplars: Vec::new(),
        }
    }

    #[test]
    fn test_health_score_perfect() {
        let genes = vec![
            make_gene(1.0, 1.0, true, 1),
            make_gene(1.0, 1.0, true, 1),
        ];
        let score = calculate_health_score(&genes, &[]);
        assert!((score.overall - 100.0).abs() < 1.0);
    }

    #[test]
    fn test_health_score_empty() {
        let score = calculate_health_score(&[], &[]);
        assert_eq!(score.overall, 0.0);
    }

    #[test]
    fn test_health_score_with_mutations() {
        let genes = vec![make_gene(0.8, 0.8, true, 2)];
        let mutations = vec![Mutation {
            id: "m1".into(), file: "test.ts".into(), line: 1,
            gene: GeneId::VariantHandling, expected: "a".into(),
            actual: "b".into(), impact: MutationImpact::High,
            code: String::new(), suggestion: String::new(),
            detected_at: 0, resolved: false, resolved_at: None,
        }];
        let score = calculate_health_score(&genes, &mutations);
        // With 1 mutation and 1 gene, mutation_score = 0.0
        assert!(score.overall < 80.0);
    }

    #[test]
    fn test_health_score_clamped() {
        let genes = vec![make_gene(0.5, 0.5, true, 3)];
        let score = calculate_health_score(&genes, &[]);
        assert!(score.overall >= 0.0 && score.overall <= 100.0);
    }

    #[test]
    fn test_genetic_diversity() {
        let genes = vec![
            make_gene(0.8, 0.8, true, 3),
            make_gene(0.7, 0.7, true, 4),
        ];
        let diversity = calculate_genetic_diversity(&genes);
        // 7 alleles / (2 * 5) = 0.7
        assert!((diversity - 0.7).abs() < 0.01);
    }
}

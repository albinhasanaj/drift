#![allow(clippy::cloned_ref_to_slice_refs)]
//! Production stress tests for the DNA module.
//! Targets: health score boundaries, mutation edge cases, diversity, determinism.

use drift_analysis::structural::dna::types::*;
use drift_analysis::structural::dna::health::{calculate_health_score, calculate_genetic_diversity};
use drift_analysis::structural::dna::mutations::{compare_mutations, detect_mutations};

// ─── Helpers ────────────────────────────────────────────────────────

fn gene(
    id: GeneId,
    consistency: f64,
    confidence: f64,
    has_dominant: bool,
    allele_count: usize,
) -> Gene {
    let alleles: Vec<Allele> = (0..allele_count)
        .map(|i| Allele {
            id: format!("allele-{}", i),
            name: format!("Allele {}", i),
            description: String::new(),
            frequency: if i == 0 {
                confidence
            } else {
                (1.0 - confidence) / (allele_count - 1).max(1) as f64
            },
            file_count: 5,
            pattern: String::new(),
            examples: if i > 0 && has_dominant {
                vec![AlleleExample {
                    file: format!("src/file_{}.ts", i),
                    line: i as u32 * 10,
                    code: format!("allele {} usage", i),
                    context: String::new(),
                }]
            } else {
                vec![]
            },
            is_dominant: i == 0 && has_dominant,
        })
        .collect();

    Gene {
        id,
        name: id.name().into(),
        description: String::new(),
        dominant: if has_dominant {
            alleles.first().cloned()
        } else {
            None
        },
        alleles,
        confidence,
        consistency,
        exemplars: Vec::new(),
    }
}

fn mutation(id: &str, gene_id: GeneId, impact: MutationImpact) -> Mutation {
    Mutation {
        id: id.into(),
        file: "test.ts".into(),
        line: 1,
        gene: gene_id,
        expected: "dominant".into(),
        actual: "deviant".into(),
        impact,
        code: String::new(),
        suggestion: String::new(),
        detected_at: 1000,
        resolved: false,
        resolved_at: None,
    }
}

// ─── Health score stress ────────────────────────────────────────────

#[test]
fn stress_health_empty_genes() {
    let s = calculate_health_score(&[], &[]);
    assert_eq!(s.overall, 0.0);
    assert_eq!(s.consistency, 0.0);
    assert_eq!(s.confidence, 0.0);
    assert_eq!(s.mutation_score, 1.0); // no mutations = perfect
    assert_eq!(s.coverage, 0.0);
}

#[test]
fn stress_health_perfect_score() {
    let genes = vec![
        gene(GeneId::VariantHandling, 1.0, 1.0, true, 1),
        gene(GeneId::ResponsiveApproach, 1.0, 1.0, true, 1),
    ];
    let s = calculate_health_score(&genes, &[]);
    assert!(
        (s.overall - 100.0).abs() < 1.0,
        "Perfect genes should yield ~100, got {}",
        s.overall
    );
}

#[test]
fn stress_health_zero_consistency_zero_confidence() {
    let genes = vec![gene(GeneId::VariantHandling, 0.0, 0.0, true, 1)];
    let s = calculate_health_score(&genes, &[]);
    // consistency=0, confidence=0, mutation_score=1.0, coverage=1.0
    // overall = (0*0.4 + 0*0.3 + 1.0*0.2 + 1.0*0.1) * 100 = 30
    assert!(
        (s.overall - 30.0).abs() < 1.0,
        "Expected ~30, got {}",
        s.overall
    );
}

#[test]
fn stress_health_no_dominant_alleles() {
    let genes = vec![
        gene(GeneId::VariantHandling, 0.5, 0.5, false, 3),
        gene(GeneId::Theming, 0.5, 0.5, false, 2),
    ];
    let s = calculate_health_score(&genes, &[]);
    assert_eq!(s.coverage, 0.0, "No dominant alleles → coverage = 0");
    assert!(s.overall >= 0.0 && s.overall <= 100.0);
}

#[test]
fn stress_health_mutations_equal_genes_zeroes_mutation_score() {
    let genes = vec![gene(GeneId::VariantHandling, 0.8, 0.8, true, 2)];
    let mutations = vec![mutation("m1", GeneId::VariantHandling, MutationImpact::High)];
    let s = calculate_health_score(&genes, &mutations);
    assert!(
        (s.mutation_score - 0.0).abs() < f64::EPSILON,
        "1 mutation / 1 gene → mutation_score = 0, got {}",
        s.mutation_score
    );
}

#[test]
fn stress_health_mutations_exceed_genes() {
    let genes = vec![gene(GeneId::VariantHandling, 0.8, 0.8, true, 2)];
    let mutations: Vec<Mutation> = (0..100)
        .map(|i| mutation(&format!("m{}", i), GeneId::VariantHandling, MutationImpact::High))
        .collect();
    let s = calculate_health_score(&genes, &mutations);
    // mutation_ratio = 100/1 = 100, capped at 1.0 → mutation_score = 0
    assert!(
        (s.mutation_score - 0.0).abs() < f64::EPSILON,
        "Excess mutations should cap penalty at 1.0"
    );
    assert!(s.overall >= 0.0);
}

#[test]
fn stress_health_all_10_genes() {
    let genes: Vec<Gene> = GeneId::ALL
        .iter()
        .map(|id| gene(*id, 0.7, 0.6, true, 3))
        .collect();
    let s = calculate_health_score(&genes, &[]);
    assert!(s.overall >= 0.0 && s.overall <= 100.0);
    assert_eq!(s.coverage, 1.0, "All genes have dominant → coverage = 1.0");
}

#[test]
fn stress_health_score_always_clamped() {
    // Extreme values that could push score out of bounds
    let genes = vec![gene(GeneId::VariantHandling, 999.0, 999.0, true, 1)];
    let s = calculate_health_score(&genes, &[]);
    assert!(
        s.overall >= 0.0 && s.overall <= 100.0,
        "Score must be clamped to [0,100], got {}",
        s.overall
    );
}

// ─── Mutation detection stress ──────────────────────────────────────

#[test]
fn stress_detect_mutations_no_dominant() {
    let genes = vec![gene(GeneId::VariantHandling, 0.5, 0.5, false, 3)];
    let mutations = detect_mutations(&genes, 1000);
    assert!(
        mutations.is_empty(),
        "No dominant allele → no mutations should be detected"
    );
}

#[test]
fn stress_detect_mutations_single_allele_no_mutations() {
    let genes = vec![gene(GeneId::VariantHandling, 1.0, 1.0, true, 1)];
    let mutations = detect_mutations(&genes, 1000);
    assert!(
        mutations.is_empty(),
        "Single dominant allele → no mutations"
    );
}

#[test]
fn stress_detect_mutations_with_examples() {
    let genes = vec![gene(GeneId::VariantHandling, 0.8, 0.8, true, 3)];
    let mutations = detect_mutations(&genes, 1000);
    // Non-dominant alleles with examples should produce mutations
    for m in &mutations {
        assert!(!m.id.is_empty(), "Mutation ID should not be empty");
        assert!(!m.suggestion.is_empty(), "Suggestion should not be empty");
        assert_eq!(m.detected_at, 1000);
        assert!(!m.resolved);
    }
}

#[test]
fn stress_detect_mutations_impact_classification() {
    // Build a gene where non-dominant allele has very low frequency
    let mut g = gene(GeneId::VariantHandling, 0.95, 0.95, true, 2);
    g.alleles[1].frequency = 0.05; // < 0.1 AND dominant > 0.8 → High
    g.alleles[1].examples = vec![AlleleExample {
        file: "src/x.ts".into(),
        line: 1,
        code: "code".into(),
        context: String::new(),
    }];
    let mutations = detect_mutations(&[g], 1000);
    assert!(
        mutations.iter().all(|m| m.impact == MutationImpact::High),
        "Low-frequency allele with high dominant should be High impact"
    );
}

#[test]
fn stress_detect_mutations_sorted_by_impact_then_file() {
    let mut g = gene(GeneId::VariantHandling, 0.9, 0.9, true, 3);
    g.alleles[1].frequency = 0.05;
    g.alleles[1].examples = vec![AlleleExample {
        file: "z.ts".into(),
        line: 1,
        code: "".into(),
        context: String::new(),
    }];
    g.alleles[2].frequency = 0.25;
    g.alleles[2].examples = vec![AlleleExample {
        file: "a.ts".into(),
        line: 1,
        code: "".into(),
        context: String::new(),
    }];
    let mutations = detect_mutations(&[g], 1000);
    // Should be sorted: High before Medium, then by file
    for window in mutations.windows(2) {
        assert!(
            window[0].impact <= window[1].impact
                || (window[0].impact == window[1].impact && window[0].file <= window[1].file),
            "Mutations not sorted correctly"
        );
    }
}

// ─── Mutation comparison stress ─────────────────────────────────────

#[test]
fn stress_compare_mutations_empty_both() {
    let diff = compare_mutations(&[], &[]);
    assert!(diff.new_mutations.is_empty());
    assert!(diff.resolved_mutations.is_empty());
    assert!(diff.persisting_mutations.is_empty());
}

#[test]
fn stress_compare_mutations_all_new() {
    let current = vec![mutation("m1", GeneId::VariantHandling, MutationImpact::High)];
    let diff = compare_mutations(&[], &current);
    assert_eq!(diff.new_mutations.len(), 1);
    assert!(diff.resolved_mutations.is_empty());
    assert!(diff.persisting_mutations.is_empty());
}

#[test]
fn stress_compare_mutations_all_resolved() {
    let previous = vec![mutation("m1", GeneId::VariantHandling, MutationImpact::High)];
    let diff = compare_mutations(&previous, &[]);
    assert!(diff.new_mutations.is_empty());
    assert_eq!(diff.resolved_mutations.len(), 1);
    assert!(diff.persisting_mutations.is_empty());
}

#[test]
fn stress_compare_mutations_persisting() {
    let m = mutation("m1", GeneId::VariantHandling, MutationImpact::High);
    let diff = compare_mutations(&[m.clone()], &[m]);
    assert!(diff.new_mutations.is_empty());
    assert!(diff.resolved_mutations.is_empty());
    assert_eq!(diff.persisting_mutations.len(), 1);
}

// ─── Genetic diversity stress ───────────────────────────────────────

#[test]
fn stress_diversity_empty() {
    assert_eq!(calculate_genetic_diversity(&[]), 0.0);
}

#[test]
fn stress_diversity_single_allele_per_gene() {
    let genes = vec![
        gene(GeneId::VariantHandling, 1.0, 1.0, true, 1),
        gene(GeneId::Theming, 1.0, 1.0, true, 1),
    ];
    let d = calculate_genetic_diversity(&genes);
    // 2 alleles / (2 * 5) = 0.2
    assert!((d - 0.2).abs() < 0.01, "Expected 0.2, got {}", d);
}

#[test]
fn stress_diversity_max_alleles() {
    let genes = vec![gene(GeneId::VariantHandling, 0.3, 0.3, true, 10)];
    let d = calculate_genetic_diversity(&genes);
    // 10 alleles / (1 * 5) = 2.0, clamped to 1.0
    assert!(
        (d - 1.0).abs() < 0.01,
        "Diversity should clamp to 1.0, got {}",
        d
    );
}

// ─── GeneId stress ──────────────────────────────────────────────────

#[test]
fn stress_gene_id_frontend_backend_disjoint() {
    for f in GeneId::FRONTEND {
        assert!(
            !GeneId::BACKEND.contains(f),
            "{:?} is in both FRONTEND and BACKEND",
            f
        );
    }
}

#[test]
fn stress_gene_id_all_covers_everything() {
    assert_eq!(
        GeneId::ALL.len(),
        GeneId::FRONTEND.len() + GeneId::BACKEND.len()
    );
}

#[test]
fn stress_gene_id_names_unique() {
    let names: Vec<&str> = GeneId::ALL.iter().map(|g| g.name()).collect();
    let unique: std::collections::HashSet<&&str> = names.iter().collect();
    assert_eq!(names.len(), unique.len());
}

#[test]
fn stress_gene_id_descriptions_nonempty() {
    for g in GeneId::ALL {
        assert!(!g.description().is_empty(), "{:?} has empty description", g);
    }
}

// ─── MutationImpact ordering ────────────────────────────────────────

#[test]
fn stress_mutation_impact_ordering() {
    assert!(MutationImpact::High < MutationImpact::Medium);
    assert!(MutationImpact::Medium < MutationImpact::Low);
}

// ─── DnaThresholds ──────────────────────────────────────────────────

#[test]
fn stress_thresholds_values() {
    assert!((DnaThresholds::DOMINANT_MIN_FREQUENCY - 0.6).abs() < f64::EPSILON);
    assert!((DnaThresholds::MUTATION_IMPACT_HIGH - 0.1).abs() < f64::EPSILON);
    assert!((DnaThresholds::MUTATION_IMPACT_MEDIUM - 0.3).abs() < f64::EPSILON);
    assert!((DnaThresholds::HEALTH_SCORE_WARNING - 70.0).abs() < f64::EPSILON);
    assert!((DnaThresholds::HEALTH_SCORE_CRITICAL - 50.0).abs() < f64::EPSILON);
}

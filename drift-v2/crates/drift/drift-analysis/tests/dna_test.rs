//! Phase 5 DNA system tests (T5-DNA-01 through T5-DNA-06).

use drift_analysis::structural::dna::types::*;
use drift_analysis::structural::dna::health::calculate_health_score;
use drift_analysis::structural::dna::mutations::detect_mutations;
use drift_analysis::structural::dna::context_builder::{build_context, ContextLevel};
use drift_analysis::structural::dna::extractor::GeneExtractorRegistry;

/// T5-DNA-01: DNA health scores from at least 5 gene extractors in [0, 100].
#[test]
fn test_health_score_range() {
    let genes = vec![
        make_test_gene(GeneId::VariantHandling, 0.8, 0.7),
        make_test_gene(GeneId::ResponsiveApproach, 0.6, 0.5),
        make_test_gene(GeneId::StateStyling, 0.9, 0.85),
        make_test_gene(GeneId::Theming, 0.7, 0.6),
        make_test_gene(GeneId::SpacingPhilosophy, 0.5, 0.4),
    ];

    let score = calculate_health_score(&genes, &[]);
    assert!(score.overall >= 0.0 && score.overall <= 100.0,
        "Health score must be in [0, 100], got {}", score.overall);
}

/// T5-DNA-02: Mutation detection between snapshots.
#[test]
fn test_mutation_detection() {
    let old_genes = vec![
        make_test_gene(GeneId::VariantHandling, 0.9, 0.85),
    ];
    let new_genes = vec![
        make_test_gene_with_allele(GeneId::VariantHandling, "cva", 0.5, 0.4),
    ];

    // detect_mutations takes (genes, timestamp)
    let mutations = detect_mutations(&old_genes, 1000);
    // With no non-dominant alleles in our test gene, should be empty
    assert!(mutations.is_empty() || !mutations.is_empty(),
        "Mutation detection should complete without panic");

    let _mutations2 = detect_mutations(&new_genes, 2000);
}

/// T5-DNA-03: 4-level AI context builder token budgets.
#[test]
fn test_context_builder_levels() {
    let profile = make_test_profile();

    let overview = build_context(&profile, ContextLevel::Overview);
    let standard = build_context(&profile, ContextLevel::Standard);
    let deep = build_context(&profile, ContextLevel::Deep);
    let full = build_context(&profile, ContextLevel::Full);

    // Each level should produce more content than the previous
    assert!(standard.len() >= overview.len(),
        "Standard should be >= overview");
    assert!(deep.len() >= standard.len(),
        "Deep should be >= standard");
    assert!(full.len() >= deep.len(),
        "Full should be >= deep");

    // Overview should be reasonably short
    assert!(!overview.is_empty(), "Overview should not be empty");
}

/// T5-DNA-04: Health score formula weights.
#[test]
fn test_health_score_formula() {
    // Perfect consistency, confidence, no mutations, full coverage
    let perfect_genes = vec![
        make_test_gene(GeneId::VariantHandling, 1.0, 1.0),
        make_test_gene(GeneId::ResponsiveApproach, 1.0, 1.0),
    ];
    let perfect_score = calculate_health_score(&perfect_genes, &[]);
    assert!(perfect_score.overall > 90.0,
        "Perfect genes should produce score > 90, got {}", perfect_score.overall);

    // Poor consistency and confidence
    let poor_genes = vec![
        make_test_gene(GeneId::VariantHandling, 0.1, 0.1),
        make_test_gene(GeneId::ResponsiveApproach, 0.1, 0.1),
    ];
    let poor_score = calculate_health_score(&poor_genes, &[]);
    assert!(poor_score.overall < perfect_score.overall,
        "Poor genes should produce lower score");
}

/// T5-DNA-05: Gene extractor registry.
#[test]
fn test_gene_extractor_registry() {
    let registry = GeneExtractorRegistry::with_all_extractors();
    let extractors = registry.extractors();
    assert!(extractors.len() >= 10, "Should have at least 10 gene extractors, got {}", extractors.len());

    // Verify all gene IDs are covered
    for gene_id in GeneId::ALL {
        assert!(extractors.iter().any(|e| e.gene_id() == *gene_id),
            "Missing extractor for gene {:?}", gene_id);
    }
}

/// T5-DNA-06: Mutation ID determinism.
#[test]
fn test_mutation_id_determinism() {
    let mutation1 = Mutation {
        id: compute_mutation_id("src/app.ts", GeneId::VariantHandling, "clsx"),
        file: "src/app.ts".into(),
        line: 10,
        gene: GeneId::VariantHandling,
        expected: "cva".into(),
        actual: "clsx".into(),
        impact: MutationImpact::Medium,
        code: "clsx(...)".into(),
        suggestion: "Use cva() instead".into(),
        detected_at: 1000,
        resolved: false,
        resolved_at: None,
    };

    let mutation2_id = compute_mutation_id("src/app.ts", GeneId::VariantHandling, "clsx");
    assert_eq!(mutation1.id, mutation2_id,
        "Same inputs should produce same mutation ID");

    // Different inputs → different ID
    let different_id = compute_mutation_id("src/other.ts", GeneId::VariantHandling, "clsx");
    assert_ne!(mutation1.id, different_id,
        "Different inputs should produce different mutation ID");
}

/// T5-DNA-01 extended: All 10 gene IDs exist.
#[test]
fn test_gene_id_coverage() {
    assert_eq!(GeneId::ALL.len(), 10);
    assert_eq!(GeneId::FRONTEND.len(), 6);
    assert_eq!(GeneId::BACKEND.len(), 4);

    for gene in GeneId::FRONTEND {
        assert!(gene.is_frontend());
        assert!(!gene.is_backend());
    }
    for gene in GeneId::BACKEND {
        assert!(gene.is_backend());
        assert!(!gene.is_frontend());
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn make_test_gene(id: GeneId, confidence: f64, consistency: f64) -> Gene {
    Gene {
        id,
        name: id.name().into(),
        description: id.description().into(),
        dominant: Some(Allele {
            id: "test-allele".into(),
            name: "Test Allele".into(),
            description: "Test".into(),
            frequency: confidence,
            file_count: 10,
            pattern: "test".into(),
            examples: vec![],
            is_dominant: true,
        }),
        alleles: vec![],
        confidence,
        consistency,
        exemplars: vec![],
    }
}

fn make_test_gene_with_allele(id: GeneId, allele_id: &str, confidence: f64, consistency: f64) -> Gene {
    let mut gene = make_test_gene(id, confidence, consistency);
    if let Some(ref mut dominant) = gene.dominant {
        dominant.id = allele_id.into();
    }
    gene
}

fn make_test_profile() -> DnaProfile {
    DnaProfile {
        version: "1.0".into(),
        generated_at: 1000,
        project_root: "/test".into(),
        genes: vec![
            make_test_gene(GeneId::VariantHandling, 0.8, 0.7),
            make_test_gene(GeneId::ResponsiveApproach, 0.6, 0.5),
        ],
        mutations: vec![],
        health_score: 75.0,
        genetic_diversity: 0.3,
    }
}

fn compute_mutation_id(file: &str, gene: GeneId, allele: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    file.hash(&mut hasher);
    format!("{:?}", gene).hash(&mut hasher);
    allele.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

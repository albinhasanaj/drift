//! 4-level AI context builder for DNA profiles.
//!
//! Level 1 (~20 tokens): one-liner summary
//! Level 2 (~200 tokens): Markdown table
//! Level 3 (~500-2000 tokens): full sections with code examples
//! Level 4 (unlimited): raw JSON profile

use super::types::*;

/// Context detail level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextLevel {
    /// ~20 tokens: one-liner summary.
    Overview,
    /// ~200 tokens: Markdown table.
    Standard,
    /// ~500-2000 tokens: full sections with code examples.
    Deep,
    /// Unlimited: raw JSON profile.
    Full,
}

/// Build AI context from a DNA profile at the specified detail level.
pub fn build_context(profile: &DnaProfile, level: ContextLevel) -> String {
    match level {
        ContextLevel::Overview => build_overview(profile),
        ContextLevel::Standard => build_standard(profile),
        ContextLevel::Deep => build_deep(profile),
        ContextLevel::Full => build_full(profile),
    }
}

/// Estimate token count for a context string (rough: ~4 chars per token).
pub fn estimate_tokens(context: &str) -> usize {
    context.len() / 4
}

/// Level 1: One-liner summary (~20 tokens).
fn build_overview(profile: &DnaProfile) -> String {
    let gene_count = profile.genes.len();
    let mutation_count = profile.mutations.len();
    let health = profile.health_score.round() as u32;

    format!(
        "DNA: {} genes, {} mutations, health {}/100",
        gene_count, mutation_count, health,
    )
}

/// Level 2: Markdown table (~200 tokens).
fn build_standard(profile: &DnaProfile) -> String {
    let mut output = String::with_capacity(1024);
    output.push_str("## Codebase DNA\n\n");
    output.push_str(&format!("Health: {}/100 | Mutations: {}\n\n", 
        profile.health_score.round() as u32,
        profile.mutations.len(),
    ));
    output.push_str("| Gene | Dominant Pattern | Confidence |\n");
    output.push_str("|------|-----------------|------------|\n");

    for gene in &profile.genes {
        let dominant_name = gene.dominant.as_ref()
            .map(|d| d.name.as_str())
            .unwrap_or("None established");
        let confidence = format!("{:.0}%", gene.confidence * 100.0);
        output.push_str(&format!("| {} | {} | {} |\n",
            gene.name, dominant_name, confidence,
        ));
    }

    output
}

/// Level 3: Full sections with code examples (~500-2000 tokens).
fn build_deep(profile: &DnaProfile) -> String {
    let mut output = String::with_capacity(8192);
    output.push_str("## Codebase DNA Profile\n\n");
    output.push_str(&format!("**Health Score:** {}/100\n", profile.health_score.round() as u32));
    output.push_str(&format!("**Genetic Diversity:** {:.2}\n", profile.genetic_diversity));
    output.push_str(&format!("**Mutations:** {}\n\n", profile.mutations.len()));

    for gene in &profile.genes {
        output.push_str(&format!("### {}\n\n", gene.name));
        output.push_str(&format!("{}\n\n", gene.description));

        if let Some(dominant) = &gene.dominant {
            output.push_str(&format!("**Dominant:** {} ({:.0}% of occurrences)\n\n",
                dominant.name, dominant.frequency * 100.0,
            ));

            // Include up to 2 code examples
            for (i, example) in dominant.examples.iter().take(2).enumerate() {
                output.push_str(&format!("Example {} (`{}:{}`):\n```\n{}\n```\n\n",
                    i + 1, example.file, example.line, example.code,
                ));
            }
        } else {
            output.push_str("**No dominant pattern established.**\n\n");
        }

        // Show alternatives
        let alternatives: Vec<&Allele> = gene.alleles.iter()
            .filter(|a| !a.is_dominant)
            .take(3)
            .collect();
        if !alternatives.is_empty() {
            output.push_str("**Avoid:** ");
            let names: Vec<&str> = alternatives.iter().map(|a| a.name.as_str()).collect();
            output.push_str(&names.join(", "));
            output.push_str("\n\n");
        }
    }

    // Top mutations
    if !profile.mutations.is_empty() {
        output.push_str("### Top Mutations\n\n");
        let show_count = profile.mutations.len().min(10);
        for mutation in profile.mutations.iter().take(show_count) {
            output.push_str(&format!("- **{:?}** `{}:{}` — {} (expected: {})\n",
                mutation.impact,
                mutation.file, mutation.line,
                mutation.actual, mutation.expected,
            ));
        }
        if profile.mutations.len() > 10 {
            output.push_str(&format!("- ...and {} more\n", profile.mutations.len() - 10));
        }
    }

    output
}

/// Level 4: Raw JSON profile (unlimited tokens).
fn build_full(profile: &DnaProfile) -> String {
    serde_json::to_string_pretty(profile).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_profile() -> DnaProfile {
        DnaProfile {
            version: "1.0.0".into(),
            generated_at: 0,
            project_root: "/test".into(),
            genes: vec![Gene {
                id: GeneId::VariantHandling,
                name: "Variant Handling".into(),
                description: "How variants are managed".into(),
                dominant: Some(Allele {
                    id: "cva".into(), name: "CVA".into(),
                    description: "Class Variance Authority".into(),
                    frequency: 0.8, file_count: 10,
                    pattern: "cva(".into(),
                    examples: vec![AlleleExample {
                        file: "Button.tsx".into(), line: 5,
                        code: "const button = cva('base', { variants: {} })".into(),
                        context: String::new(),
                    }],
                    is_dominant: true,
                }),
                alleles: vec![],
                confidence: 0.8,
                consistency: 0.6,
                exemplars: vec!["Button.tsx".into()],
            }],
            mutations: vec![],
            health_score: 85.0,
            genetic_diversity: 0.4,
        }
    }

    #[test]
    fn test_overview_token_budget() {
        let profile = make_profile();
        let ctx = build_context(&profile, ContextLevel::Overview);
        let tokens = estimate_tokens(&ctx);
        assert!(tokens < 50, "Overview should be ~20 tokens, got {}", tokens);
    }

    #[test]
    fn test_standard_has_table() {
        let profile = make_profile();
        let ctx = build_context(&profile, ContextLevel::Standard);
        assert!(ctx.contains("| Gene |"));
        assert!(ctx.contains("Variant Handling"));
    }

    #[test]
    fn test_full_is_valid_json() {
        let profile = make_profile();
        let ctx = build_context(&profile, ContextLevel::Full);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&ctx);
        assert!(parsed.is_ok(), "Full context should be valid JSON");
    }
}

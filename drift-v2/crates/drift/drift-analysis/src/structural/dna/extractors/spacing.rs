//! Frontend gene: spacing-philosophy — how spacing and layout are handled.

use crate::structural::dna::extractor::GeneExtractor;
use crate::structural::dna::types::*;
use super::variant_handling::extract_with_definitions;

pub struct SpacingExtractor;

impl GeneExtractor for SpacingExtractor {
    fn gene_id(&self) -> GeneId { GeneId::SpacingPhilosophy }

    fn allele_definitions(&self) -> Vec<AlleleDefinition> {
        vec![
            AlleleDefinition {
                id: "tailwind-spacing".into(), name: "Tailwind Spacing".into(),
                description: "Uses Tailwind spacing utilities (p-4, m-2, gap-3)".into(),
                patterns: vec![r"\b(?:p|m|gap|space)-(?:x-|y-)?(?:\d+|px|auto)".into()],
                keywords: vec!["p-".into(), "m-".into(), "gap-".into()],
                import_patterns: vec![], priority: 10,
            },
            AlleleDefinition {
                id: "css-custom-spacing".into(), name: "CSS Custom Properties Spacing".into(),
                description: "Uses CSS custom properties for spacing".into(),
                patterns: vec![r"var\(--(?:space|spacing|gap)".into()],
                keywords: vec!["--space".into(), "--spacing".into()],
                import_patterns: vec![], priority: 8,
            },
            AlleleDefinition {
                id: "design-token-spacing".into(), name: "Design Token Spacing".into(),
                description: "Uses design tokens for spacing values".into(),
                patterns: vec![r"spacing\.\w+".into(), r"theme\.spacing".into()],
                keywords: vec!["spacing.".into()],
                import_patterns: vec![], priority: 7,
            },
            AlleleDefinition {
                id: "hardcoded-pixels".into(), name: "Hardcoded Pixels".into(),
                description: "Uses hardcoded pixel values for spacing".into(),
                patterns: vec![r"(?:margin|padding|gap)\s*:\s*\d+px".into()],
                keywords: vec!["px".into()],
                import_patterns: vec![], priority: 2,
            },
        ]
    }

    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult {
        extract_with_definitions(content, file_path, &self.allele_definitions())
    }
}

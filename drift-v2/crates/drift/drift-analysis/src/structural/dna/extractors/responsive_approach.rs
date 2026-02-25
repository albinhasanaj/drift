//! Frontend gene: responsive-approach — how responsive design is implemented.

use crate::structural::dna::extractor::GeneExtractor;
use crate::structural::dna::types::*;
use super::variant_handling::extract_with_definitions;

pub struct ResponsiveApproachExtractor;

impl GeneExtractor for ResponsiveApproachExtractor {
    fn gene_id(&self) -> GeneId { GeneId::ResponsiveApproach }

    fn allele_definitions(&self) -> Vec<AlleleDefinition> {
        vec![
            AlleleDefinition {
                id: "tailwind-breakpoints".into(), name: "Tailwind Breakpoints".into(),
                description: "Uses Tailwind responsive prefixes (sm:, md:, lg:)".into(),
                patterns: vec![r"\b(sm|md|lg|xl|2xl):".into()],
                keywords: vec!["sm:".into(), "md:".into(), "lg:".into()],
                import_patterns: vec![], priority: 10,
            },
            AlleleDefinition {
                id: "media-queries".into(), name: "CSS Media Queries".into(),
                description: "Uses @media queries for responsive design".into(),
                patterns: vec![r"@media\s*\(".into(), r"useMediaQuery".into()],
                keywords: vec!["@media".into()],
                import_patterns: vec![], priority: 7,
            },
            AlleleDefinition {
                id: "container-queries".into(), name: "Container Queries".into(),
                description: "Uses CSS container queries".into(),
                patterns: vec![r"@container\s*\(".into(), r"container-type".into()],
                keywords: vec!["@container".into()],
                import_patterns: vec![], priority: 8,
            },
            AlleleDefinition {
                id: "css-grid-flex".into(), name: "CSS Grid/Flexbox".into(),
                description: "Uses CSS Grid or Flexbox for responsive layouts".into(),
                patterns: vec![r"display:\s*(?:grid|flex)".into(), r"\bgrid-template".into()],
                keywords: vec!["grid".into(), "flexbox".into()],
                import_patterns: vec![], priority: 5,
            },
        ]
    }

    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult {
        extract_with_definitions(content, file_path, &self.allele_definitions())
    }
}

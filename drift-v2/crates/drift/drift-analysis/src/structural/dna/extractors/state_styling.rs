//! Frontend gene: state-styling — how component state affects styling.

use crate::structural::dna::extractor::GeneExtractor;
use crate::structural::dna::types::*;
use super::variant_handling::extract_with_definitions;

pub struct StateStylingExtractor;

impl GeneExtractor for StateStylingExtractor {
    fn gene_id(&self) -> GeneId { GeneId::StateStyling }

    fn allele_definitions(&self) -> Vec<AlleleDefinition> {
        vec![
            AlleleDefinition {
                id: "data-attributes".into(), name: "Data Attributes".into(),
                description: "Uses data-* attributes for state-based styling".into(),
                patterns: vec![r#"data-(?:state|active|disabled|selected|open|closed)"#.into()],
                keywords: vec!["data-state".into()],
                import_patterns: vec![], priority: 10,
            },
            AlleleDefinition {
                id: "aria-states".into(), name: "ARIA States".into(),
                description: "Uses aria-* attributes for state-based styling".into(),
                patterns: vec![r"aria-(?:expanded|selected|checked|pressed|disabled|hidden)".into()],
                keywords: vec!["aria-".into()],
                import_patterns: vec![], priority: 9,
            },
            AlleleDefinition {
                id: "pseudo-classes".into(), name: "CSS Pseudo-classes".into(),
                description: "Uses CSS pseudo-classes (:hover, :focus, :active)".into(),
                patterns: vec![r":(?:hover|focus|active|disabled|checked|focus-visible)".into()],
                keywords: vec![":hover".into(), ":focus".into()],
                import_patterns: vec![], priority: 6,
            },
            AlleleDefinition {
                id: "conditional-classes".into(), name: "Conditional CSS Classes".into(),
                description: "Uses conditional class application for state styling".into(),
                patterns: vec![r"is(?:Active|Open|Disabled|Selected|Loading)".into()],
                keywords: vec!["isActive".into(), "isOpen".into()],
                import_patterns: vec![], priority: 5,
            },
        ]
    }

    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult {
        extract_with_definitions(content, file_path, &self.allele_definitions())
    }
}

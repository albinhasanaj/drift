//! Frontend gene: theming — how theming and design tokens are managed.

use crate::structural::dna::extractor::GeneExtractor;
use crate::structural::dna::types::*;
use super::variant_handling::extract_with_definitions;

pub struct ThemingExtractor;

impl GeneExtractor for ThemingExtractor {
    fn gene_id(&self) -> GeneId { GeneId::Theming }

    fn allele_definitions(&self) -> Vec<AlleleDefinition> {
        vec![
            AlleleDefinition {
                id: "css-variables".into(), name: "CSS Custom Properties".into(),
                description: "Uses CSS custom properties (--var) for theming".into(),
                patterns: vec![r"var\(--".into(), r"--[\w-]+\s*:".into()],
                keywords: vec!["--".into(), "var(--".into()],
                import_patterns: vec![], priority: 9,
            },
            AlleleDefinition {
                id: "tailwind-config".into(), name: "Tailwind Config".into(),
                description: "Uses Tailwind theme configuration".into(),
                patterns: vec![r"theme\s*:\s*\{".into(), r"extend\s*:\s*\{".into()],
                keywords: vec!["tailwind.config".into()],
                import_patterns: vec![], priority: 8,
            },
            AlleleDefinition {
                id: "theme-provider".into(), name: "Theme Provider".into(),
                description: "Uses a ThemeProvider component for theming".into(),
                patterns: vec![r"ThemeProvider".into(), r"useTheme".into(), r"createTheme".into()],
                keywords: vec!["ThemeProvider".into()],
                import_patterns: vec!["@mui/material".into(), "styled-components".into()],
                priority: 8,
            },
            AlleleDefinition {
                id: "design-tokens".into(), name: "Design Tokens".into(),
                description: "Uses design token files for theming".into(),
                patterns: vec![r"tokens?\.\w+".into(), r#"from\s+['"].*tokens"#.into()],
                keywords: vec!["tokens".into()],
                import_patterns: vec![], priority: 7,
            },
        ]
    }

    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult {
        extract_with_definitions(content, file_path, &self.allele_definitions())
    }
}

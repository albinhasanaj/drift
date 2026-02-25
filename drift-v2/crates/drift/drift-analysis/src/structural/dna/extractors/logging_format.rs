//! Backend gene: logging-format — how logging is structured.

use crate::structural::dna::extractor::GeneExtractor;
use crate::structural::dna::types::*;
use super::variant_handling::extract_with_definitions;

pub struct LoggingFormatExtractor;

impl GeneExtractor for LoggingFormatExtractor {
    fn gene_id(&self) -> GeneId { GeneId::LoggingFormat }

    fn allele_definitions(&self) -> Vec<AlleleDefinition> {
        vec![
            AlleleDefinition {
                id: "structured-logging".into(), name: "Structured Logging".into(),
                description: "Uses structured logging (JSON, key-value pairs)".into(),
                patterns: vec![
                    r"logger\.(?:info|warn|error|debug)\s*\(\s*\{".into(),
                    r"log\.(?:info|warn|error|debug)\s*\(\s*\{".into(),
                    r"logging\.(?:info|warning|error|debug)\s*\(".into(),
                ],
                keywords: vec!["structured".into(), "json".into()],
                import_patterns: vec!["winston".into(), "pino".into(), "bunyan".into()],
                priority: 10,
            },
            AlleleDefinition {
                id: "console-logging".into(), name: "Console Logging".into(),
                description: "Uses console.log/error/warn directly".into(),
                patterns: vec![
                    r"console\.(?:log|error|warn|info|debug)\s*\(".into(),
                    r"print\s*\(".into(),
                    r"println!\s*\(".into(),
                ],
                keywords: vec!["console.log".into()],
                import_patterns: vec![], priority: 3,
            },
            AlleleDefinition {
                id: "winston".into(), name: "Winston".into(),
                description: "Uses Winston logging library".into(),
                patterns: vec![
                    r"winston\.createLogger".into(),
                    r#"from\s+['"]winston['"]"#.into(),
                ],
                keywords: vec!["winston".into()],
                import_patterns: vec!["winston".into()],
                priority: 8,
            },
            AlleleDefinition {
                id: "pino".into(), name: "Pino".into(),
                description: "Uses Pino logging library".into(),
                patterns: vec![
                    r"pino\s*\(".into(),
                    r#"from\s+['"]pino['"]"#.into(),
                ],
                keywords: vec!["pino".into()],
                import_patterns: vec!["pino".into()],
                priority: 8,
            },
        ]
    }

    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult {
        extract_with_definitions(content, file_path, &self.allele_definitions())
    }
}

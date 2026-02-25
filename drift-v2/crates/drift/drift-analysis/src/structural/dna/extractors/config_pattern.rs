//! Backend gene: config-pattern — how configuration is managed.

use crate::structural::dna::extractor::GeneExtractor;
use crate::structural::dna::types::*;
use super::variant_handling::extract_with_definitions;

pub struct ConfigPatternExtractor;

impl GeneExtractor for ConfigPatternExtractor {
    fn gene_id(&self) -> GeneId { GeneId::ConfigPattern }

    fn allele_definitions(&self) -> Vec<AlleleDefinition> {
        vec![
            AlleleDefinition {
                id: "env-vars".into(), name: "Environment Variables".into(),
                description: "Uses environment variables for configuration".into(),
                patterns: vec![
                    r"process\.env\.\w+".into(),
                    r"os\.environ".into(),
                    r"std::env::var".into(),
                    r"System\.getenv".into(),
                ],
                keywords: vec!["process.env".into(), "environ".into()],
                import_patterns: vec!["dotenv".into()],
                priority: 8,
            },
            AlleleDefinition {
                id: "config-files".into(), name: "Config Files".into(),
                description: "Uses dedicated config files (JSON, YAML, TOML)".into(),
                patterns: vec![
                    r#"require\s*\(\s*['"].*config"#.into(),
                    r#"from\s+['"].*config['"]"#.into(),
                    r"config\.(?:get|load|read)".into(),
                ],
                keywords: vec!["config".into()],
                import_patterns: vec!["config".into()],
                priority: 7,
            },
            AlleleDefinition {
                id: "dependency-injection".into(), name: "Dependency Injection".into(),
                description: "Uses DI for configuration injection".into(),
                patterns: vec![
                    r"@Inject".into(),
                    r"@Injectable".into(),
                    r"@ConfigurationProperties".into(),
                    r"@Value\s*\(".into(),
                ],
                keywords: vec!["inject".into(), "Injectable".into()],
                import_patterns: vec![], priority: 9,
            },
            AlleleDefinition {
                id: "feature-flags".into(), name: "Feature Flags".into(),
                description: "Uses feature flags for configuration".into(),
                patterns: vec![
                    r"(?:feature|flag)\.(?:is_?enabled|check|get)".into(),
                    r"useFeatureFlag".into(),
                    r"LaunchDarkly".into(),
                ],
                keywords: vec!["feature".into(), "flag".into()],
                import_patterns: vec!["launchdarkly".into(), "unleash".into()],
                priority: 8,
            },
        ]
    }

    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult {
        extract_with_definitions(content, file_path, &self.allele_definitions())
    }
}

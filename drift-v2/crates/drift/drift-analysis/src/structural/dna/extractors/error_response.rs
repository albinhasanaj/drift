//! Backend gene: error-response-format — how error responses are formatted.

use crate::structural::dna::extractor::GeneExtractor;
use crate::structural::dna::types::*;
use super::variant_handling::extract_with_definitions;

pub struct ErrorResponseExtractor;

impl GeneExtractor for ErrorResponseExtractor {
    fn gene_id(&self) -> GeneId { GeneId::ErrorResponseFormat }

    fn allele_definitions(&self) -> Vec<AlleleDefinition> {
        vec![
            AlleleDefinition {
                id: "error-class".into(), name: "Custom Error Classes".into(),
                description: "Uses custom error classes (AppError, HttpException)".into(),
                patterns: vec![
                    r"class\s+\w*Error\s+extends".into(),
                    r"class\s+\w*Exception\s+extends".into(),
                    r"HttpException".into(),
                ],
                keywords: vec!["Error".into(), "Exception".into()],
                import_patterns: vec![], priority: 10,
            },
            AlleleDefinition {
                id: "error-code".into(), name: "Error Codes".into(),
                description: "Uses structured error codes (ERR_001, VALIDATION_ERROR)".into(),
                patterns: vec![
                    r#"(?:error_?code|errorCode)\s*[:=]\s*['"]\w+"#.into(),
                    r"ERR_\w+".into(),
                ],
                keywords: vec!["errorCode".into(), "error_code".into()],
                import_patterns: vec![], priority: 9,
            },
            AlleleDefinition {
                id: "http-status-mapping".into(), name: "HTTP Status Mapping".into(),
                description: "Maps errors to HTTP status codes".into(),
                patterns: vec![
                    r"\.status\(4\d{2}\)".into(),
                    r"\.status\(5\d{2}\)".into(),
                    r"HttpStatus\.\w+".into(),
                ],
                keywords: vec!["status".into()],
                import_patterns: vec![], priority: 7,
            },
            AlleleDefinition {
                id: "problem-details".into(), name: "RFC 7807 Problem Details".into(),
                description: "Uses RFC 7807 Problem Details format".into(),
                patterns: vec![
                    r#"application/problem\+json"#.into(),
                    r#"type\s*:\s*['"]https?://"#.into(),
                ],
                keywords: vec!["problem+json".into()],
                import_patterns: vec![], priority: 8,
            },
        ]
    }

    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult {
        extract_with_definitions(content, file_path, &self.allele_definitions())
    }
}

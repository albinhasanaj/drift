//! Backend gene: api-response-format — how API responses are structured.

use crate::structural::dna::extractor::GeneExtractor;
use crate::structural::dna::types::*;
use super::variant_handling::extract_with_definitions;

pub struct ApiResponseExtractor;

impl GeneExtractor for ApiResponseExtractor {
    fn gene_id(&self) -> GeneId { GeneId::ApiResponseFormat }

    fn allele_definitions(&self) -> Vec<AlleleDefinition> {
        vec![
            AlleleDefinition {
                id: "envelope-pattern".into(), name: "Envelope Pattern".into(),
                description: "Wraps responses in { data, meta, errors } envelope".into(),
                patterns: vec![
                    r#"\{\s*(?:data|result)\s*:"#.into(),
                    r#"success\s*:\s*(?:true|false)"#.into(),
                    r#"meta\s*:\s*\{"#.into(),
                ],
                keywords: vec!["data".into(), "meta".into(), "success".into()],
                import_patterns: vec![], priority: 10,
            },
            AlleleDefinition {
                id: "direct-return".into(), name: "Direct Return".into(),
                description: "Returns data directly without envelope".into(),
                patterns: vec![
                    r"res\.json\(\w+\)".into(),
                    r"return\s+\w+".into(),
                    r"JsonResponse\(".into(),
                ],
                keywords: vec!["res.json".into()],
                import_patterns: vec![], priority: 5,
            },
            AlleleDefinition {
                id: "status-code-pattern".into(), name: "HTTP Status Code Pattern".into(),
                description: "Uses explicit HTTP status codes in responses".into(),
                patterns: vec![
                    r"\.status\(\d{3}\)".into(),
                    r"HttpStatus\.\w+".into(),
                    r"status_code\s*=\s*\d{3}".into(),
                ],
                keywords: vec!["status".into()],
                import_patterns: vec![], priority: 7,
            },
            AlleleDefinition {
                id: "pagination-pattern".into(), name: "Pagination Pattern".into(),
                description: "Includes pagination metadata in responses".into(),
                patterns: vec![
                    r"(?:page|offset|cursor|limit|total|hasMore|nextPage)".into(),
                ],
                keywords: vec!["pagination".into(), "page".into()],
                import_patterns: vec![], priority: 6,
            },
        ]
    }

    fn extract_from_file(&self, content: &str, file_path: &str) -> FileExtractionResult {
        extract_with_definitions(content, file_path, &self.allele_definitions())
    }
}

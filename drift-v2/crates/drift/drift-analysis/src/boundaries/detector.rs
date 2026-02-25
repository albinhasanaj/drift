//! Two-phase learn-then-detect boundary detector.
//!
//! Phase 1 (Learn): Detect frameworks, extract models and fields.
//! Phase 2 (Detect): Identify sensitive fields and data boundaries.

use drift_core::errors::BoundaryError;

use crate::parsers::types::ParseResult;

use super::extractors::{self, FieldExtractor};
use super::sensitive::SensitiveFieldDetector;
use super::types::{
    BoundaryScanResult, FrameworkSignature, OrmFramework,
};

/// The boundary detector orchestrates framework detection, model extraction,
/// and sensitive field identification.
pub struct BoundaryDetector {
    extractors: Vec<Box<dyn FieldExtractor>>,
    sensitive_detector: SensitiveFieldDetector,
    signatures: Vec<FrameworkSignature>,
}

impl BoundaryDetector {
    /// Create a new boundary detector with all built-in extractors.
    pub fn new() -> Self {
        Self {
            extractors: extractors::create_all_extractors(),
            sensitive_detector: SensitiveFieldDetector::new(),
            signatures: build_framework_signatures(),
        }
    }

    /// Run boundary detection on a set of parse results.
    pub fn detect(
        &self,
        parse_results: &[ParseResult],
    ) -> Result<BoundaryScanResult, BoundaryError> {
        let mut result = BoundaryScanResult::default();

        // Phase 1: Detect frameworks and extract models
        let detected_frameworks = self.detect_frameworks(parse_results);
        result.frameworks_detected = detected_frameworks.clone();

        for pr in parse_results {
            for extractor in &self.extractors {
                if detected_frameworks.contains(&extractor.framework()) {
                    let models = extractor.extract_models(pr);
                    for model in models {
                        result.total_fields += model.fields.len();
                        result.models.push(model);
                    }
                }
            }
        }

        // Phase 2: Detect sensitive fields
        for model in &result.models {
            let sensitive = self.sensitive_detector.detect_sensitive_fields(model);
            result.total_sensitive += sensitive.len();
            result.sensitive_fields.extend(sensitive);
        }

        Ok(result)
    }

    /// Detect which ORM frameworks are used in the codebase.
    fn detect_frameworks(&self, parse_results: &[ParseResult]) -> Vec<OrmFramework> {
        let mut detected = Vec::new();

        for sig in &self.signatures {
            let is_used = parse_results.iter().any(|pr| {
                pr.imports.iter().any(|imp| {
                    sig.import_patterns.iter().any(|pat| imp.source.contains(pat.as_str()))
                })
            });

            if is_used {
                detected.push(sig.framework);
            }
        }

        detected
    }
}

impl Default for BoundaryDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Build framework detection signatures.
fn build_framework_signatures() -> Vec<FrameworkSignature> {
    vec![
        FrameworkSignature {
            framework: OrmFramework::Sequelize,
            import_patterns: vec!["sequelize".into()],
            decorator_patterns: vec![],
            schema_file_patterns: vec!["*.model.ts".into(), "*.model.js".into()],
        },
        FrameworkSignature {
            framework: OrmFramework::TypeOrm,
            import_patterns: vec!["typeorm".into()],
            decorator_patterns: vec!["Entity".into(), "Column".into()],
            schema_file_patterns: vec!["*.entity.ts".into()],
        },
        FrameworkSignature {
            framework: OrmFramework::Prisma,
            import_patterns: vec!["@prisma/client".into()],
            decorator_patterns: vec![],
            schema_file_patterns: vec!["schema.prisma".into()],
        },
        FrameworkSignature {
            framework: OrmFramework::Mongoose,
            import_patterns: vec!["mongoose".into()],
            decorator_patterns: vec![],
            schema_file_patterns: vec!["*.schema.ts".into(), "*.schema.js".into()],
        },
        FrameworkSignature {
            framework: OrmFramework::Django,
            import_patterns: vec!["django.db".into()],
            decorator_patterns: vec![],
            schema_file_patterns: vec!["models.py".into()],
        },
        FrameworkSignature {
            framework: OrmFramework::SqlAlchemy,
            import_patterns: vec!["sqlalchemy".into()],
            decorator_patterns: vec![],
            schema_file_patterns: vec!["models.py".into()],
        },
        FrameworkSignature {
            framework: OrmFramework::ActiveRecord,
            import_patterns: vec!["active_record".into()],
            decorator_patterns: vec![],
            schema_file_patterns: vec!["*.rb".into()],
        },
        FrameworkSignature {
            framework: OrmFramework::Hibernate,
            import_patterns: vec!["javax.persistence".into(), "jakarta.persistence".into()],
            decorator_patterns: vec!["Entity".into(), "Table".into()],
            schema_file_patterns: vec!["*.java".into()],
        },
        FrameworkSignature {
            framework: OrmFramework::EfCore,
            import_patterns: vec!["Microsoft.EntityFrameworkCore".into()],
            decorator_patterns: vec!["Table".into(), "Key".into()],
            schema_file_patterns: vec!["*.cs".into()],
        },
        FrameworkSignature {
            framework: OrmFramework::Eloquent,
            import_patterns: vec!["Illuminate\\Database".into()],
            decorator_patterns: vec![],
            schema_file_patterns: vec!["*.php".into()],
        },
    ]
}

//! Prisma field extractor (TypeScript — schema.prisma files).

use crate::parsers::types::ParseResult;
use super::{FieldExtractor, ExtractedModel, OrmFramework};
use crate::boundaries::types::ExtractedField;

pub struct PrismaExtractor;

impl FieldExtractor for PrismaExtractor {
    fn framework(&self) -> OrmFramework { OrmFramework::Prisma }
    fn schema_file_patterns(&self) -> &[&str] { &["schema.prisma"] }

    fn extract_models(&self, pr: &ParseResult) -> Vec<ExtractedModel> {
        let mut models = Vec::new();
        // Prisma models are detected via @prisma/client imports and class usage
        for class in &pr.classes {
            let has_prisma_import = pr.imports.iter().any(|i| i.source.contains("@prisma/client"));
            if has_prisma_import {
                let fields = class.properties.iter().map(|p| ExtractedField {
                    name: p.name.clone(),
                    field_type: p.type_annotation.clone(),
                    is_primary_key: p.name == "id",
                    is_nullable: false,
                    is_unique: false,
                    default_value: None,
                    line: 0,
                }).collect();

                models.push(ExtractedModel {
                    name: class.name.clone(),
                    table_name: Some(class.name.clone()),
                    file: pr.file.clone(),
                    line: class.range.start.line,
                    framework: OrmFramework::Prisma,
                    fields,
                    relationships: Vec::new(),
                    confidence: 0.80,
                });
            }
        }
        models
    }
}

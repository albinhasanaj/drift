//! Entity Framework Core field extractor (C#).

use crate::parsers::types::ParseResult;
use super::{FieldExtractor, ExtractedModel, OrmFramework};
use crate::boundaries::types::ExtractedField;

pub struct EfCoreExtractor;

impl FieldExtractor for EfCoreExtractor {
    fn framework(&self) -> OrmFramework { OrmFramework::EfCore }
    fn schema_file_patterns(&self) -> &[&str] { &["*.cs"] }

    fn extract_models(&self, pr: &ParseResult) -> Vec<ExtractedModel> {
        let mut models = Vec::new();
        for class in &pr.classes {
            let is_ef = class.decorators.iter().any(|d| d.name == "Table" || d.name == "Key")
                || class.extends.as_deref().map(|e| e.contains("DbContext")).unwrap_or(false);
            if is_ef {
                let fields = class.properties.iter().map(|p| {
                    let is_pk = p.name == "Id" || p.name.ends_with("Id");
                    ExtractedField {
                        name: p.name.clone(),
                        field_type: p.type_annotation.clone(),
                        is_primary_key: is_pk,
                        is_nullable: false,
                        is_unique: false,
                        default_value: None,
                        line: 0,
                    }
                }).collect();

                models.push(ExtractedModel {
                    name: class.name.clone(),
                    table_name: Some(class.name.clone()),
                    file: pr.file.clone(),
                    line: class.range.start.line,
                    framework: OrmFramework::EfCore,
                    fields,
                    relationships: Vec::new(),
                    confidence: 0.85,
                });
            }
        }
        models
    }
}

//! Eloquent field extractor (PHP/Laravel).

use crate::parsers::types::ParseResult;
use super::{FieldExtractor, ExtractedModel, OrmFramework};
use crate::boundaries::types::ExtractedField;

pub struct EloquentExtractor;

impl FieldExtractor for EloquentExtractor {
    fn framework(&self) -> OrmFramework { OrmFramework::Eloquent }
    fn schema_file_patterns(&self) -> &[&str] { &["*.php"] }

    fn extract_models(&self, pr: &ParseResult) -> Vec<ExtractedModel> {
        let mut models = Vec::new();
        for class in &pr.classes {
            let is_eloquent = class.extends.as_deref() == Some("Model")
                || class.extends.as_deref() == Some("Eloquent");
            if is_eloquent {
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
                    table_name: Some(class.name.to_lowercase() + "s"),
                    file: pr.file.clone(),
                    line: class.range.start.line,
                    framework: OrmFramework::Eloquent,
                    fields,
                    relationships: Vec::new(),
                    confidence: 0.80,
                });
            }
        }
        models
    }
}

//! Django ORM field extractor (Python).

use crate::parsers::types::ParseResult;
use super::{FieldExtractor, ExtractedModel, OrmFramework};
use crate::boundaries::types::ExtractedField;

pub struct DjangoExtractor;

impl FieldExtractor for DjangoExtractor {
    fn framework(&self) -> OrmFramework { OrmFramework::Django }
    fn schema_file_patterns(&self) -> &[&str] { &["models.py"] }

    fn extract_models(&self, pr: &ParseResult) -> Vec<ExtractedModel> {
        let mut models = Vec::new();
        for class in &pr.classes {
            let is_django = class.extends.as_deref() == Some("Model")
                || class.extends.as_deref() == Some("models.Model");
            if is_django {
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
                    table_name: Some(format!("app_{}", class.name.to_lowercase())),
                    file: pr.file.clone(),
                    line: class.range.start.line,
                    framework: OrmFramework::Django,
                    fields,
                    relationships: Vec::new(),
                    confidence: 0.85,
                });
            }
        }
        models
    }
}

//! Hibernate field extractor (Java).

use crate::parsers::types::ParseResult;
use super::{FieldExtractor, ExtractedModel, OrmFramework};
use crate::boundaries::types::ExtractedField;

pub struct HibernateExtractor;

impl FieldExtractor for HibernateExtractor {
    fn framework(&self) -> OrmFramework { OrmFramework::Hibernate }
    fn schema_file_patterns(&self) -> &[&str] { &["*.java"] }

    fn extract_models(&self, pr: &ParseResult) -> Vec<ExtractedModel> {
        let mut models = Vec::new();
        for class in &pr.classes {
            let is_hibernate = class.decorators.iter().any(|d| {
                d.name == "Entity" || d.name == "Table"
            });
            if is_hibernate {
                let fields = class.properties.iter().map(|p| {
                    let is_pk = p.name == "id"
                        || class.decorators.iter().any(|d| d.name == "Id");
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
                    table_name: Some(class.name.to_lowercase()),
                    file: pr.file.clone(),
                    line: class.range.start.line,
                    framework: OrmFramework::Hibernate,
                    fields,
                    relationships: Vec::new(),
                    confidence: 0.90,
                });
            }
        }
        models
    }
}

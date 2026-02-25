//! ActiveRecord field extractor (Ruby).

use crate::parsers::types::ParseResult;
use super::{FieldExtractor, ExtractedModel, OrmFramework};
use crate::boundaries::types::ExtractedField;

pub struct ActiveRecordExtractor;

impl FieldExtractor for ActiveRecordExtractor {
    fn framework(&self) -> OrmFramework { OrmFramework::ActiveRecord }
    fn schema_file_patterns(&self) -> &[&str] { &["*.rb", "schema.rb"] }

    fn extract_models(&self, pr: &ParseResult) -> Vec<ExtractedModel> {
        let mut models = Vec::new();
        for class in &pr.classes {
            let is_ar = class.extends.as_deref() == Some("ApplicationRecord")
                || class.extends.as_deref() == Some("ActiveRecord::Base");
            if is_ar {
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
                    framework: OrmFramework::ActiveRecord,
                    fields,
                    relationships: Vec::new(),
                    confidence: 0.85,
                });
            }
        }
        models
    }
}

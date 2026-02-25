//! Sequelize field extractor (JavaScript/TypeScript).

use crate::parsers::types::ParseResult;
use super::{FieldExtractor, ExtractedModel, OrmFramework};
use crate::boundaries::types::ExtractedField;

pub struct SequelizeExtractor;

impl FieldExtractor for SequelizeExtractor {
    fn framework(&self) -> OrmFramework { OrmFramework::Sequelize }
    fn schema_file_patterns(&self) -> &[&str] { &["*.model.ts", "*.model.js"] }

    fn extract_models(&self, pr: &ParseResult) -> Vec<ExtractedModel> {
        let mut models = Vec::new();
        // Sequelize models are typically classes extending Model or calls to sequelize.define()
        for class in &pr.classes {
            let is_sequelize = class.extends.as_deref() == Some("Model")
                || class.decorators.iter().any(|d| d.name == "Table");
            if is_sequelize {
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
                    framework: OrmFramework::Sequelize,
                    fields,
                    relationships: Vec::new(),
                    confidence: 0.85,
                });
            }
        }
        models
    }
}

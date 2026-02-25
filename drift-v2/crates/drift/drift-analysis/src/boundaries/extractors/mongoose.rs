//! Mongoose field extractor (JavaScript/TypeScript).

use crate::parsers::types::ParseResult;
use super::{FieldExtractor, ExtractedModel, OrmFramework};
use crate::boundaries::types::ExtractedField;

pub struct MongooseExtractor;

impl FieldExtractor for MongooseExtractor {
    fn framework(&self) -> OrmFramework { OrmFramework::Mongoose }
    fn schema_file_patterns(&self) -> &[&str] { &["*.schema.ts", "*.schema.js", "*.model.ts", "*.model.js"] }

    fn extract_models(&self, pr: &ParseResult) -> Vec<ExtractedModel> {
        let mut models = Vec::new();
        // Mongoose schemas are typically new Schema({...}) calls
        let has_mongoose = pr.imports.iter().any(|i| i.source == "mongoose");
        if !has_mongoose { return models; }

        for class in &pr.classes {
            let fields = class.properties.iter().map(|p| ExtractedField {
                name: p.name.clone(),
                field_type: p.type_annotation.clone(),
                is_primary_key: p.name == "_id",
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
                framework: OrmFramework::Mongoose,
                fields,
                relationships: Vec::new(),
                confidence: 0.75,
            });
        }
        models
    }
}
